#!/usr/bin/env python3
"""
internuncio.py — entry point for "Internuncio".

Its only responsibility is to:
1. Parse arguments (argparse).
2. Apply the safety guards (whitelist + confirmation) in a centralized
   way, no matter which path led to a given target.
3. Delegate the actual work to the specialized modules
   (modules/scanner.py, modules/spoofer.py, modules/limiter.py).

It contains no network logic of its own: that lives in modules/ and
utils/, so each piece can be read, tested, and maintained separately.

Available modes:
    --scan                           Only discovers hosts on the lab
                                      subnet, does not attack. At the end
                                      it lets you pick one, several, or
                                      "all" to pass on to attack mode.
    --target IP --gateway IP         Attacks a SINGLE victim.
    --targets IP1,IP2,... --gateway  Attacks SEVERAL victims at once
                                      (multi-target, requires the
                                      reinforced confirmation phrase).
"""

import argparse
import signal
import sys
import time

import config
from utils.logger import Color, log_ok, log_warn, log_err, log_info
from utils.network_utils import (
    filter_whitelisted_ips,
    get_own_ip,
    set_ip_forward,
)
from modules.scanner import scan_network
from modules.spoofer import SpoofManager
from modules.limiter import (
    apply_bandwidth_limit,
    apply_total_block,
    clear_tc,
    clear_iptables,
)

# --- Global state of the ongoing attack, needed so the kill-switch     ---
# --- (sigint_handler) knows what to restore no matter how it was launched. ---
manager = SpoofManager()
total_block_targets = []  # IPs with --bandwidth 0, so their iptables rules get cleaned up on exit
current_interface = None


def sigint_handler(sig, frame):
    """
    Global kill-switch (Ctrl+C): restores the real ARP state of ALL
    active victims (one or several), removes the interface's tc rules
    and the iptables rules from any total block, and disables
    ip_forward. Leaves the lab network exactly as it was before running
    the script.
    """
    print()
    log_warn("Interrupt signal received (Ctrl+C). Restoring the network...")

    manager.restore_all()

    if current_interface:
        clear_tc(current_interface)
        log_ok("tc rules removed.")

    for ip in total_block_targets:
        clear_iptables(ip)
    if total_block_targets:
        log_ok("iptables (DROP) rules removed.")

    set_ip_forward(False)
    log_ok("Restoration complete. Exiting.")
    sys.exit(0)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Internuncio — MITM lab tool (ARP Spoofing) + bandwidth limiting for IDS testing."
    )
    parser.add_argument("--target", help="IP of a single victim")
    parser.add_argument("--targets", help="Comma-separated list of victim IPs (multi-target mode)")
    parser.add_argument("--gateway", help="IP of the lab router/gateway")
    parser.add_argument("--interface", required=True, help="Network interface to use, e.g.: eth0")
    parser.add_argument(
        "--bandwidth",
        default=config.DEFAULT_BANDWIDTH,
        help="Maximum allowed rate (e.g.: 1kbit, 500kbit). '0' = total cut.",
    )
    parser.add_argument("--scan", action="store_true", help="Only scan the lab network, do not attack.")
    return parser.parse_args()


def confirm_single_target(ip: str) -> bool:
    """Standard confirmation (inherited from the original script) for attacking a SINGLE victim."""
    response = input(
        f"{Color.YELLOW}Are you sure {ip} is inside your isolated lab "
        f"(GNS3/VMware, with no real internet access)? (y/N): {Color.END}"
    ).strip().lower()
    return response == "y"


def confirm_multi_target(ips: list) -> bool:
    """
    Reinforced confirmation for attacking SEVERAL hosts at once: requires
    typing config.MULTI_TARGET_CONFIRMATION_PHRASE verbatim (uppercase
    and hyphens included), a simple "y" is not enough. The blast radius
    of a mistake multiplies with the number of simultaneous victims, so
    the safety guard must also be harder to trigger by accident.
    """
    print(f"{Color.RED}{Color.BOLD}WARNING!{Color.END}")
    print(f"{Color.RED}You are about to SIMULTANEOUSLY attack {len(ips)} hosts: {', '.join(ips)}{Color.END}")
    print(f"{Color.RED}Are you absolutely sure you are in an authorized lab?{Color.END}")
    response = input(
        f"{Color.RED}Type '{config.MULTI_TARGET_CONFIRMATION_PHRASE}' to continue: {Color.END}"
    ).strip()
    return response == config.MULTI_TARGET_CONFIRMATION_PHRASE


def launch_attack(ips: list, gateway: str, interface: str, bandwidth: str):
    """
    Starts the spoofing sessions (one per victim, via SpoofManager) and
    applies the corresponding traffic limitation, then stays in a status
    loop until the user presses Ctrl+C.
    """
    global current_interface
    current_interface = interface

    set_ip_forward(True)

    for ip in ips:
        manager.add_target(ip, gateway, interface)

    if bandwidth == "0":
        for ip in ips:
            apply_total_block(interface, ip)
            total_block_targets.append(ip)
    else:
        apply_bandwidth_limit(interface, bandwidth)

    log_info("Attack in progress. Press Ctrl+C to stop and restore the network.")
    counter = 0
    while True:
        counter += 2 * len(ips)
        bw_status = "TOTAL CUT" if bandwidth == "0" else bandwidth
        print(
            f"{Color.GREEN}[ARP]{Color.END} packets ~sent: {counter} | "
            f"active victims: {len(ips)} | {Color.CYAN}[BW]{Color.END} limit: {bw_status}   ",
            end="\r",
        )
        time.sleep(config.POISON_INTERVAL)


def run_attack_flow(ips: list, gateway: str, interface: str, bandwidth: str):
    """
    The single entry point any attack path MUST go through (--target,
    --targets, or a selection made from --scan). Applies, in order:
    whitelist -> thread limit -> confirmation (simple or reinforced
    depending on the number of victims) -> kill-switch -> attack.

    Centralizing it here prevents any new flow from accidentally
    skipping one of the safety guards.
    """
    valid_ips = filter_whitelisted_ips(ips)
    if not valid_ips:
        log_err("UNAUTHORIZED NETWORK")
        log_err(f"None of the IPs are inside the lab whitelist ({config.WHITELIST_SUBNET}).")
        sys.exit(1)

    if len(valid_ips) > config.MAX_THREADS:
        log_warn(
            f"Simultaneous targets are capped at {config.MAX_THREADS} "
            f"(out of {len(valid_ips)} requested)."
        )
        valid_ips = valid_ips[: config.MAX_THREADS]

    if len(valid_ips) == 1:
        if not confirm_single_target(valid_ips[0]):
            log_warn("Operation cancelled by the user.")
            sys.exit(0)
    else:
        if not confirm_multi_target(valid_ips):
            log_warn("Incorrect confirmation phrase. Aborting for safety.")
            sys.exit(0)

    launch_attack(valid_ips, gateway, interface, bandwidth)


def scan_mode(interface: str):
    """
    --scan mode: only discovers hosts on the lab subnet, never attacks by
    itself. At the end, it shows the full list (IP/MAC/host) and lets you
    explicitly choose who to pass on to attack mode — including the
    "all" option, but always with prior visibility of exactly which
    hosts will be affected.
    """
    hosts = scan_network(interface)
    if not hosts:
        return

    print(f"\n{Color.BOLD}Scan summary:{Color.END}")
    for i, h in enumerate(hosts):
        print(f"  [{i}] {h['ip']:<15} MAC: {h['mac']}  Hostname: {h['hostname']}")

    response = input(f"\n{Color.YELLOW}Do you want to limit any of these? (y/N): {Color.END}").strip().lower()
    if response != "y":
        return

    selection = input(
        "Enter the number(s) from the list separated by commas (e.g.: 0,2) "
        "or type 'all' to select all of them: "
    ).strip()

    if selection.lower() == "all":
        chosen = hosts
    else:
        try:
            indices = [int(x) for x in selection.split(",")]
            chosen = [hosts[i] for i in indices]
        except (ValueError, IndexError):
            log_err("Invalid selection.")
            return

    chosen_ips = [h["ip"] for h in chosen]

    # Automatically exclude our own IP: ARP-poisoning ourselves would
    # never make sense (nor be safe).
    own_ip = get_own_ip(interface)
    if own_ip in chosen_ips:
        chosen_ips.remove(own_ip)
        log_warn(f"Your own IP ({own_ip}) is excluded from the victim list.")

    if not chosen_ips:
        log_warn("No valid IP remains after excluding your own.")
        return

    gateway = input(f"{Color.YELLOW}IP of this lab's gateway: {Color.END}").strip()
    bandwidth = input(
        f"{Color.YELLOW}Bandwidth to apply (e.g.: 1kbit, or '0' for a total cut) "
        f"[{config.DEFAULT_BANDWIDTH}]: {Color.END}"
    ).strip() or config.DEFAULT_BANDWIDTH

    run_attack_flow(chosen_ips, gateway, interface, bandwidth)


def main():
    args = parse_args()
    print(f"{Color.BOLD}=== Internuncio — MITM / ARP Spoofing Lab ==={Color.END}")

    # The kill-switch is registered right from startup: even if the user
    # cancels before reaching the attack, Ctrl+C should never raise a
    # raw traceback.
    signal.signal(signal.SIGINT, sigint_handler)

    if args.scan:
        scan_mode(args.interface)
        return

    if args.targets:
        ips = [ip.strip() for ip in args.targets.split(",") if ip.strip()]
    elif args.target:
        ips = [args.target]
    else:
        log_err("You must specify --scan, --target, or --targets.")
        sys.exit(1)

    if not args.gateway:
        log_err("Missing --gateway.")
        sys.exit(1)

    run_attack_flow(ips, args.gateway, args.interface, args.bandwidth)


if __name__ == "__main__":
    if sys.platform != "linux":
        log_err("This script requires Linux (Kali/Parrot) due to its dependency on tc/iptables/procfs.")
        sys.exit(1)
    main()
