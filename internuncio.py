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
    --scan                           Purely read-only: lists hosts on
                                      the lab subnet and exits. Never
                                      attacks.
    --target IP --gateway IP         Attacks a SINGLE victim.
    --targets IP1,IP2,... --gateway  Attacks SEVERAL victims at once
                                      (multi-target, requires the
                                      reinforced confirmation phrase).
    --all --gateway IP               Scans the lab subnet and attacks
                                      EVERY host found (same reinforced
                                      confirmation as --targets).
"""

import argparse
import os
import signal
import sys
import time

import config
from utils.logger import Color, log_ok, log_warn, log_err, log_info
from utils.network_utils import (
    filter_whitelisted_ips,
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
from utils.vendor_lookup import update_oui_database

# --- Global state of the ongoing attack, needed so the kill-switch     ---
# --- (sigint_handler) knows what to restore no matter how it was launched. ---
manager = SpoofManager()
total_block_targets = []  # IPs with --bandwidth 0, so their iptables rules get cleaned up on exit
current_interface = None


def restore_network():
    """
    Restores the real ARP state of ALL active victims, removes the
    interface's tc rules and any iptables total-block rules, and
    disables ip_forward — leaving the lab network exactly as it was
    before running the script.

    Extracted from sigint_handler so the SAME cleanup can run from two
    triggers: Ctrl+C, and an unexpected exception during the attack
    (e.g. a victim going offline mid-run). Without this, a crash would
    leave ip_forward enabled and any already-poisoned victims without
    a restore, silently and indefinitely.

    Each step is isolated in its own try/except: this function is
    itself called from main()'s generic exception handler, so a failure
    in one cleanup step (e.g. permissions) must not raise again and
    skip the remaining ones — that would trade one raw traceback for
    two, and still leave later steps undone.

    tc/iptables are torn down FIRST, before the ARP restore packets are
    sent: `tc tbf` shapes the WHOLE interface, not just the victim's
    forwarded traffic, so with a low --bandwidth (e.g. 1kbit) it also
    throttles our own restore-ARP packets going out the same NIC. If
    the qdisc is still in place when restore_all() runs, those packets
    can fail with ENOBUFS exactly when they matter most. Lifting the
    shaping first means the restore always goes out at full speed.
    """
    if current_interface:
        try:
            clear_tc(current_interface)
            log_ok("tc rules removed.")
        except Exception as e:
            log_err(f"Error removing tc rules: {e}")

    for ip in total_block_targets:
        try:
            clear_iptables(ip)
        except Exception as e:
            log_err(f"Error removing iptables rule for {ip}: {e}")
    if total_block_targets:
        log_ok("iptables (DROP) rules removed.")

    try:
        manager.restore_all()
    except Exception as e:
        log_err(f"Error restoring ARP sessions: {e}")

    try:
        set_ip_forward(False)
    except Exception as e:
        log_err(f"Error disabling ip_forward: {e}")


def sigint_handler(sig, frame):
    """Global kill-switch (Ctrl+C): triggers restore_network() and exits cleanly."""
    print()
    log_warn("Interrupt signal received (Ctrl+C). Restoring the network...")
    restore_network()
    log_ok("Restoration complete. Exiting.")
    sys.exit(0)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Internuncio — MITM lab tool (ARP Spoofing) + bandwidth limiting for IDS testing."
    )
    parser.add_argument("--target", help="IP of a single victim")
    parser.add_argument("--targets", help="Comma-separated list of victim IPs (multi-target mode)")
    parser.add_argument("--gateway", help="IP of the lab router/gateway")
    # Not required=True at the argparse level because --update-oui
    # doesn't need any network interface (it only downloads a file);
    # the "this mode needs an interface" validation is done by hand in
    # main().
    parser.add_argument("--interface", help="Network interface to use, e.g.: eth0")
    parser.add_argument(
        "--bandwidth",
        default=config.DEFAULT_BANDWIDTH,
        help="Maximum allowed rate (e.g.: 1kbit, 500kbit). '0' = total cut.",
    )
    parser.add_argument("--scan", action="store_true", help="Only scan the lab network, do not attack.")
    parser.add_argument(
        "--all",
        action="store_true",
        help="Scan the lab subnet and attack every host found (requires --gateway; still gated by the reinforced multi-target confirmation phrase).",
    )
    parser.add_argument(
        "--update-oui",
        action="store_true",
        help="Download the latest IEEE OUI vendor database into data/oui_db.json and exit. Requires internet access.",
    )
    # Running with no arguments at all (no --scan, no --target(s), no
    # --update-oui...) can't do anything useful either way — show just
    # the short usage line and exit cleanly instead of falling through
    # to the root check and then "you must specify --scan, --target, or
    # --targets". The full, detailed help (with descriptions for every
    # flag) is reserved for an explicit --help/-h, via print_usage()
    # instead of print_help() here. Checked against sys.argv directly
    # (not the parsed `args`) so it only triggers on a truly bare
    # invocation, not e.g. `--bandwidth 0` alone with everything else
    # defaulted.
    if len(sys.argv) == 1:
        parser.print_usage()
        print("Run with --help for the full list of options.")
        sys.exit(0)

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

    # Poisoning the gateway "against itself" (target == gateway, e.g. when
    # selecting "all" hosts from --scan and the gateway answered the ARP
    # sweep too) has no MITM effect and only wastes a session/thread — so
    # it's dropped here, in the single choke point every attack path goes
    # through, same as the whitelist check above.
    if gateway in valid_ips:
        valid_ips.remove(gateway)
        log_warn(f"Gateway IP ({gateway}) removed from the target list — it can't be poisoned against itself.")

    if not valid_ips:
        log_err("No valid targets remain after excluding the gateway.")
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
    --scan mode: purely read-only discovery. Lists hosts on the lab
    subnet and exits — it never asks about attacking any of them. To
    attack a host found here, run again with --target/--targets and
    that IP.
    """
    hosts = scan_network(interface)
    if not hosts:
        return

    print(f"\n{Color.BOLD}Scan summary:{Color.END}")
    for i, h in enumerate(hosts):
        print(f"  [{i}] {h['ip']:<15} MAC: {h['mac']}  Vendor: {h['vendor']}")


def all_mode(interface: str, gateway: str, bandwidth: str):
    """
    --all mode: scans the lab subnet internally (same visibility as
    --scan — the discovered list is printed before anything else
    happens) and then hands EVERY host found to run_attack_flow(),
    which is the same choke point --target/--targets go through: the
    gateway is dropped from the target list, and since this is
    virtually always more than one victim, the reinforced multi-target
    confirmation phrase is required, same as a manual --targets run.
    """
    hosts = scan_network(interface)
    if not hosts:
        log_warn("No active hosts were detected; nothing to attack.")
        return

    print(f"\n{Color.BOLD}Scan summary:{Color.END}")
    for i, h in enumerate(hosts):
        print(f"  [{i}] {h['ip']:<15} MAC: {h['mac']}  Vendor: {h['vendor']}")

    ips = [h["ip"] for h in hosts]
    run_attack_flow(ips, gateway, interface, bandwidth)


def main():
    args = parse_args()
    print(f"{Color.BOLD}=== Internuncio — MITM / ARP Spoofing Lab ==={Color.END}")

    # The kill-switch is registered right from startup: even if the user
    # cancels before reaching the attack, Ctrl+C should never raise a
    # raw traceback.
    signal.signal(signal.SIGINT, sigint_handler)

    # Everything below runs inside a try/except so that ANY unexpected
    # failure mid-attack (e.g. a victim going offline and its MAC
    # resolution raising) still triggers the same network restoration
    # as Ctrl+C, instead of crashing with ip_forward left enabled and
    # already-poisoned victims never restored. sys.exit() raises
    # SystemExit, which this "except Exception" deliberately does not
    # catch, so normal CLI validation errors below are unaffected.
    try:
        # --update-oui is resolved before anything else and doesn't
        # require --interface: it's the only operation in the whole
        # project that needs internet access, and it never touches the
        # lab network.
        if args.update_oui:
            update_oui_database()
            return

        # Every other mode needs raw sockets (ARP), and the attack modes
        # additionally need tc/iptables/ip_forward — all of which require
        # root. Checked here, once, so a non-root run fails with one
        # clear message instead of a raw PermissionError traceback deep
        # inside scapy (and a second one when cleanup itself then tries
        # to touch ip_forward without permission).
        if os.geteuid() != 0:
            log_err("Internuncio needs root privileges (raw sockets, tc, iptables, ip_forward).")
            log_err(f"Run it with sudo, e.g.: sudo python3 {sys.argv[0]} --scan --interface eth0")
            sys.exit(1)

        if not args.interface:
            log_err("Missing --interface.")
            sys.exit(1)

        if args.scan:
            scan_mode(args.interface)
            return

        if args.all:
            if not args.gateway:
                log_err("Missing --gateway.")
                sys.exit(1)
            all_mode(args.interface, args.gateway, args.bandwidth)
            return

        if args.targets:
            ips = [ip.strip() for ip in args.targets.split(",") if ip.strip()]
        elif args.target:
            ips = [args.target]
        else:
            log_err("You must specify --scan, --target, --targets, or --all.")
            sys.exit(1)

        if not args.gateway:
            log_err("Missing --gateway.")
            sys.exit(1)

        run_attack_flow(ips, args.gateway, args.interface, args.bandwidth)
    except Exception as e:
        log_err(f"Unexpected error: {e}")
        log_warn("Restoring the network before exiting...")
        restore_network()
        sys.exit(1)


if __name__ == "__main__":
    if sys.platform != "linux":
        log_err("This script requires Linux (Kali/Parrot) due to its dependency on tc/iptables/procfs.")
        sys.exit(1)
    main()
