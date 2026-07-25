"""
modules/limiter.py

Traffic control (tc + iptables), inherited from the original script.

All shaping/blocking logic lives here so spoofer.py doesn't mix
responsibilities: spoofer decides WHO to deceive (ARP), limiter decides
WHAT happens to their traffic once it passes through our machine.

Important design note (read before using multi-target mode): `tc` with
tbf/netem is applied at the WHOLE-INTERFACE level (all forwarded
traffic), not per individual IP. This means that if several victims are
poisoned at once, ALL of them share the same aggregate bandwidth limit
configured here — it is not an independent per-host limit. The total
block via iptables, on the other hand, IS per IP (-s/-d rules), so in
multi-target mode the total cut (--bandwidth 0) does act independently
per victim. Independent per-IP shaping would require HTB classes plus
u32/iptables "mark" filters, which is out of scope for this lab tool.
"""

import subprocess

import config
from utils.logger import log_ok, log_warn


def run_cmd(cmd: list, allow_failure: bool = False):
    """Wrapper around subprocess to launch network commands with uniform error handling."""
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0 and not allow_failure:
        log_warn(f"Command failed ({' '.join(cmd)}): {result.stderr.strip()}")
    return result


def clear_tc(interface: str):
    """Removes any previous queuing discipline (qdisc) on the interface."""
    run_cmd(["tc", "qdisc", "del", "dev", interface, "root"], allow_failure=True)


def apply_bandwidth_limit(interface: str, bandwidth: str):
    """
    Applies a rate limit over the WHOLE interface using tc:

    - tbf (Token Bucket Filter): fixes the maximum transfer rate (the
      value the user passes via --bandwidth).
    - netem: adds packet loss and extra latency, to degrade the link more
      realistically (useful to see how the IDS reacts to erratic traffic,
      not just slow traffic).
    """
    clear_tc(interface)

    run_cmd([
        "tc", "qdisc", "add", "dev", interface, "root", "handle", "1:",
        "tbf", "rate", bandwidth, "burst", config.TBF_BURST, "latency", config.TBF_LATENCY,
    ])

    run_cmd([
        "tc", "qdisc", "add", "dev", interface, "parent", "1:", "handle", "10:",
        "netem", "loss", config.NETEM_LOSS, "delay", config.NETEM_DELAY,
    ], allow_failure=True)

    log_ok(f"Bandwidth limited to {bandwidth} on {interface} (tbf + netem)")


def apply_total_block(interface: str, target_ip: str):
    """
    Total cut for a specific IP: inserts iptables rules that drop all
    traffic to/from `target_ip` that passes through our machine (possible
    thanks to ARP spoofing). Unlike tc, this IS independent per victim.
    """
    run_cmd(["iptables", "-I", "FORWARD", "-s", target_ip, "-j", "DROP"])
    run_cmd(["iptables", "-I", "FORWARD", "-d", target_ip, "-j", "DROP"])
    log_ok(f"TOTAL block applied to {target_ip} (iptables DROP)")


def clear_iptables(target_ip: str):
    """Removes the DROP rules created by apply_total_block for a specific IP."""
    run_cmd(["iptables", "-D", "FORWARD", "-s", target_ip, "-j", "DROP"], allow_failure=True)
    run_cmd(["iptables", "-D", "FORWARD", "-d", target_ip, "-j", "DROP"], allow_failure=True)
