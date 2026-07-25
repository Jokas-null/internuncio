"""
modules/scanner.py

Active network scanner (Discovery). Sends ARP requests across the lab
subnet and collects which hosts are alive, their MAC, and (when possible)
their hostname.

It ALWAYS stays inside config.WHITELIST_SUBNET: it never scans a subnet
other than the authorized lab one, regardless of the interface used. This
is deliberate: a "generic" scanner that walks whatever network is passed
on the CLI would be trivial to point at someone else's network; here the
scan subnet is fixed by configuration, not by argument.
"""

import ipaddress
import socket

from scapy.all import ARP, Ether, srp

import config
from utils.logger import log_info, log_ok, log_warn


def resolve_hostname(ip: str) -> str:
    """
    Attempts reverse DNS resolution to show a readable name next to the
    IP. On lab networks without DNS configured this will usually fail, so
    the exception is caught and a placeholder is returned instead of
    aborting the whole scan over a single host without a name.
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return "unknown"


def scan_network(interface: str) -> list:
    """
    Scans the lab subnet (config.WHITELIST_SUBNET) by sending a single
    broadcast ARP "who-has" targeting the whole range. Any host that
    answers proves it is alive and on the same subnet (no need for ping;
    ARP is already a reliable layer-2 discovery within the segment).

    Returns a list of dicts: {"ip": ..., "mac": ..., "hostname": ...}
    """
    network = ipaddress.ip_network(config.WHITELIST_SUBNET, strict=False)
    log_info(f"Scanning {network} on interface {interface} (this may take a few seconds)...")

    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
    responses = srp(request, timeout=config.SCAN_TIMEOUT, iface=interface, verbose=False)[0]

    hosts = []
    for _, received in responses:
        ip = received.psrc
        mac = received.hwsrc
        hostname = resolve_hostname(ip)
        hosts.append({"ip": ip, "mac": mac, "hostname": hostname})
        log_ok(f"Active host: {ip:<15} MAC: {mac}  Hostname: {hostname}")

    if not hosts:
        log_warn("No active hosts were detected on the lab subnet.")

    return hosts
