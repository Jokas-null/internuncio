"""
modules/scanner.py

Active network scanner (Discovery). Sends ARP requests across the lab
subnet and collects which hosts are alive, their MAC, and its resolved
vendor (see utils/vendor_lookup.py).

It ALWAYS stays inside config.WHITELIST_SUBNET: it never scans a subnet
other than the authorized lab one, regardless of the interface used. This
is deliberate: a "generic" scanner that walks whatever network is passed
on the CLI would be trivial to point at someone else's network; here the
scan subnet is fixed by configuration, not by argument.
"""

import ipaddress

from scapy.all import ARP, Ether, srp

import config
from utils.logger import log_info, log_host_found, log_warn
from utils.vendor_lookup import get_vendor


def scan_network(interface: str) -> list:
    """
    Scans the lab subnet (config.WHITELIST_SUBNET) by sending a single
    broadcast ARP "who-has" targeting the whole range. Any host that
    answers proves it is alive and on the same subnet (no need for ping;
    ARP is already a reliable layer-2 discovery within the segment).

    Returns a list of dicts: {"ip": ..., "mac": ..., "vendor": ...}
    """
    network = ipaddress.ip_network(config.WHITELIST_SUBNET, strict=False)
    log_info(f"Scanning {network} on interface {interface} (this may take a few seconds)...")

    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
    responses = srp(request, timeout=config.SCAN_TIMEOUT, iface=interface, verbose=False)[0]

    hosts = []
    for _, received in responses:
        ip = received.psrc
        mac = received.hwsrc
        # get_vendor() resuelve contra la base OUI local (data/oui_db.json,
        # cacheada en memoria por vendor_lookup), así que añadir esta
        # columna no introduce latencia de red por cada host encontrado.
        vendor = get_vendor(mac)
        hosts.append({"ip": ip, "mac": mac, "vendor": vendor})
        log_host_found(ip, mac, vendor)

    if not hosts:
        log_warn("No active hosts were detected on the lab subnet.")

    return hosts
