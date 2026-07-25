"""
utils/network_utils.py

Network utilities shared by scanner.py, spoofer.py, and internuncio.py:

- Verify that an IP falls inside the lab whitelist
  (config.WHITELIST_SUBNET) — the project's hard safety guard.
- Resolve the MAC address of a remote host via ARP.
- Obtain our own interface's IP/MAC, needed to automatically exclude
  ourselves from victim lists.
- Enable/disable ip_forward.

Split from spoofer.py and scanner.py because both modules need these same
functions ("who am I on the network?", "is this IP allowed?"); keeping
them in one place avoids duplicated logic and possible inconsistencies in
the safety guard.
"""

import fcntl
import ipaddress
import socket
import struct

from scapy.all import ARP, Ether, srp

import config
from utils.logger import log_warn

SIOCGIFADDR = 0x8915
SIOCGIFHWADDR = 0x8927


def is_ip_whitelisted(ip_str: str) -> bool:
    """
    Checks whether `ip_str` belongs to config.WHITELIST_SUBNET.

    This is the project's central safety guard: it is used before
    attacking a single target, to filter the scanner's results, and to
    vet any IP list in multi-target mode. No flow in the program should
    touch an IP without going through this function first.
    """
    try:
        lab_network = ipaddress.ip_network(config.WHITELIST_SUBNET, strict=False)
        ip = ipaddress.ip_address(ip_str)
        return ip in lab_network
    except ValueError:
        return False


def filter_whitelisted_ips(ips: list) -> list:
    """Returns only the IPs from `ips` that fall inside the whitelist, warning about the discarded ones."""
    valid = [ip for ip in ips if is_ip_whitelisted(ip)]
    discarded = [ip for ip in ips if ip not in valid]
    for ip in discarded:
        log_warn(f"IP {ip} discarded for being outside the whitelist ({config.WHITELIST_SUBNET})")
    return valid


def get_mac(ip: str, interface: str, timeout: int = None) -> str:
    """
    Sends a broadcast ARP "who-has" request and returns the real MAC of
    the host that answers. This is the foundation for both the scanner
    (listing hosts) and the spoofer (building believable ARP "reply"
    packets).
    """
    timeout = timeout or config.ARP_RESOLVE_TIMEOUT
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    response = srp(request, timeout=timeout, iface=interface, verbose=False)[0]
    if response:
        return response[0][1].hwsrc
    raise RuntimeError(f"Could not resolve the MAC of {ip}. Is it powered on and on the same subnet?")


def get_own_ip(interface: str) -> str:
    """
    Gets the IP assigned to `interface` on THIS machine via a socket
    ioctl (SIOCGIFADDR). Used to automatically exclude the attacker
    itself from the victim list in multi-target mode (ARP-poisoning
    yourself would never make sense).
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        info = fcntl.ioctl(
            s.fileno(),
            SIOCGIFADDR,
            struct.pack("256s", interface[:15].encode("utf-8")),
        )
        return socket.inet_ntoa(info[20:24])
    finally:
        s.close()


def get_own_mac(interface: str) -> str:
    """Returns the MAC of our own interface (useful for logging/debugging)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        info = fcntl.ioctl(
            s.fileno(),
            SIOCGIFHWADDR,
            struct.pack("256s", interface[:15].encode("utf-8")),
        )
        return ":".join("%02x" % b for b in info[18:24])
    finally:
        s.close()


def set_ip_forward(enable: bool):
    """
    Enables/disables the kernel's IP packet forwarding
    (/proc/sys/net/ipv4/ip_forward).

    Without this, the traffic that ARP spoofing redirects to us would get
    "stuck" on our machine instead of continuing to its real destination,
    turning the MITM into an uncontrolled total outage instead of one
    shaped by the limiter.
    """
    value = "1" if enable else "0"
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        f.write(value)
