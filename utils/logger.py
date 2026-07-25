"""
utils/logger.py

Console output with ANSI colors, inherited from the original script.

Split into its own module because ALL other modules (scanner, spoofer,
limiter, internuncio) need to print status messages with the same style.
Centralizing it avoids duplicating color codes in every file and allows
the logging format to be changed in a single place.
"""


class Color:
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    END = "\033[0m"


def log_ok(msg: str):
    """Success message (green). E.g.: MAC resolved, network rule applied."""
    print(f"{Color.GREEN}[+] {msg}{Color.END}")


def log_warn(msg: str):
    """Warning (yellow). E.g.: a non-critical command failed, IP discarded."""
    print(f"{Color.YELLOW}[!] {msg}{Color.END}")


def log_err(msg: str):
    """Critical error (red). E.g.: unauthorized network, unrecoverable failure."""
    print(f"{Color.RED}[-] {msg}{Color.END}")


def log_info(msg: str):
    """Neutral information (cyan). E.g.: intermediate steps of the flow."""
    print(f"{Color.CYAN}[*] {msg}{Color.END}")
