"""
utils/vendor_lookup.py

Resolves a device's manufacturer (vendor) from the OUI
(Organizationally Unique Identifier) of its MAC address: the first
3 octets, which the IEEE assigns uniquely to each network hardware
manufacturer.

Key design point: normal scanning (--scan) NEVER needs internet access.
The database lives as a local JSON file (config.OUI_DB_PATH), generated
from the IEEE's official oui.txt, and is loaded into memory only once
(module-level cache). Only `update_oui_database()` — explicitly invoked
via --update-oui — reaches out to the internet to refresh that file.
"""

import json
import os
import re
import urllib.request

import config
from utils.logger import log_info, log_ok, log_err, log_warn

# In-memory cache of the already-loaded OUI database. Kept at module
# level (not per instance) because a single scan may resolve dozens of
# MACs, and there's no point re-reading the JSON file from disk for
# each one.
_oui_cache = None


def _normalize_oui(mac: str) -> str:
    """
    Extracts the first 3 octets of a MAC and normalizes them to
    uppercase with no separators (e.g. "70:C7:F2:10:E1:4A" -> "70C7F2").
    This is the key format used in data/oui_db.json.

    Raises ValueError if the MAC is malformed (fewer than 6 hex
    digits), so the caller can degrade to "Unknown" instead of
    propagating an exception all the way up through the whole scan.
    """
    hex_only = re.sub(r"[^0-9A-Fa-f]", "", mac)
    if len(hex_only) < 6:
        raise ValueError(f"Malformed MAC: {mac!r}")
    return hex_only[:6].upper()


def _is_locally_administered(mac: str) -> bool:
    """
    Checks the "locally administered" bit (the second-least-significant
    bit of the MAC's first octet). When it's set, the address was NOT
    assigned by the IEEE to any manufacturer: it was randomly generated
    by the device itself.

    This is exactly what modern iOS and Android do by default when
    joining a WiFi network (MAC randomization), to make device tracking
    by MAC harder. If this case weren't filtered out, that prefix would
    get looked up in the OUI database and return a real — but
    completely misleading — vendor.
    """
    hex_only = re.sub(r"[^0-9A-Fa-f]", "", mac)
    first_octet = int(hex_only[0:2], 16)
    return bool(first_octet & 0b00000010)


def _load_database() -> dict:
    """Loads data/oui_db.json into memory exactly once (lazy loading + cache)."""
    global _oui_cache
    if _oui_cache is not None:
        return _oui_cache

    if not os.path.exists(config.OUI_DB_PATH):
        log_warn(f"{config.OUI_DB_PATH} not found; run --update-oui to generate it.")
        _oui_cache = {}
        return _oui_cache

    try:
        with open(config.OUI_DB_PATH, "r", encoding="utf-8") as f:
            _oui_cache = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        log_err(f"Could not read {config.OUI_DB_PATH}: {e}")
        _oui_cache = {}

    return _oui_cache


def get_vendor(mac: str) -> str:
    """
    Returns the manufacturer name associated with a MAC, or a
    descriptive string when a normal lookup doesn't apply.

    Order of checks matters: whether the MAC is randomized is checked
    first, because in that case ANY result from the OUI database would
    be wrong — that prefix was never assigned to a real manufacturer.
    Only when it isn't randomized does it make sense to query
    data/oui_db.json.
    """
    try:
        if _is_locally_administered(mac):
            return "Randomized MAC (likely mobile device)"
        oui = _normalize_oui(mac)
    except ValueError:
        return "Unknown"

    database = _load_database()
    return database.get(oui, "Unknown")


def update_oui_database() -> bool:
    """
    Downloads the IEEE's official OUI listing (oui.txt) and converts it
    into data/oui_db.json.

    This is the ONLY function in the whole project that needs internet
    access: everything else (including normal scanning) always works
    against the already-generated local copy, precisely so --scan keeps
    working in an isolated lab with no real outbound access.
    """
    log_info(f"Downloading OUI database from {config.OUI_SOURCE_URL} ...")
    # standards-oui.ieee.org rejects urllib's default User-Agent
    # (responds with 418); a normal browser-like User-Agent is enough
    # to get the file served.
    request = urllib.request.Request(
        config.OUI_SOURCE_URL,
        headers={"User-Agent": "Mozilla/5.0 (compatible; Internuncio-OUI-Updater/1.0)"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            content = response.read().decode("utf-8", errors="ignore")
    except Exception as e:
        log_err(f"Could not download the OUI database: {e}")
        return False

    # Each entry in the IEEE's oui.txt has a line like:
    #   70-C7-F2   (hex)		Apple, Inc
    # We only care about the hyphenated hex prefix and the vendor name
    # that follows "(hex)"; the rest (postal address, etc.) is
    # discarded since the scanner doesn't need it.
    pattern = re.compile(r"^([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$", re.MULTILINE)

    database = {}
    for prefix, vendor in pattern.findall(content):
        oui = prefix.replace("-", "").upper()
        database[oui] = vendor.strip()

    if not database:
        log_err("Downloaded content did not match the expected format; database was not generated.")
        return False

    os.makedirs(os.path.dirname(config.OUI_DB_PATH), exist_ok=True)
    with open(config.OUI_DB_PATH, "w", encoding="utf-8") as f:
        json.dump(database, f, indent=2, ensure_ascii=False, sort_keys=True)

    # Invalidate the in-memory cache so the next lookup reloads the
    # freshly written file instead of continuing to use the old version.
    global _oui_cache
    _oui_cache = None

    log_ok(f"OUI database updated: {len(database)} vendors saved to {config.OUI_DB_PATH}")
    return True
