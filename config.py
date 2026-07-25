"""
config.py

Global configuration for the "Internuncio" project.

All values that used to live as scattered constants in the original
monolithic script are centralized here, so every module (scanner,
spoofer, limiter, utils) imports them from a single place instead of
duplicating or desynchronizing them across files.
"""

# --- Hard safety guard: lab network whitelist ---
# ONLY IPs inside this subnet can be scanned/attacked. Change this value
# to match your internal GNS3/VMware lab network (an isolated network,
# with no real internet access). Any IP outside this range is discarded
# both by the scanner and by the attack modes.
WHITELIST_SUBNET = "192.168.100.0/24"

# --- Extreme confirmation phrase for multi-victim mode ---
# Must be typed exactly (uppercase and hyphens included) before attacking
# more than one host at once, precisely because the blast radius of a
# mistake multiplies with the number of simultaneous victims.
MULTI_TARGET_CONFIRMATION_PHRASE = "YES"

# --- Network timeouts and cadence ---
ARP_RESOLVE_TIMEOUT = 4   # seconds to wait for a response when resolving a MAC via ARP
POISON_INTERVAL = 2       # seconds between each round of poisoned ARP packets
SCAN_TIMEOUT = 3          # seconds to wait for responses during network discovery

# --- Simultaneous threads/victims limit ---
# Each active victim consumes a dedicated thread running its ARP-poisoning
# loop. This number is capped so neither the lab network nor the Python
# process itself gets out of control.
MAX_THREADS = 3

# --- tc (traffic control) parameters ---
DEFAULT_BANDWIDTH = "1kbit"
TBF_BURST = "32kbit"
TBF_LATENCY = "400ms"
NETEM_LOSS = "10%"
NETEM_DELAY = "100ms"

# --- OUI (vendor) database ---
# Local path of the vendor database (generated from the IEEE's official
# oui.txt) and the source URL used to refresh it via --update-oui. Normal
# scanning ALWAYS uses the local copy: only --update-oui needs internet
# access.
OUI_DB_PATH = "data/oui_db.json"
OUI_SOURCE_URL = "https://standards-oui.ieee.org/oui/oui.txt"
