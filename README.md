# Internuncio

Internuncio is a modular ARP-spoofing / MITM lab tool for evaluating the
detection capabilities of an IDS/IPS in an **isolated lab network**
(GNS3, VMware, or any other segment with no route to a real production
network or the internet). It performs classic ARP cache poisoning to
place itself between a victim host and its gateway, then uses Linux
traffic-control primitives to throttle or completely cut the victim's
bandwidth, generating traffic patterns an IDS should be able to detect.

> **This is an offensive network tool.** It is built exclusively for
> authorized testing on networks you own or are explicitly authorized to
> test — a personal lab, a CTF environment, or an internal security
> assessment with sign-off. It must never be pointed at a network you do
> not control. See [Legal / Ethical Notice](#legal--ethical-notice)
> below.

---

## Table of contents

- [How it works](#how-it-works)
- [Safety mechanisms](#safety-mechanisms)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration-configpy)
- [Usage](#usage)
  - [Network discovery (`--scan`)](#network-discovery---scan)
  - [Single-target attack (`--target`)](#single-target-attack---target)
  - [Multi-target attack (`--targets`)](#multi-target-attack---targets)
  - [Bandwidth limiting vs. total cut](#bandwidth-limiting-vs-total-cut)
  - [MAC vendor lookup and `--update-oui`](#mac-vendor-lookup-and---update-oui)
  - [Stopping the attack (kill-switch)](#stopping-the-attack-kill-switch)
- [Known limitations](#known-limitations)
- [Legal / Ethical Notice](#legal--ethical-notice)
- [License](#license)

---

## How it works

Internuncio combines three well-known primitives into one orchestrated
flow:

1. **ARP cache poisoning.** For a chosen victim and its gateway,
   Internuncio sends forged, unsolicited ARP "is-at" replies
   (gratuitous ARP) to each of them, claiming that the attacker's own
   MAC address corresponds to the other party's IP. Once both ARP
   caches are poisoned, all IP traffic between the victim and the
   gateway is physically routed through the attacker's network
   interface.

2. **IP forwarding.** With traffic now flowing through the attacker,
   the Linux kernel's IP forwarding (`/proc/sys/net/ipv4/ip_forward`)
   is enabled so the machine acts as a transparent router instead of
   silently dropping packets that aren't addressed to it — this is
   what keeps the attack a controlled MITM instead of an immediate,
   uncontrolled outage.

3. **Traffic shaping / blocking.** Once traffic is flowing through the
   attacker, `tc` (Linux Traffic Control) and `iptables` are used to
   degrade or cut it:
   - `tc qdisc ... tbf` caps the maximum throughput to whatever rate is
     requested (e.g. `500kbit`).
   - `tc qdisc ... netem` layers in packet loss and extra latency, to
     simulate a degrading link rather than just a slow one.
   - `iptables -j DROP` rules, scoped to the victim's IP, are used for
     a **total** cut (`--bandwidth 0`) instead of shaping.

Everything above is reversible in real time: interrupting the script
(`Ctrl+C`) sends the correct ARP replies to restore both hosts' caches,
tears down the `tc` queueing disciplines, removes any `iptables` rules
it created, and disables IP forwarding — returning the lab network to
its original state.

## Safety mechanisms

Internuncio is designed so that misuse requires deliberately bypassing
several layers, not just a typo:

| Mechanism | Where | What it does |
|---|---|---|
| **Subnet whitelist** | `config.WHITELIST_SUBNET` | Every IP — whether it comes from `--target`, `--targets`, or a `--scan` selection — is checked against this CIDR before anything else happens. Anything outside it is discarded with an "UNAUTHORIZED NETWORK" error. |
| **Manual confirmation** | `internuncio.py` | Attacking a single host requires an explicit `y` at a prompt. |
| **Reinforced confirmation** | `internuncio.py` / `config.MULTI_TARGET_CONFIRMATION_PHRASE` | Attacking more than one host at once requires typing an exact phrase (`YES-I-AM-SURE` by default), not just `y` — the blast radius of a mistake scales with the victim count. |
| **Thread cap** | `config.MAX_THREADS` | No more than 10 simultaneous poisoning sessions are allowed; extra targets are rejected with a warning. |
| **Scoped discovery** | `modules/scanner.py` | The scanner only ever probes `config.WHITELIST_SUBNET`, never an arbitrary range passed on the CLI. |
| **Self-exclusion** | `utils/network_utils.get_own_ip` | When selecting "all" hosts from a scan, the attacker's own IP is automatically removed from the victim list. |
| **Kill-switch** | `internuncio.py: sigint_handler` | `Ctrl+C` always restores ARP tables, removes `tc`/`iptables` rules, and disables IP forwarding before exiting — including mid-attack, across every active victim. |

## Requirements

- Linux (developed and tested for Kali / Parrot OS).
- Python 3.8+.
- `iproute2` (provides `tc`) and `iptables` — present by default on
  Kali/Parrot.
- Root privileges (required for raw sockets, `tc`, `iptables`, and
  writing to `/proc/sys/net/ipv4/ip_forward`).

## Installation

```bash
git clone https://github.com/Jokas-null/internuncio.git
cd internuncio
pip install -r requirements.txt
```

## Configuration (`config.py`)

Before running anything, edit `config.py` to match your lab:

```python
WHITELIST_SUBNET = "192.168.100.0/24"        # your isolated lab subnet
MULTI_TARGET_CONFIRMATION_PHRASE = "YES-I-AM-SURE"

ARP_RESOLVE_TIMEOUT = 4     # seconds to wait for an ARP reply
POISON_INTERVAL = 2         # seconds between poisoning rounds
SCAN_TIMEOUT = 3            # seconds to wait during --scan

MAX_THREADS = 10            # max simultaneous victims

DEFAULT_BANDWIDTH = "1kbit" # used when --bandwidth is omitted
TBF_BURST = "32kbit"
TBF_LATENCY = "400ms"
NETEM_LOSS = "10%"
NETEM_DELAY = "100ms"
```

`WHITELIST_SUBNET` is the single most important value: it is the hard
boundary of where the tool is allowed to operate.

## Usage

All commands require root.

### Network discovery (`--scan`)

```bash
sudo python3 internuncio.py --scan --interface eth0
```

Sends ARP requests across `WHITELIST_SUBNET` and prints every host that
answers, along with its MAC and its manufacturer (resolved offline from
the MAC's OUI prefix — see [MAC vendor lookup](#mac-vendor-lookup-and---update-oui)
below). Afterwards you're prompted to optionally select one, several
(`0,2`), or `all` of the discovered hosts to hand off to attack mode —
you'll then be asked for the gateway IP and desired bandwidth
interactively.

### Single-target attack (`--target`)

```bash
sudo python3 internuncio.py --target 192.168.100.50 --gateway 192.168.100.1 \
    --interface eth0 --bandwidth 500kbit
```

Poisons the victim and gateway's ARP caches, applies the bandwidth
limit, and prints a live status line until interrupted.

### Multi-target attack (`--targets`)

```bash
sudo python3 internuncio.py --targets 192.168.100.50,192.168.100.51 \
    --gateway 192.168.100.1 --interface eth0 --bandwidth 1kbit
```

Runs one poisoning session per victim (threaded, up to
`MAX_THREADS`), and requires typing the reinforced confirmation phrase
before proceeding.

### Bandwidth limiting vs. total cut

- `--bandwidth 500kbit` (or any `tc`-compatible rate) — shapes traffic
  with `tbf` + `netem`.
- `--bandwidth 0` — switches to a total block: per-victim `iptables
  DROP` rules instead of shaping.

### MAC vendor lookup and `--update-oui`

Every host found by `--scan` is annotated with its manufacturer,
resolved from the OUI (first 3 octets) of its MAC against a local
database (`data/oui_db.json`, built from the IEEE's official OUI
registry). This lookup is always offline — it never touches the
network — so `--scan` keeps working with no internet access.

A MAC with its "locally administered" bit set is reported as
`Randomized MAC (likely mobile device)` instead of a vendor name: that
bit indicates the address was generated on the device itself rather
than assigned by the IEEE, which is the default MAC-randomization
behavior of modern iOS and Android when joining a WiFi network.

To (re)generate `data/oui_db.json` from the latest IEEE data:

```bash
python3 internuncio.py --update-oui
```

This is the only command in the whole project that needs internet
access; it does not require `--interface` and does not touch the lab
network in any way.

### Stopping the attack (kill-switch)

Press `Ctrl+C` at any time. This is the *only* way the attack should be
stopped — it triggers `sigint_handler`, which:

1. Restores the real ARP entries for every active victim and the
   gateway.
2. Removes the `tc` queueing disciplines from the interface.
3. Removes any `iptables DROP` rules created for a total block.
4. Disables IP forwarding.

## Known limitations

- **`tc` shaping is interface-wide, not per victim.** `tbf`/`netem` are
  applied to the whole network interface's forwarded traffic. In
  multi-target mode, all currently poisoned victims share one
  aggregate bandwidth cap — they are not shaped independently. The
  total block (`--bandwidth 0`) *is* independent per victim, since
  `iptables` rules are scoped by IP. Fully independent per-IP shaping
  would require HTB classes with `u32`/`iptables --set-mark` filters,
  which is intentionally out of scope for this lab tool.
- **Vendor lookup is OUI-only.** It identifies the manufacturer from
  the MAC's first 3 octets, not the specific device model; consumer
  devices with a randomized MAC report as `Randomized MAC (likely
  mobile device)` rather than a real vendor, by design.
- **Layer-2 only.** ARP spoofing only works within the same broadcast
  domain/subnet; it cannot reach hosts behind a router relative to the
  attacker.

## Legal / Ethical Notice

Internuncio performs ARP cache poisoning and traffic manipulation —
techniques that, on a network you do not own or do not have explicit
written authorization to test, are illegal in most jurisdictions and
can disrupt production systems. This project is provided strictly for:

- Personal, isolated lab environments (GNS3, VMware, virtual switches)
  with no bridge to a production network or the internet.
- CTF competitions and security training environments.
- Authorized internal security assessments / IDS validation, with
  explicit sign-off from whoever owns the network.

The whitelist, confirmation prompts, and kill-switch reduce the chance
of accidental misuse, but they are not a substitute for authorization.
You are responsible for how and where you run this tool.

## License

Released under the [MIT License](LICENSE).
