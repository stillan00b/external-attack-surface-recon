# Phase 4 — Active scanning reference

The masscan→nmap handover, why it's shaped this way, the tuning knobs, and the
exact non-invasive invocations. Read this before running `04_active_scan.py`.

## Table of contents
- [Why two stages](#why-two-stages)
- [Stage A — masscan breadth pass](#stage-a--masscan-breadth-pass)
- [Stage B — nmap confirmation + service detection](#stage-b--nmap-confirmation--service-detection)
- [CDN / fronting reconciliation](#cdn--fronting-reconciliation)
- [Tuning table](#tuning-table)
- [Rate-ceiling composition](#rate-ceiling-composition)
- [What is explicitly forbidden](#what-is-explicitly-forbidden)

## Why two stages

The expensive operation is nmap service/version detection. Running it across all
65,535 ports on every in-scope IP is wasteful: most ports are closed and most
IPs may be dark. The cheap operation is a stateless SYN sweep that just asks
"is anything here?" masscan does that at high speed; nmap then does the careful
work on only the hits.

But masscan alone is not trustworthy as a final answer. It is **stateless** — it
fires SYNs and records SYN/ACKs without tracking connection state. Under packet
loss, rate-induced congestion, or against SYN-proxies and scrubbing appliances
(which banks and large enterprises run at the edge), it reports ports as open
that are not. So masscan output is **candidates**, and nmap — which is
stateful and completes enough of the handshake to be sure — is the
**confirmation**. The handover gives you masscan's speed and nmap's accuracy
without inheriting masscan's false positives.

```
in-scope IPs ──► masscan (fast, stateless)  ──► IP:port CANDIDATES
                                                      │
                          only these pairs ──────────►│
                                                      ▼
                         nmap -sV (stateful, version) ──► CONFIRMED open + service
                                                      │
                    masscan hit, nmap can't confirm ──► UNCONFIRMED (reported separately)
```

## Stage A — masscan breadth pass

Find candidate open ports across the authorized IP set as fast as the rate
ceiling allows.

```bash
# Targets, exclusions and ports ALL come from the gate. --print-targets refuses
# (non-zero exit) unless the gate passes, so a failed gate means no target file.
# RATE is scope.yaml rate.masscan_max_rate (default 1000).
G="python3 scripts/scope_gate.py --scope scope.yaml"
$G --print-targets  > targets_in_scope.txt || exit 2
$G --print-excludes > excludes.txt         || exit 3
PORTS="$($G --print-ports)"                 || exit 3

masscan -iL targets_in_scope.txt \
        --excludefile excludes.txt \
        -p "${PORTS}" \
        --max-rate "${RATE}" \
        --open-only \
        --wait 5 \
        -oL masscan_raw.txt

# Full-range sweep ONLY for scan.full_range_on hosts. Each entry must be an IP
# that passes `$G --check <ip>`; for a hostname, check it with its resolved IPs
# and list those IPs here, not the name.
masscan -iL full_range_hosts.txt --excludefile excludes.txt -p1-65535 \
        --max-rate "${RATE}" --open-only --wait 5 -oL masscan_full_raw.txt
```

**Why `--excludefile` when targets are already filtered:** it's a second
safeguard. If the target list is ever built wrong (a hand-edited file, a merge
bug, a broad cidr added after ASN review that swallows an excluded block), the scanner still
drops every `out_of_scope` cidr and IP. masscan reports how many ranges it
removed at startup. If that number is unexpectedly large, stop and check.
Hostname/domain exclusions can't go in an IP file. The matcher enforces them
(`--check`), and the gate prints a note listing them.

**Do the time math before choosing ports.** Duration ≈ (IPs × ports) ÷ rate.

| Scope | Ports | @ 1000 pkt/s |
|-------|-------|--------------|
| one /24 | external-default (115) | ~30 s |
| one /24 | 1-65535 | ~4.7 h |
| one /16 | external-default (115) | ~2.1 h |
| one /16 | 1-65535 | ~50 days |

This is why the default is the curated `external-default` set and the full
range is reserved for named high-value hosts. `scope_gate.py` prints this
estimate as the "Masscan plan" and **fails the gate** if the pass can't finish
inside the remaining engagement window. Fix that by narrowing `scan.ports`,
trimming `scan.full_range_on`, or splitting scope across runs. Don't fix it by
raising the rate.

Notes:
- `--max-rate` is the single most important safety control here. It is an
  aggregate ceiling; if you shard masscan across hosts, the rates must sum under
  it (see composition below).
- `--open-only` keeps the output to actual SYN/ACKs.
- `--wait 5` lets late responses arrive before exit, reducing false negatives.
- Parse `masscan_raw.txt` into normalized `IP:port` candidate pairs for Stage B.
- Treat **every** pair as unverified until nmap confirms it. Do not report
  masscan results as findings on their own.

## Stage B — nmap confirmation + service detection

Confirm each candidate and identify the service. nmap touches **only** the
ports masscan flagged.

```bash
# CANDIDATES: a file of "IP:port" → convert to nmap's grouped form
# (one -p list per host, or use a host:port handoff). TIMING is scope.yaml
# rate.nmap_timing (default T3).
nmap -sS -sV \
     -Pn \
     --version-intensity 5 \
     -"${TIMING}" \
     -p "${PORTS_FOR_HOST}" \
     --max-retries 2 \
     --excludefile excludes.txt \
     -oA nmap_confirm_<host> \
     "${HOST}"
```

Notes:
- `-sV` is the service/version detection — the whole point of this stage.
- `--excludefile` is the same file masscan used. The CDN-fallback and
  hostname passes (below) feed nmap targets that never went through masscan,
  so nmap needs its own copy of the safeguard. Always pass nmap the
  **checked IPs**, never a hostname, so a DNS change between `--check` and the
  scan can't redirect it.
- `-Pn` skips host discovery here because masscan already proved the host
  answers on a port; re-pinging wastes time and adds noise.
- **No `-sC`** by default. The default-script set (`-sC` = `--script=default`)
  includes scripts that probe more than we want for a pure inventory. If the
  operator wants light banner enrichment, enable a hand-picked safe subset
  explicitly — never the whole default category, and never `vuln`.
- A candidate nmap reports as `closed`/`filtered`/unresponsive is recorded
  **unconfirmed**, listed separately in the report, never as open.
- `--version-intensity 5` is a balanced default; lower it to 2 for a quieter,
  faster pass on fragile targets.

Then identify live web services and do a light tech fingerprint:

```bash
httpx -l confirmed_hosts.txt -silent -title -tech-detect -status-code -o httpx.txt
whatweb -i confirmed_web_hosts.txt --log-brief whatweb.txt
```

> Caveat: this `httpx` is ProjectDiscovery's binary, which shares its name with
> the Python `httpx` library. If `httpx` on your PATH resolves to the Python
> module's console script, the wrong tool runs. Confirm with `httpx -version`
> (expect a ProjectDiscovery banner); preflight warns if it looks wrong.

## CDN / fronting reconciliation

Two cases to handle so the report doesn't lie:

1. **Phase 1 host with no masscan hit.** Hosts discovered via CT logs / passive
   DNS that masscan didn't flag may sit behind a CDN or load balancer that
   ignores raw SYN sweeps. Give them an optional direct nmap pass on the top
   ports rather than dropping them silently.
2. **Host resolving to a CDN edge.** If an IP falls in a known CDN range, you
   are scanning the CDN, not the origin. Flag the host as CDN-fronted in the
   report and in the coverage ledger ("scanned CDN edge, not origin") so its
   open ports aren't attributed to the org's own infrastructure.

Detection order in `04_active_scan.py`:
- **Published edge ranges.** Cloudflare (`/ips-v4`, `/ips-v6`), Fastly
  (`api.fastly.com/public-ip-list`), and AWS CloudFront (the `CLOUDFRONT`
  service in `ip-ranges.json`).
- **A CNAME-name heuristic** for Akamai, Azure CDN/Front Door, Imperva,
  Edgecast and other providers that publish no stable list.

A failed range download degrades to the heuristic and is logged. An
`in_scope` CIDR that overlaps a published edge range produces a warning and a
"SCOPE CHECK" intelligence gap.

## UDP pass

TCP sweeps miss VPN gateways (IKE 500/4500, OpenVPN 1194, WireGuard 51820),
SNMP (161), DNS (53) and NTP (123). Those are some of the most useful external
findings. After Stage B, Phase 4 runs one nmap UDP scan:

```bash
nmap -sU -Pn -n -p U:53,123,161,500,1194,4500,51820 --max-retries 1 \
     --max-rate "${RATE}" -T3 --excludefile excludes.txt -iL targets_in_scope.txt -oX udp.xml
```

- It needs root. Without it, the UDP pass is skipped and recorded as a gap.
- It uses nmap's built-in protocol payloads only. **No `-sV`**: nmap's SNMP
  version probes try community strings, which is credential guessing. No
  scripts.
- `open` means the service replied. `open|filtered` means no reply, which UDP
  can't tell apart from filtered. Those are counted, never reported as open.
- It runs after TCP, sequentially, at the global ceiling, so the ceiling still
  holds. The gate's estimate includes IPs × UDP ports × 2 probes. Real time
  can be longer, because hosts rate-limit ICMP port-unreachable replies.
- The report gives SNMP high severity and DNS medium, with a manual check for
  open recursion. NTP is low, with a manual check for mode 6/7. VPN endpoints
  are info.

## Tuning table

| Knob | scope.yaml field | Quiet | Default | Faster |
|------|------------------|-------|---------|--------|
| masscan rate | `rate.masscan_max_rate` | 200 | 1000 | 5000 (>10000 needs `high_rate_approval`) |
| masscan ports | `scan.ports` | short list | `external-default` | + `full_range_on` hosts |
| nmap timing | `rate.nmap_timing` | T2 | T3 | T4 |
| version intensity | (in script) | 2 | 5 | 7 |
| top ports | `scan.top_ports` | 100 | 1000 | 1000 + full on key hosts |
| parallel workers | `rate.parallel_workers` | 1 | 4 | 8 |

Pick "quiet" for fragile or sensitive targets, "faster" only when the
engagement window is tight and the target can take it. Default is the safe
middle for external work.

## Rate-ceiling composition

Per-worker rates do **not** compose for free. If the global masscan ceiling is
1000 pkt/s and you run 4 shards, each shard gets 250, not 1000. The same logic
applies to nmap workers: splitting the host list across N parallel nmap
processes means the aggregate must still respect the global posture. The
`04_active_scan.py` orchestration divides the ceiling by worker count when it
fans out. Ten "gentle" workers each at the full ceiling is a flood, and it's
exactly what trips target defenses and cloud-provider abuse detection.

## What is explicitly forbidden

These stay off regardless of operator urgency. They are not part of an
attack-surface inventory and flipping them changes the engagement's character
and authorization:

- `nmap --script vuln` or any `vuln` NSE category.
- Intrusive / exploit / brute / dos NSE categories.
- Any auth or credential attack.
- Aggressive `-T5` against production edge unless explicitly authorized in
  `scope.yaml` and acknowledged in the report.
- Scanning anything not matched by the in-scope matcher, including assets that
  *resolve* into out-of-scope or third-party ranges.
