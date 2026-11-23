---
name: external-attack-surface-recon
description: >-
  Discover and inventory an organization's internet-facing attack surface for
  an AUTHORIZED penetration-testing engagement, gated by a scope.yaml
  authorization check. Runs passive asset discovery (CT logs,
  subfinder/amass, DNS, WHOIS, ASN prefixes), lookalike/phishing-domain
  detection, subdomain-takeover candidate detection, a rate-capped
  masscan-to-nmap port and service inventory of in-scope IPs only, and
  email/DNS/TLS posture checks, then writes a provenance-tagged report with a
  computed coverage badge and ledger. Use whenever the user asks to map,
  enumerate or assess a company's external attack surface or footprint; find
  the domains, subdomains, IPs or exposed services an org owns; run external
  recon or perimeter discovery for a client engagement; or check for phishing
  lookalikes, dangling DNS / subdomain takeovers, or SPF/DMARC/TLS weaknesses —
  even if they don't say "attack surface". Do NOT use for internal-network
  testing, web-app testing, exploitation, credential attacks or vulnerability
  scanning.
---

# External Attack Surface Recon

## Compatibility

Default environment: Kali Linux on Windows / WSL2.
- **Required:** python3 with PyYAML, dig, nmap, masscan (with root or
  `cap_net_raw`).
- **Strongly recommended:** subfinder, amass, whois, openssl.
- **Recommended:** dnstwist, ProjectDiscovery httpx (not the Python `httpx`
  library, which shares the name), whatweb, subzy.
- **Optional:** Shodan API key, gowitness/aquatone.

A missing optional tool or key disables only its module. The script falls
back where it can: a built-in lookalike generator, a built-in takeover
signature check, and a stdlib HTTP probe. The reason is recorded in
`status.json` and in the report's intelligence gaps. Run `00_preflight.sh` to
see what will run fully and what will be degraded.


Map the full internet-facing footprint of an authorized target organization:
every domain and subdomain it owns, its IP space, exposed services, lookalike
phishing domains, and dangling-DNS takeover candidates. The output is an
auditable inventory and report — not an exploitation run.

This skill is built around one non-negotiable idea: **authorization defines
scope, and nothing touches a target host until scope is confirmed.** Passive
OSINT may run on seeds, but every active phase is gated. Read the
Authorization Gate section before anything else.

## Operating principles

Follow these throughout; they shape every decision below.

- **Authorization is the boundary, not the input.** Discovery tools *propose*
  assets; the scope file *disposes*. A discovered host is only ever scanned if
  it falls inside the authorized ranges in `scope.yaml`. This prevents the
  classic failure where enumeration drags you onto third-party or out-of-scope
  infrastructure. A hostname under the client's domain is **not** enough: it is
  scannable only if every IP it resolves to is inside an authorized CIDR.
  `shop.example.com` → Shopify is the client's name on someone else's server.
- **Non-invasive by design.** No exploitation, no `--script vuln`, no intrusive
  or exploit NSE categories, no credential attacks, no DoS-class traffic. If a
  step would meaningfully perturb a target beyond a courteous scan, it does not
  belong here.
- **Provenance on everything.** Every asset and finding records which tool/source
  produced it and when it was first seen. This mirrors a well-run threat-intel
  pipeline and is what lets findings be merged, audited, and trusted.
- **No fabrication.** If masscan flags a port that nmap can't confirm, it is
  reported `unconfirmed`, never `open`. If a source is unavailable, mark it
  skipped — never invent hosts, ports, or banners.
- **Degrade gracefully.** A missing API key or tool disables one module with a
  logged warning; it never aborts the run.
- **Validate small, then scale.** Prove the pipeline on a single seed
  domain/host, confirm the output looks sane, then fan out to full scope.

## Workflow overview

Run the phases in order. Gate checks (🔒) must pass before proceeding.

```
Phase 0  Authorization gate + scope load          🔒 hard precondition
Phase 1  Asset discovery                           passive (seeds OK)  + AXFR/PTR 🔒
Phase 2  Lookalike / phishing domain detection     passive DNS/CT       + live probe 🔒 + opt-in
Phase 3  Subdomain-takeover candidate detection    passive DNS          + HTTP fingerprint 🔒
Phase 4  Active scan: masscan → nmap handover      🔒 whole phase
Phase 5  Posture checks                            passive email/DNS    + TLS handshakes 🔒
Phase 6  Aggregate + report                        local only (badge + ledger)
```

**What counts as passive.** A step is passive only if it sends nothing to the
client's hosts or to a third party's hosts. Passive means querying data
sources (CT logs, OSINT APIs, WHOIS, RIPEstat) and doing ordinary lookups
through a recursive resolver. Anything that sends queries or connections
straight to a host is **gated** (🔒), and the script checks the gate itself:
AXFR and PTR sweeps against the client's nameservers, HTTP to any host, TLS
handshakes, port scans. Hosts that aren't the client's (lookalikes, SaaS
targets) also need an explicit opt-in in `scope.yaml`.

Optional **incremental mode** (see "Intel integration") narrows Phases 1–4 to
newly-discovered assets when an asset-delta feed is supplied.

---

## Phase 0 — Authorization gate (hard precondition)

Do not run any phase that sends packets to a target until ALL of the following
hold. If any fails, stop and tell the operator exactly what's missing.

1. `scope.yaml` exists and parses. Use `scope.yaml.example` as the template.
2. It contains at least one authorized domain or CIDR that survives
   validation.
   - Invalid CIDRs, and anything broader than /16 IPv4 or /64 IPv6, are
     rejected.
   - Domains must be bare domains. URLs, ports and mid-name wildcards are
     rejected.
   - `*.example.com` covers subdomains only, not the apex.
   - ASNs alone authorize nothing (see Phase 1).
3. The operator confirmation flag is set: `authorization.confirmed: true`.
4. The engagement window is valid (start before end) and includes the current
   date/time.
5. Rate settings are within ceilings: `masscan_max_rate` ≤ 10,000 pkt/s and
   `nmap_timing` ≤ T4, unless `rate.high_rate_approval` records the client's
   approval. `parallel_workers` is 1–16. `nmap_min_rate × parallel_workers` must
   not exceed `masscan_max_rate`.
6. `scan.ports` parses, and the estimated masscan duration
   ((IPs × ports + full-range hosts × 65,535) ÷ rate) fits in the time left in
   the window.

All six are enforced by `scripts/scope_gate.py`. An ASN-only scope fails
check 2 with instructions. Run Phase 1 passively to list the announced
prefixes, confirm them with the client, and add the approved ones to
`in_scope.cidrs`. Run it and act on the result
rather than checking by eye:

```bash
python3 scripts/scope_gate.py --scope scope.yaml          # exit 0 = passed
```

Read its **Masscan plan** (target IPs, port count, estimated duration) and its
warnings back to the operator before any active phase. If the gate fails, stop
and relay the listed reasons. Don't edit `scope.yaml` to make it pass. The
operator owns that file.

`scope.yaml` defines, at minimum: engagement ID, client name, authorized
domains / IP ranges (CIDRs) / ASNs (lookup only), an explicit out-of-scope list, the
engagement window (start/end), a global rate ceiling, and the confirmation
flag. The skill copies this header verbatim into every report so all output is
traceable to an authorization.

**Scope validation is continuous, not one-time.** Build an in-scope matcher
from the authorized CIDRs and domains. ASNs are only used to look up prefixes. Every asset discovered downstream is
checked against it *before* it becomes eligible for active scanning.
Out-of-scope discoveries are logged (they're useful context — e.g., a subdomain
pointing at a third-party SaaS) but never scanned.

```bash
G="python3 scripts/scope_gate.py --scope scope.yaml"
$G --check 203.0.113.42                              # IP or CIDR
$G --check www.example.com --ips 203.0.113.5,203.0.113.6   # hostname + its resolved IPs
$G --check www.example.com --passive                 # passive eligibility only
```

Active `--check` runs the full gate first. If the gate fails, nothing is in
scope. A hostname needs its resolved IPs. Pass the ones from your Phase 1 table
with `--ips`, or omit `--ips` and the gate resolves the name itself. It passes
only if **all** of them are authorized and not excluded. Exit 0 = in scope;
anything else = do not touch. `--passive` checks the domain only, needs no
gate pass, and never authorizes packets to the host.

**If running from cloud infrastructure (e.g., AWS EC2):** outbound scanning of
third-party targets falls under the provider's acceptable-use policy, not its
pentest policy. Before active phases, confirm the operator has notified the
provider's trust/abuse team of the engagement window and expected traffic, and
keep the authorization letter on hand. Note this in the report header.

The passive parts of Phases 1, 2, 3 and 5 may run before the gate passes.
Every gated step requires steps 1–6 above, and each script re-runs the gate
itself before such a step. A phase started after the window closes is
refused.

---

## Phase 1 — Passive enumeration & asset discovery

Goal: discover everything the org owns without sending traffic to its hosts.
Aggregate all sources into one master asset table:
`hostname → resolved IP(s) → source(s) → first_seen → in_scope flag`.

Sources, roughly highest-yield first:

- **Certificate Transparency** (crt.sh, and Censys cert search if keyed). The
  single best subdomain source — newly issued certs reveal new hostnames.
- **Passive subdomain enumeration**: `subfinder` and `amass` (passive mode),
  `assetfinder`. Take the deduplicated union.
- **DNS records** via `dig` through the recursive resolver:
  A/AAAA/MX/NS/TXT/SOA/CAA per domain. Record CNAMEs carefully; Phase 3 needs
  them.
- **RDAP/WHOIS** on seed domains for registrant patterns and nameservers.
- **ASN → announced prefixes** via RIPEstat. They are **reported, never added
  to scope**. Prefixes outside `in_scope.cidrs` are listed as
  "announced-not-authorized" for the operator to confirm with the client.
  Announced ≠ authorized.
- **Shodan** DNS data (if keyed). This is *their* index — you send no packets
  to the target. Censys isn't automated (its API changed); search it manually
  if licensed.

**Gated (🔒) light-active steps.** These run only if the gate passes, and
`--no-light-active` skips them:
- An opportunistic **AXFR** against each in-scope domain's own nameservers.
- A **PTR sweep** of the in-scope IPv4 CIDRs, capped by `--ptr-max`.

Both send queries straight to the client's infrastructure, so they can't run
before confirmation. Storage-bucket guessing isn't automated: it hits cloud
providers, so do it by hand only if the RoE allows it.

Resolve every discovered hostname to IPs and tag each row with its source(s)
and `first_seen`. This table is the spine the rest of the run hangs off.

---

## Phase 2 — Lookalike / phishing domain detection

Goal: surface domains impersonating the brand (defensive, high client value).

**Lookalikes are third-party infrastructure, often an attacker's.** By default
this phase only uses DNS, CT logs and WHOIS. It never contacts the lookalike's
own hosts.

1. Permute the brand domain(s) with `dnstwist`, or with the built-in generator
   if it's absent: typos, homoglyphs, TLD swaps, bitsquatting, insertions,
   brand+keyword combinations. **Never use `dnstwist --mxcheck`.** It sends
   SMTP to the lookalike's mail server.
2. For each candidate, enrich: registration status, registrar, creation date,
   A record, **MX presence** (active mail = phishing-ready), and a CT-log check
   for issued certs (someone stood up real infrastructure). Candidates on the
   client's own IPs or nameservers are flagged "likely client-owned".
3. **Live probe 🔒 + opt-in:** one HTTP GET per registered lookalike to spot
   cloned pages. It runs only if the gate passes **and**
   `lookalike.live_probe: true`, which means the RoE allows contacting
   third-party infrastructure. Never submit lookalikes to public scanning
   services such as urlscan.io public scans, because that publishes the
   engagement.
4. Risk-rank: MX **and** (cert **or** live page) = high. One of those = medium.
   Registered only = low. Unregistered permutations are counted, not listed.

Report this as a ranked table; it's one of the most actionable defensive
outputs of the engagement.

---

## Phase 3 — Subdomain-takeover candidate detection

Goal: find dangling DNS records pointing at deprovisioned services.

1. Re-resolve every Phase 1 hostname under an in-scope domain, and walk its
   CNAME chain (passive).
2. Match CNAME targets against `signatures/takeover_fingerprints.json`. Treat
   a chain that ends without an address as dangling. That covers NXDOMAIN, and
   also NOERROR with no data, which some providers return for names that don't
   exist.
3. **HTTP fingerprint 🔒:** one GET over https and http to the client's
   hostname, matching the provider's "unclaimed" page. The request lands on the
   third-party provider. That's the one sanctioned exception to "only touch
   authorized IPs", because the hostname is the client's and it's a single page
   fetch. It needs the gate to pass. `takeover.http_fingerprint: false` turns
   it off. `subzy` adds results if installed.
4. Flag **candidates** only. Report each with the manual validation step
   ("verify by attempting claim within authorized scope"). The skill never
   auto-claims a resource — confirmation is a human, in-scope action. This keeps
   the phase non-destructive.

Takeover candidates are high severity in the report: a claimable subdomain is a
direct brand-and-trust compromise vector.

---

## Phase 4 — Active scan: masscan → nmap handover (gated)

Goal: a confirmed open-port and service inventory across in-scope hosts. No
vuln scripts, no intrusive NSE — service detection only.

This is a **two-stage handover** that buys masscan's speed *and* nmap's
accuracy. Read `references/scanning.md` for the full rationale, tuning table,
and exact invocations. Summary:

**Stage A — masscan breadth pass.** Run masscan across the in-scope IP set to
find *candidate* open ports fast. masscan is stateless: under packet loss or
against SYN-proxies / scrubbing appliances (which large orgs have) it produces
false positives. So its output is treated strictly as **candidates**, never as
confirmed-open. Rate is hard-capped from `scope.yaml`'s global ceiling — default
`--max-rate 1000` — because this stage is the loudest and most abuse-prone part
of the run. Output: a list of `IP:port` candidates.

Every masscan input comes from the gate, never from a hand-built list:

- **Targets:** `--print-targets`, which emits nothing and exits non-zero unless
  the gate passes.
- **Ports:** `--print-ports`, from `scan.ports`. The default is
  `external-default`, 115 common external TCP ports. A full 1–65535 sweep is
  only for `scan.full_range_on` hosts, because at 1000 pkt/s it takes ~4.7h per
  /24 and ~50 days per /16.
- **Exclusions:** `--print-excludes`, passed to masscan **and** nmap as
  `--excludefile`. It's a second safeguard, so a bad target list still can't
  reach an out-of-scope IP.

**Stage B — nmap confirmation + service detection.** Feed *only* the
masscan-discovered `IP:port` pairs into nmap with version detection (`-sV`,
default timing `-T3`), explicitly **no** `--script vuln` and **no**
intrusive/exploit NSE categories. nmap gets the same `--excludefile`, and
always targets IPs, never hostnames. Because nmap's SYN scan is stateful, this
stage filters out masscan's false positives — the handover is what gives speed
*and* accuracy. nmap only ever touches ports masscan already flagged, keeping
the workload small and the footprint low. A port that masscan flagged but nmap
can't confirm is recorded `unconfirmed` — never reported as open.

**CDN/CDN-fronted reconciliation.** Hosts discovered via CT/DNS (Phase 1) that
have no masscan hit get an optional direct nmap pass, since CDN-fronted hosts
may not behave predictably under masscan. **Each one must pass
`--check <host> --ips <resolved IPs>` first**, and nmap then scans those checked
IPs. A host on a CDN edge normally fails that check, because CDN IPs aren't in
the client's CIDRs. Record it in the ledger as "CDN-fronted (provider) — not
scanned" rather than scanning it. If the RoE explicitly authorizes the CDN
range and it's in `in_scope.cidrs`, flag the results: you scanned the CDN, not
the origin, so don't report those ports as the org's.

How CDN detection works:
- **Published ranges** come from the providers: Cloudflare, Fastly and AWS
  CloudFront. That's public data, cached per run in `phase4/cdn_ranges.json`.
- **A CNAME-name heuristic** covers providers with no public list: Akamai,
  Azure, Imperva and others. The report marks those detections as heuristic.
- **An `in_scope` CIDR that overlaps a CDN edge** is flagged as a likely scope
  mistake. Those IPs serve other customers too.

**UDP pass (root).** After the TCP stages finish, one `nmap -sU` runs over the
same targets and excludes for `scan.udp_ports`: DNS, NTP, SNMP, IKE, NAT-T,
OpenVPN, WireGuard.
- It uses nmap's built-in protocol payloads only. There's no `-sV`, because
  its SNMP probes guess community strings, and no scripts.
- "Open" means the service replied. "open|filtered" means no reply. Those are
  counted in the ledger but never reported as open.
- Without root it's skipped, and the report says UDP wasn't covered.
- The gate counts the UDP probes in its time estimate. The real duration can
  be longer, because targets rate-limit ICMP.

**Scale lever (single-node).** For large host sets, split the in-scope list
into chunks and run a small pool of nmap workers in parallel, each with its own
rate cap. The per-worker caps must **sum to under** the global ceiling — ten
"gentle" workers still constitute a flood. The chunk/work-unit format is defined
in `references/work-units.md` so this execution layer can later be swapped for a
distributed runner without changing the methodology.

Also run `httpx` to identify live web services, and a light tech fingerprint
(`whatweb`) on the web surface. Run both **only on hosts that passed the active
check**, not on everything Phase 1 discovered. Each sends HTTP requests to the
host.

### Abort procedure

Stop Phase 4 immediately if any of these happen:
- the client or your engagement lead asks you to stop
- you see signs of impact (services slowing or failing, alerts the client
  mentions)
- the script prints `DROPPED out-of-scope …`, which means the target list is
  wrong
- anything else looks unexpected

**How to stop:**
- Press **Ctrl-C** in the terminal running the phase, or
- from any other terminal, run `touch <run-dir>/STOP`.

Either one kills every running masscan and nmap process, including their child
processes. The abort is recorded in `status.json`, and the phase exits with
code 4. The phase also aborts by itself when the engagement window ends
mid-scan, because the authorization has expired. While a `STOP` file exists,
Phase 4 refuses to start.

**After stopping:**
1. Call the `engagement.emergency_contacts`. The gate and the report header
   print them.
2. Note the time (UTC) and what you saw.
3. Don't resume until whoever asked for the stop clears it. Then delete the
   `STOP` file and re-run Phase 4.

Results gathered before the abort stay in the run directory. Phase 6 reports
the phase as aborted and lowers the coverage badge.

---

## Phase 5 — Read-only posture checks

All pure-read, all high client value, all from data you can pull without
hammering targets:

- **Email / DNS (passive):** these come from DNS lookups.
  - SPF: presence, `+all`/`?all`/`~all`, multiple records, more than 10 DNS
    lookups, `ptr`.
  - DMARC: presence, `p=none`, `pct`, `sp=none`, missing `rua`.
  - Common DKIM selectors. This is information only, because a missing
    selector doesn't prove there's no DKIM.
  - MTA-STS, TLS-RPT, CAA, DNSSEC.
- **TLS 🔒:** weak protocol support **can't** be read from earlier banners.
  It takes a handshake. For each *confirmed* TLS service from Phase 4, re-check
  the IP and make up to ~6 handshakes:
  - one verified (certificate chain and hostname)
  - one to read the certificate (expiry, issuer, SANs)
  - one per protocol version from TLS 1.0 to 1.3

  There's no cipher enumeration. nmap's `ssl-enum-ciphers` is in the
  *intrusive* NSE category, so it's excluded. `testssl.sh` stays opt-in and
  manual. STARTTLS (SMTP/IMAP/POP) isn't tested.
- **Screenshots** (optional, manual): run `gowitness`/`aquatone` on
  `phase4/web_urls.txt`.

---

## Phase 6 — Aggregation & report

Produce a timestamped output directory containing: raw per-tool logs, the
consolidated asset inventory (CSV + JSON), per-phase findings, and a Markdown
report. The report MUST include, in this order:

1. **Header** — engagement ID, client, scope recap (verbatim from
   `scope.yaml`), generation timestamp, and the **scan-coverage badge**.
2. **Executive summary** — board-relevant, a handful of bullets.
3. **Asset inventory** — counts and the hostname/IP table.
4. **Lookalike risk table** (Phase 2), ranked.
5. **Takeover candidates** (Phase 3), each with its manual-validation note.
6. **Port/service matrix** (Phase 4) — confirmed open ports only; `unconfirmed`
   listed separately.
7. **Posture findings** (Phase 5) — SPF/DMARC/TLS.
8. **Intelligence gaps** — what couldn't be determined and why (e.g., "10.x
   range behind Cloudflare; scanned CDN edge, not origin").
9. **Appendix A: Scan-Coverage Ledger** (mandatory) — one row per authorized
   scope block: IPs/hosts enumerated, scanned, skipped (with reason:
   rate-limited / CDN-fronted / out-of-scope / resolves outside authorized
   CIDRs / unreachable).

**Scan-coverage badge** (stamp exactly one, computed from the ledger):

Coverage = IPv4 addresses masscan swept ÷ non-excluded authorized IPv4
addresses.

- `COVERAGE: FULL` — ≥ 95%, no failed nmap host jobs, not a `--only` run.
- `COVERAGE: PARTIAL` — ≥ 50%.
- `COVERAGE: MINIMAL` — < 50%, a `--only` validation run, or Phase 4 never
  ran. The report is indicative only.

`06_report.py` computes the badge. A missing or hand-edited badge invalidates
the report.

**Severity** (defined in `06_report.py`; services match by port *or* nmap
service name):

- **High:**
  - takeover candidate on a "vulnerable"-status provider
  - AXFR allowed
  - exposed RDP/VNC, Telnet, SMB/NetBIOS/MSRPC
  - exposed databases, Redis, Memcached, Elasticsearch, Kafka, ZooKeeper
  - exposed Docker API, etcd, kubelet, Consul
  - exposed NFS/rpcbind, Modbus/S7/IPMI, SNMP (UDP 161)
  - SPF `+all`, expired TLS certificate
  - a product matching the prioritization feed
- **Medium:**
  - takeover candidate on an "edge"-status provider
  - SSH, FTP, WinRM, LDAP, the Kubernetes API, admin consoles (Kibana,
    Webmin, RabbitMQ, …)
  - management or edge products (Jenkins, BIG-IP, FortiGate, Citrix,
    GlobalProtect, …)
  - missing DMARC or `p=none`, missing SPF, SPF over 10 lookups
  - legacy TLS, untrusted certificate, certificate expiring within 30 days
  - lookalike with MX, a certificate or a live page
  - DNS answering on UDP 53 (check manually for open recursion)
- **Low:** SPF `~all`, DMARC `pct<100`, missing `rua`, hostname mismatch,
  registered-only lookalikes, NTP on UDP 123 (check manually for mode 6/7).
- **Info:** missing MTA-STS, CAA, DNSSEC; VPN endpoints (IKE, NAT-T, OpenVPN,
  WireGuard).

JSON is written alongside the Markdown so the output can feed other tooling.

### Handling the output

A run directory is a map of the client's attack surface. Treat it as
confidential client data from the moment Phase 1 writes it.

- **Store it on an encrypted volume** (LUKS/BitLocker/FileVault, or an
  encrypted container). The scripts create everything owner-only (files 0600,
  directories 0700).
- **Never commit it.** The scripts drop a `.gitignore` (`*`) into
  `output.dir`.
- **Never upload results or targets to public services.** That includes
  public urlscan.io scans, pastebins, public AI tools, and VirusTotal URL
  submissions for client assets. Doing so publishes the engagement.
- **API keys stay in environment variables.** They are never written to
  `scope.yaml`, `commands.log` or raw output. Shodan's key in particular is
  kept out of the logged URL.
- **Share the deliverable, not the run directory.** Hand over `report.md` and
  `report.json` (and `assets.csv` if the client wants it). `raw/` and
  `commands.log` are working papers. Keep them for the retention period in
  case the client asks what was sent when.
- **Retention:** set `output.retention_days` to what the contract says. The
  report header prints the deletion deadline. When it passes, delete the run
  directory securely: `shred -u` the files, or destroy the encrypted container.
  Record the deletion.

---

## Intel integration (two channels, kept separate)

If the operator runs a companion threat-intelligence pipeline, integrate at
**two distinct layers** — and never let them blur, because the safety
properties differ.

**Prioritization channel (threat-landscape intel → ranking).** A
threat-landscape feed (CVEs, exploit status, KEV listings, GreyNoise activity,
TTPs) is consumed *only* to rank discovered services. When Phase 4 finds a
service version that matches an actively-exploited product, flag it
high-priority for manual review. Critically, this does **not** make the skill
confirm the vuln — it runs no vuln NSE. It says "this exposed service is running
something under active exploitation as of today's intel; verify manually." The
daily cadence of such a feed is what makes this worthwhile (KEV/GreyNoise status
shifts day to day).

**Asset-delta channel (asset-discovery feed → targets).** A separate feed that
watches *your* surface (new CT certs, new passive-DNS records, newly-indexed
Shodan services) can supply an `intel_delta.json` to drive **incremental mode**:
prioritize newly-discovered assets instead of re-scanning the full surface
every run. Every delta entry **still passes the Phase 0 scope gate** before
anything touches it.

**The hard boundary:** threat-landscape **IOCs (attacker IPs/domains/hashes)
must never enter the scan target set.** Scanning attacker infrastructure because
it appeared in a feed is exactly the scope violation Phase 0 exists to prevent.
IOCs may flow into the *report* as defensive context (does any discovered asset
resolve to known-bad infra? — a read-only lookup), but never into target
selection. Prioritization intel ranks; only the scope-gated asset-delta selects.

See `references/intel-contract.md` for the `intel_delta.json` shape and the
prioritization-export shape.

---

## File map

```
external-attack-surface-recon/
├── SKILL.md                       (this file)
├── scope.yaml.example             authorization + scope template
├── scripts/
│   ├── 00_preflight.sh            tool + API-key check; capability map
│   ├── scope_gate.py              Phase 0 gate, in-scope matcher, scan inputs
│   │                              (--check / --print-targets / --print-excludes / --print-ports)
│   ├── common.py                  shared: run dir, status ledger, audit log, DNS/HTTP helpers
│   ├── 01_passive_enum.py         Phase 1 (passive; AXFR/PTR gated)
│   ├── 02_lookalike.py            Phase 2 (DNS/CT/WHOIS; live probe gated + opt-in)
│   ├── 03_takeover.py             Phase 3 (DNS; HTTP fingerprint gated)
│   ├── 04_active_scan.py          Phase 4 (gated; masscan→nmap; --dry-run, --only)
│   ├── 05_posture.py              Phase 5 (email/DNS passive; TLS gated)
│   └── 06_report.py               aggregation, badge, ledger, report.md/json, assets.csv
├── signatures/
│   └── takeover_fingerprints.json claimable-service signatures
└── references/
    ├── scanning.md                Phase 4 rationale, tuning, invocations
    ├── work-units.md              work-unit + result-record shapes (distribution-ready)
    └── intel-contract.md          intel-delta + prioritization-feed shapes
```

**Run directory.** Phase 1 creates
`<output.dir>/<engagement-id>_<UTC timestamp>/`. Every later phase takes
`--run-dir` pointing at it. Each run holds:

- `scope_snapshot.yaml` and its sha256. A later phase refuses to run if
  `scope.yaml` has changed since the run started.
- `status.json`: per-phase modules marked ran, degraded, skipped or failed,
  with reasons. This becomes "Intelligence gaps".
- `commands.log`: every external command and network action, with timestamps.
  This is the audit trail.
- `raw/`: tool output.
- `phase1/` … `phase5/`: results.
- `report.md`, `report.json`, `assets.csv`, `assets.json`.

Use the scripts. Never run a phase's tools by hand with a target list you
wrote yourself. If a script can't do something you need, take every input
(targets, ports, excludes, per-host checks) from `scope_gate.py`.

## Data contracts

The JSON shapes this skill passes between phases are defined **inline in the
reference files** — they are the canonical contracts, not loose examples. There
is deliberately no `schemas/` directory: these records are produced and consumed
by this skill's own scripts, so a separate schema file would just be a second
description that can drift from the code. Edit the inline shapes deliberately;
they are what downstream phases rely on.

- **Work-unit** and **result-record** shapes → `references/work-units.md`. The
  result-record is the merge key for dedup; changing it affects Phase 6
  aggregation and any future distributed runner.
- **`intel_delta.json`** (asset-delta input) and the **prioritization-feed**
  object → `references/intel-contract.md`.
- **`scope.yaml`** → validated at runtime by `scripts/scope_gate.py` (semantic
  checks: sane prefixes, valid and current window, confirmation flag, rate and
  timing ceilings, port spec, and a duration-vs-window estimate), which is
  stronger than a structural schema would be here.

One contract crosses a trust boundary and therefore gets enforced in code, not
just documented: the **asset-delta feed is an untrusted input that selects scan
targets**, so when incremental mode is built it must validate an incoming
`intel_delta.json` against its documented shape *before* any entry reaches the
scope gate. That validation lives as a function in the ingesting script (a
schema file would be redundant with the parsing it must do anyway).

## How to run it (orchestration)

Run from `scripts/` (or pass full paths). `R` is the run directory Phase 1
prints.

```bash
python3 scope_gate.py --scope scope.yaml          # 1. gate; relay plan + warnings
./00_preflight.sh --scope scope.yaml              # 2. capability map
python3 01_passive_enum.py --scope scope.yaml --domain example.com   # 3. validate small
python3 01_passive_enum.py --scope scope.yaml     # 4. full Phase 1 -> prints run dir R
python3 02_lookalike.py   --scope scope.yaml --run-dir "$R"
python3 03_takeover.py    --scope scope.yaml --run-dir "$R"
python3 04_active_scan.py --scope scope.yaml --run-dir "$R" --dry-run   # 5. show plan
python3 04_active_scan.py --scope scope.yaml --run-dir "$R" --only 203.0.113.5  # 6. one host
python3 04_active_scan.py --scope scope.yaml --run-dir "$R"            # 7. full scan
python3 05_posture.py     --scope scope.yaml --run-dir "$R"
python3 06_report.py      --scope scope.yaml --run-dir "$R"            # 8. report
```

1. If the gate fails, stop and report what's missing. Don't improvise scope.
2. Tell the operator which modules will run fully and which degraded.
3. Check that the validate-small run's `phase1/assets.json` looks right before
   fanning out.
4. Show the operator the `--dry-run` plan before the first real scan.
   `--only` then proves the masscan→nmap handover on one host. Re-run Phase 1
   without `--run-dir` to start a new run before the full scan, because
   `--only` leaves the badge at MINIMAL.
5. masscan needs raw sockets: run Phase 4 as root, or
   `sudo setcap cap_net_raw,cap_net_admin=eip $(command -v masscan)`. Without
   root, nmap falls back to a connect scan (`-sT`), and the report notes it.
6. After Phase 6, read `report.md`. Rewrite the auto-generated executive
   summary for the audience, and walk the operator through the badge,
   high findings and intelligence gaps.

When in doubt about whether something is in scope or invasive, stop and ask the
operator. A skipped check is recoverable; an out-of-scope scan is not.