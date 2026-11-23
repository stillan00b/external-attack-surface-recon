#!/usr/bin/env python3
"""
scope_gate.py — Phase 0 authorization gate and reusable in-scope matcher.

Two jobs:
  1. validate()  — refuse to authorize active scanning unless scope.yaml passes
                   every gate condition (confirmed flag, current window, at least
                   one authorized target).
  2. InScope     — a matcher that every later phase uses to decide whether a
                   discovered host/IP/domain may be actively scanned. Discovery
                   proposes; this matcher disposes.

Exit codes (when run as CLI):
  0  gate PASSED — active scanning authorized
     (--check: gate passed AND asset is in scope for active scanning;
      --check --passive: asset is eligible for passive work)
  2  gate FAILED, or --check asset is out of scope
  3  scope file missing or unparseable

Usage:
  python3 scope_gate.py --scope scope.yaml            # validate, human output
  python3 scope_gate.py --scope scope.yaml --json     # validate, JSON output
  python3 scope_gate.py --scope scope.yaml --check 203.0.113.42   # test one asset
  python3 scope_gate.py --scope scope.yaml --check www.example.com --ips 203.0.113.5
  python3 scope_gate.py --scope scope.yaml --check www.example.com --passive
  python3 scope_gate.py --scope scope.yaml --print-targets  > targets.txt   # gate must pass
  python3 scope_gate.py --scope scope.yaml --print-excludes > excludes.txt
  python3 scope_gate.py --scope scope.yaml --print-ports                    # masscan -p value

--check (active) runs the full gate first: if the gate fails, NO asset is
reported in scope, whatever the matcher says.

The module itself performs NO network activity and is safe to import from any
phase. The single exception is the CLI: `--check <hostname>` without `--ips`
resolves the name through the system resolver (a normal DNS lookup).
"""

import argparse
import ipaddress
import json
import re
import socket
import sys
from datetime import datetime, timezone

try:
    import yaml
except ImportError:
    sys.stderr.write(
        "ERROR: PyYAML not installed. Run: pip install pyyaml --break-system-packages\n"
    )
    sys.exit(3)


def _parse_dt(value):
    """
    Parse an ISO-8601 timestamp. Returns (dt, was_naive):
      - (datetime, False) — had an explicit offset (e.g. trailing Z or +00:00)
      - (datetime, True)  — parsed but had NO timezone; assumed UTC, caller warns
      - (None, False)     — unparseable
    A naive timestamp is dangerous: an operator in Mountain Time writing local
    midnight would have the window silently shifted ~6-7h if we assume UTC, so
    the gate surfaces it rather than swallowing it.
    """
    if value is None:
        return None, False
    if isinstance(value, datetime):
        if value.tzinfo:
            return value, False
        return value.replace(tzinfo=timezone.utc), True
    s = str(value).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None, False
    if dt.tzinfo:
        return dt, False
    return dt.replace(tzinfo=timezone.utc), True


# ----- rate / timing / duration governance -----------------------------------
# Hard ceilings the gate enforces on scope.yaml's `rate` block. Going above a
# hard ceiling requires rate.high_rate_approval (a reference to where the client
# approved it, e.g. "RoE §4.2"), which is then echoed into the gate output.
MASSCAN_RATE_DEFAULT = 1000      # pkt/s, aggregate, used when unset
MASSCAN_RATE_WARN = 2000         # above this: warning
MASSCAN_RATE_MAX = 10000         # above this: FAIL unless approved
NMAP_TIMINGS = ("T0", "T1", "T2", "T3", "T4", "T5")
NMAP_TIMING_DEFAULT = "T3"       # T4 warns; T5 FAILS unless approved
MAX_PARALLEL_WORKERS = 16
WINDOW_WARN_DAYS = 90            # longer windows usually mean a typo in a date
SCAN_DURATION_WARN_HOURS = 24
FULL_RANGE_PORTS = 65535

# Curated external-facing TCP set used for the masscan breadth pass when
# scan.ports is unset or "external-default". A full 1-65535 sweep at a polite
# rate takes hours per /24 (256 x 65535 / 1000 pps ~ 4.7h), so full range is
# reserved for scan.full_range_on hosts. Covers remote access / VPN, mail, DNS,
# directory, file sharing, databases, caches, queues, container/orchestration
# APIs, CI and admin consoles, and common alt-HTTP ports.
EXTERNAL_DEFAULT_PORTS = (
    "21,22,23,25,53,80,81,88,102,110,111,135,139,143,179,389,443,444,445,465,"
    "502,587,623,636,873,902,989,990,993,995,1080,1099,1194,1433,1434,1521,"
    "1723,1883,2049,2082,2083,2086,2087,2095,2096,2181,2222,2375,2376,2379,"
    "2380,3000,3128,3268,3269,3306,3389,3443,4443,4786,4848,5000,5001,5060,"
    "5061,5222,5432,5555,5601,5672,5800,5900,5901,5985,5986,6000,6379,6443,"
    "7001,7002,7443,7474,8000,8008,8009,8080,8081,8082,8088,8090,8161,8181,"
    "8443,8500,8834,8880,8883,8888,9000,9001,9042,9090,9092,9100,9200,9300,"
    "9443,9999,10000,10250,10443,11211,15672,27017,50000"
)


def _as_int(value):
    """Strict int coercion for config values: ints or digit strings only."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def parse_port_spec(spec):
    """
    Parse a masscan/nmap-style TCP port spec ("80,443,8000-8100") into a sorted
    list of ports. Raises ValueError on anything malformed or out of range.
    "external-default" expands to EXTERNAL_DEFAULT_PORTS.
    """
    spec = str(spec).strip()
    if spec.lower() == "external-default":
        spec = EXTERNAL_DEFAULT_PORTS
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if part.upper().startswith(("U:", "T:")):
            raise ValueError(f"protocol prefixes are not supported here: '{part}' "
                             "(the masscan breadth pass is TCP)")
        if "-" in part:
            lo, _, hi = part.partition("-")
            lo, hi = _as_int(lo), _as_int(hi)
            if lo is None or hi is None or not (1 <= lo <= hi <= 65535):
                raise ValueError(f"bad port range '{part}'")
            ports.update(range(lo, hi + 1))
        else:
            p = _as_int(part)
            if p is None or not (1 <= p <= 65535):
                raise ValueError(f"bad port '{part}'")
            ports.add(p)
    if not ports:
        raise ValueError("port spec is empty")
    return sorted(ports)


def resolve_ports(scope):
    """Return (name, port_list) for scope.yaml scan.ports (default external set)."""
    raw = (scope.get("scan") or {}).get("ports") or "external-default"
    if isinstance(raw, list):
        raw = ",".join(str(p) for p in raw)
    return str(raw), parse_port_spec(raw)


# Small, high-value external UDP set: DNS, NTP, SNMP, IKE/IPsec NAT-T, OpenVPN,
# WireGuard. VPN and SNMP exposure are among the most useful external findings.
# Probed with nmap's built-in protocol payloads only — no version probes, no
# SNMP community guessing.
UDP_DEFAULT_PORTS = "53,123,161,500,1194,4500,51820"
UDP_RETRIES = 1   # nmap --max-retries for the UDP pass -> up to 2 probes per port


def resolve_udp(scope):
    """Return (enabled, port_list) from scan.udp / scan.udp_ports."""
    scan = scope.get("scan") or {}
    enabled = scan.get("udp", True) is not False
    raw = scan.get("udp_ports") or UDP_DEFAULT_PORTS
    if isinstance(raw, list):
        raw = ",".join(str(p) for p in raw)
    return enabled, parse_port_spec(raw)


def compress_ports(ports):
    """[80,81,82,443] -> '80-82,443' for a compact -p argument."""
    out, i = [], 0
    while i < len(ports):
        j = i
        while j + 1 < len(ports) and ports[j + 1] == ports[j] + 1:
            j += 1
        out.append(str(ports[i]) if i == j else f"{ports[i]}-{ports[j]}")
        i = j + 1
    return ",".join(out)


def count_target_ips(matcher):
    """
    Number of IPs the masscan pass would cover: in_scope IPv4 cidrs
    (deduplicated) minus out_of_scope cidrs/hosts. CIDRs either nest or are
    disjoint, so after collapsing, each overlap is exactly the smaller block.

    IPv6 is deliberately NOT counted: the masscan sweep is IPv4-only (a /64 is
    2^64 addresses and can't be swept). IPv6 cidrs still authorize IPv6 hosts
    found via AAAA records, which are checked one at a time with --check.
    """
    total = 0
    for version in (4,):
        ins = list(ipaddress.collapse_addresses(
            n for n in matcher.in_nets if n.version == version))
        outs = list(ipaddress.collapse_addresses(
            [n for n in matcher.out_nets if n.version == version] +
            [ipaddress.ip_network(h) for h in matcher.out_hosts if h.version == version]))
        for n in ins:
            excluded = 0
            for o in outs:
                if o.subnet_of(n):
                    excluded += o.num_addresses
                elif n.subnet_of(o):
                    excluded += n.num_addresses
            total += max(n.num_addresses - excluded, 0)
    return total


def _fmt_duration(seconds):
    seconds = int(seconds)
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m, _ = divmod(rem, 60)
    if d:
        return f"{d}d {h}h {m}m"
    if h:
        return f"{h}h {m}m"
    return f"{m}m" if m else f"{seconds}s"


class InScope:
    """
    Reusable matcher. Build once from scope.yaml, then ask is_in_scope(asset)
    for every discovered IP, CIDR, or hostname before scanning it.

    Precedence: an out_of_scope match ALWAYS wins, even if the asset also
    matches in_scope. Exclusions are deliberately stronger than inclusions.
    """

    # Reject in_scope prefixes broader than this — a fat-fingered prefix length
    # (e.g. 0.0.0.0/0 or a /1) would authorize scanning a huge swath of the
    # internet. /16 = 65,536 addresses is already a large external engagement;
    # anything broader is almost certainly a mistake and must be made explicit.
    MIN_SAFE_PREFIX_V4 = 16
    MIN_SAFE_PREFIX_V6 = 64

    def __init__(self, scope: dict):
        s_in = (scope.get("in_scope") or {})
        s_out = (scope.get("out_of_scope") or {})

        # Warnings about silently-unusable scope entries. Callers (the gate)
        # surface these so an exclusion or target can never just vanish.
        self.warnings = []

        # Domains. A plain entry ("example.com") covers the apex AND every
        # subdomain. A wildcard ("*.example.com") is read the way an RoE means
        # it: subdomains only, apex NOT included. For exclusions a wildcard is
        # widened to apex + subdomains, because a broader exclusion is the safe
        # direction. Anything that isn't a plain domain (URLs, paths, ports,
        # wildcards mid-name, spaces) is rejected with a warning, not guessed at.
        self.in_domains, self.in_subs_only = set(), set()
        # An explicit apex entry overrides a wildcard for the same domain.
        explicit = {self._domain(r, None)[0] for r in (s_in.get("domains") or [])
                    if not str(r).strip().startswith("*.")}
        for raw in (s_in.get("domains") or []):
            d, wild = self._domain(raw, "in_scope.domains")
            if d:
                self.in_domains.add(d)
                if wild and d not in explicit:
                    self.in_subs_only.add(d)
                    self.warnings.append(
                        f"in_scope.domains: '{raw}' covers subdomains of {d} only, "
                        f"not {d} itself. Add '{d}' as well if the apex is in scope.")
        self.out_domains = set()
        for raw in (s_out.get("domains") or []):
            d, _ = self._domain(raw, "out_of_scope.domains")
            if d:
                self.out_domains.add(d)

        self.in_nets = self._nets(s_in.get("cidrs"), "in_scope.cidrs")
        self.out_nets = self._nets(s_out.get("cidrs"), "out_of_scope.cidrs")

        # out_of_scope.hosts may be single IPs (treated as /32 or /128) OR
        # hostnames. Hostnames that don't parse as IPs are kept as domain-style
        # exclusions rather than silently dropped.
        self.out_hosts = set()
        for h in (s_out.get("hosts") or []):
            val = str(h).strip()
            try:
                self.out_hosts.add(ipaddress.ip_address(val))
            except ValueError:
                # Not an IP — a hostname exclusion (also excludes its subdomains).
                d, _ = self._domain(val, "out_of_scope.hosts")
                if d:
                    self.out_domains.add(d)

        # ASNs: accept "AS64500", "as64500", "ASN64500" or 64500.
        self.in_asns = set()
        for a in (s_in.get("asns") or []):
            m = re.fullmatch(r"(?i)\s*(?:asn?)?\s*(\d{1,10})\s*", str(a))
            if m and 0 < int(m.group(1)) < 2 ** 32:
                self.in_asns.add(m.group(1))
            else:
                self.warnings.append(f"in_scope.asns: '{a}' is not a valid ASN — ignored")
        # An ASN is NEVER IP scope by itself: "announced by the client's ASN" is
        # not "authorized". Phase 1 reports the announced prefixes; the operator
        # confirms them with the client and adds the approved ones to
        # in_scope.cidrs. An ASN-only scope therefore authorizes no IPs, and the
        # gate says so.
        self.asn_only = bool(self.in_asns) and not self.in_nets

    _DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+"
                            r"(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$")

    def _domain(self, raw, label):
        """Normalize one scope domain entry. Returns (domain, was_wildcard), or
        (None, False) after recording a warning (label=None: no warning)."""
        s = str(raw).strip().lower().rstrip(".")
        wild = s.startswith("*.")
        if wild:
            s = s[2:]
        elif s.startswith("."):
            s = s.lstrip(".")
        try:
            s = s.encode("idna").decode("ascii") if any(ord(c) > 127 for c in s) else s
        except UnicodeError:
            pass
        if not self._DOMAIN_RE.match(s):
            if label:
                hint = " (give a bare domain, not a URL)" if "/" in s or ":" in s else ""
                self.warnings.append(f"{label}: '{raw}' is not a valid domain{hint} — ignored")
            return None, False
        return s, wild

    def _nets(self, values, label):
        nets = []
        for c in (values or []):
            raw = str(c).strip()
            try:
                net = ipaddress.ip_network(raw, strict=False)
            except ValueError:
                self.warnings.append(f"{label}: '{raw}' is not a valid CIDR — ignored")
                continue
            # Broad-range guard applies only to INCLUSIONS. Exclusions are
            # allowed to be broad (a wide exclusion is conservative/safe).
            if label.startswith("in_scope"):
                floor = self.MIN_SAFE_PREFIX_V4 if net.version == 4 else self.MIN_SAFE_PREFIX_V6
                if net.prefixlen < floor:
                    self.warnings.append(
                        f"{label}: '{raw}' is broader than /{floor} "
                        f"({net.num_addresses:,} addresses) — REJECTED as a likely "
                        f"mistake. Narrow the range or split it into explicit blocks."
                    )
                    continue
            nets.append(net)
        return nets

    def classify_announced(self, prefixes):
        """
        Sort ASN-announced prefixes into 'authorized' (inside an in_scope cidr)
        and 'announced-not-authorized'. This never changes scope: announced is
        not authorized, so unapproved prefixes stay unscannable until the
        operator adds them to in_scope.cidrs after client confirmation.
        Returns [{"prefix", "status"}].
        """
        out = []
        for p in prefixes or []:
            try:
                net = ipaddress.ip_network(str(p).strip(), strict=False)
            except ValueError:
                continue
            covered = any(net.version == n.version and net.subnet_of(n) for n in self.in_nets)
            out.append({"prefix": str(net),
                        "status": "authorized" if covered else "announced-not-authorized"})
        return out

    def _ip_excluded(self, ip):
        if ip in self.out_hosts:
            return True
        return any(ip in n for n in self.out_nets)

    def _ip_included(self, ip):
        return any(ip in n for n in self.in_nets)

    def _domain_excluded(self, host):
        return any(host == d or host.endswith("." + d) for d in self.out_domains)

    def _domain_included(self, host):
        return any((host == d and d not in self.in_subs_only) or host.endswith("." + d)
                   for d in self.in_domains)

    def is_in_scope(self, asset: str, resolved_ips=None, active: bool = True):
        """
        Return (bool, reason). Accepts an IP, a CIDR, or a hostname.

        active=True (the default — fail closed): True only if the asset may be
        ACTIVELY scanned. For a hostname this means the name is under an
        in_scope domain AND every IP it resolves to is inside an authorized
        cidr and not excluded. A subdomain that points at third-party
        infrastructure (SaaS, CDN, cloud) is therefore NOT scannable, even
        though the name belongs to the client. The caller must pass the
        hostname's resolved IPs in `resolved_ips`; without them a hostname is
        refused for active use, because domain ownership alone says nothing
        about who owns the box behind it.

        active=False: passive eligibility only (OSINT, CT, report context).
        A hostname passes on domain match alone; resolved_ips is ignored.
        IPs and CIDRs are judged the same way in both modes.
        """
        asset = asset.strip()

        # IP address
        try:
            ip = ipaddress.ip_address(asset)
            if self._ip_excluded(ip):
                return False, "matches out_of_scope"
            if self._ip_included(ip):
                return True, "matches in_scope cidr"
            return False, "not within any authorized cidr"
        except ValueError:
            pass

        # CIDR — in scope only if fully contained in an authorized net and not
        # overlapping any exclusion.
        try:
            net = ipaddress.ip_network(asset, strict=False)
            if any(net.overlaps(o) for o in self.out_nets):
                return False, "overlaps out_of_scope cidr"
            if any(int(net.network_address) >= int(n.network_address)
                   and int(net.broadcast_address) <= int(n.broadcast_address)
                   for n in self.in_nets):
                return True, "contained in in_scope cidr"
            return False, "not contained in any authorized cidr"
        except ValueError:
            pass

        # Hostname
        host = asset.lower().rstrip(".")
        if self._domain_excluded(host):
            return False, "matches out_of_scope domain"
        if not self._domain_included(host):
            return False, "not within any authorized domain"
        if not active:
            return True, "matches in_scope domain (passive eligibility only)"

        # Active use: the name must also land entirely on authorized IP space.
        if resolved_ips is None:
            return False, ("hostname matches in_scope domain, but active scanning "
                           "requires its resolved IPs to be checked against "
                           "authorized cidrs (none supplied)")
        ips = []
        for raw in resolved_ips:
            try:
                ips.append(ipaddress.ip_address(str(raw).strip()))
            except ValueError:
                return False, f"resolved address '{raw}' is not a valid IP"
        if not ips:
            return False, "hostname did not resolve to any IP"
        excluded = [str(ip) for ip in ips if self._ip_excluded(ip)]
        if excluded:
            return False, f"resolves to out_of_scope IP(s): {', '.join(excluded)}"
        outside = [str(ip) for ip in ips if not self._ip_included(ip)]
        if outside:
            return False, ("matches in_scope domain but resolves to IP(s) outside "
                           f"authorized cidrs (third-party?): {', '.join(outside)}")
        return True, "matches in_scope domain and all resolved IPs are in authorized cidrs"


def validate(scope_path: str):
    """
    Return (passed: bool, report: dict). report['reasons'] lists every failed
    condition; report['warnings'] lists non-fatal concerns; report['status'] is
    one of 'ok', 'failed', or 'file_error' so callers don't string-match.
    """
    report = {"scope_path": scope_path, "checks": [], "reasons": [],
              "warnings": [], "engagement": None, "passed": False,
              "status": "failed", "scan_plan": None}

    try:
        with open(scope_path, "r", encoding="utf-8") as f:
            scope = yaml.safe_load(f)
    except FileNotFoundError:
        report["reasons"].append(f"scope file not found: {scope_path}")
        report["status"] = "file_error"
        return False, report
    except yaml.YAMLError as e:
        report["reasons"].append(f"scope file does not parse: {e}")
        report["status"] = "file_error"
        return False, report

    if not isinstance(scope, dict):
        report["reasons"].append("scope file is empty or malformed")
        report["status"] = "file_error"
        return False, report

    eng = scope.get("engagement") or {}
    report["engagement"] = {"id": eng.get("id"), "client": eng.get("client")}

    def check(name, ok, why):
        report["checks"].append({"name": name, "ok": bool(ok)})
        if not ok:
            report["reasons"].append(why)
        return ok

    # Build the matcher early so its parse warnings (bad CIDRs, broad ranges,
    # dropped exclusions) surface here rather than silently downstream.
    matcher = InScope(scope)
    report["warnings"].extend(matcher.warnings)

    # 1. confirmation flag
    auth = scope.get("authorization") or {}
    check("authorization.confirmed is true",
          auth.get("confirmed") is True,
          "authorization.confirmed must be set to true by the operator")

    # 2. at least one authorized target listed
    s_in = scope.get("in_scope") or {}
    has_target = any(s_in.get(k) for k in ("domains", "cidrs", "asns"))
    check("at least one in_scope target",
          has_target,
          "in_scope must list at least one domain, cidr, or asn")

    # 2b. IP scanning needs at least one usable CIDR. An ASN-only scope can't
    #     match any IP until Phase 1 expands it, so flag the half-state: the
    #     gate may pass for passive/domain work but active IP scanning will
    #     match nothing until expansion runs.
    if matcher.asn_only:
        report["warnings"].append(
            "in_scope lists ASN(s) but no cidrs, so NO IP is authorized. An ASN "
            "is never scope by itself: Phase 1 reports its announced prefixes; "
            "confirm them with the client and add the approved ones to "
            "in_scope.cidrs. Active IP scanning is a no-op until then."
        )
    if has_target and not matcher.in_nets and not matcher.in_domains:
        if matcher.asn_only:
            # Nothing was rejected; ASNs simply aren't IP scope.
            check("at least one domain or cidr authorized", False,
                  "in_scope has only ASNs, which authorize nothing by themselves. "
                  "Run Phase 1 (passive) to list the announced prefixes, confirm them "
                  "with the client, then add the approved ones to in_scope.cidrs")
        else:
            # Every listed target was rejected (e.g. all CIDRs too broad / invalid).
            check("at least one USABLE in_scope target after validation",
                  False,
                  "all in_scope targets were rejected (see warnings) — nothing is "
                  "actually authorized to scan")

    # 3. engagement window is current
    now = datetime.now(timezone.utc)
    win = eng.get("window") or {}
    start, start_naive = _parse_dt(win.get("start"))
    end, end_naive = _parse_dt(win.get("end"))
    if start is None or end is None:
        check("engagement window parseable", False,
              "engagement.window.start/end must be valid ISO-8601 timestamps")
    else:
        if start_naive or end_naive:
            report["warnings"].append(
                "engagement.window has a timestamp with no timezone offset; "
                "assumed UTC. If you meant local time, add an offset (e.g. "
                "'-06:00' or 'Z') so the window isn't silently shifted."
            )
        if check("window start is before end", start < end,
                 f"engagement.window.start ({start.isoformat()}) must be before "
                 f"end ({end.isoformat()})"):
            if (end - start).days > WINDOW_WARN_DAYS:
                report["warnings"].append(
                    f"engagement window spans {(end - start).days} days — longer than "
                    f"{WINDOW_WARN_DAYS}; check the dates for a typo (e.g. wrong year)."
                )
        check("now within engagement window",
              start <= now <= end,
              f"current time {now.isoformat()} is outside the engagement window "
              f"({start.isoformat()} .. {end.isoformat()})")

    # 3b. rate / timing ceilings — the loudest knobs must be bounded here, not
    #     left to whatever value happens to be in the file.
    rate = scope.get("rate") or {}
    approval = str(rate.get("high_rate_approval") or "").strip()

    raw = rate.get("masscan_max_rate")
    if raw is None:
        mrate = MASSCAN_RATE_DEFAULT
        report["warnings"].append(
            f"rate.masscan_max_rate not set — using default {MASSCAN_RATE_DEFAULT} pkt/s.")
    else:
        mrate = _as_int(raw)
    if check("masscan rate is a positive integer",
             mrate is not None and mrate > 0,
             f"rate.masscan_max_rate must be a positive integer (got {raw!r})"):
        if mrate > MASSCAN_RATE_MAX:
            if check(f"masscan rate <= {MASSCAN_RATE_MAX} or approved", bool(approval),
                     f"rate.masscan_max_rate={mrate} exceeds the {MASSCAN_RATE_MAX} pkt/s "
                     f"hard ceiling; lower it, or set rate.high_rate_approval to the "
                     f"client approval reference"):
                report["warnings"].append(
                    f"masscan rate {mrate} pkt/s above hard ceiling — approved: {approval}")
        elif mrate > MASSCAN_RATE_WARN:
            report["warnings"].append(
                f"rate.masscan_max_rate={mrate} pkt/s is high for external work "
                f"(default {MASSCAN_RATE_DEFAULT}); expect target/provider defenses to notice.")

    raw_t = rate.get("nmap_timing")
    timing = str(raw_t if raw_t is not None else NMAP_TIMING_DEFAULT).strip().upper().lstrip("-")
    if timing.isdigit():
        timing = "T" + timing
    if check("nmap timing is T0..T5", timing in NMAP_TIMINGS,
             f"rate.nmap_timing must be one of T0..T5 (got {raw_t!r})"):
        if timing == "T5":
            if check("nmap T5 approved", bool(approval),
                     "rate.nmap_timing=T5 is forbidden against production edge unless "
                     "rate.high_rate_approval records the client approval"):
                report["warnings"].append(f"nmap timing T5 — approved: {approval}")
        elif timing == "T4":
            report["warnings"].append("rate.nmap_timing=T4 is noisier than the T3 default.")

    raw_w = rate.get("parallel_workers")
    workers = 1 if raw_w is None else _as_int(raw_w)
    check(f"parallel workers 1..{MAX_PARALLEL_WORKERS}",
          workers is not None and 1 <= workers <= MAX_PARALLEL_WORKERS,
          f"rate.parallel_workers must be an integer 1..{MAX_PARALLEL_WORKERS} (got {raw_w!r})")

    raw_mr = rate.get("nmap_min_rate")
    if raw_mr is not None:
        min_rate = _as_int(raw_mr)
        if check("nmap min rate is a positive integer",
                 min_rate is not None and min_rate > 0,
                 f"rate.nmap_min_rate must be null or a positive integer (got {raw_mr!r})") \
                and mrate and workers:
            check("nmap aggregate floor within global ceiling",
                  min_rate * workers <= mrate,
                  f"rate.nmap_min_rate ({min_rate}) x parallel_workers ({workers}) = "
                  f"{min_rate * workers} pkt/s exceeds the global ceiling of {mrate}; "
                  f"per-worker rates must SUM under the ceiling")

    # 3c. scan plan + duration estimate — refuse a masscan pass that cannot
    #     finish inside the authorized window at the configured rate.
    try:
        ports_name, ports = resolve_ports(scope)
        ports_ok = True
    except ValueError as e:
        ports_ok = check("scan.ports parses", False, f"scan.ports is invalid: {e}")
    try:
        udp_on, udp_ports = resolve_udp(scope)
    except ValueError as e:
        ports_ok = check("scan.udp_ports parses", False, f"scan.udp_ports is invalid: {e}") and ports_ok
        udp_on, udp_ports = False, []
    if ports_ok and mrate and mrate > 0:
        ip_count = count_target_ips(matcher)
        full_hosts = len((scope.get("scan") or {}).get("full_range_on") or [])
        tcp_packets = ip_count * len(ports) + full_hosts * (FULL_RANGE_PORTS - len(ports))
        udp_packets = ip_count * len(udp_ports) * (UDP_RETRIES + 1) if udp_on else 0
        packets = tcp_packets + udp_packets
        est = packets / mrate
        report["scan_plan"] = {
            "target_ips": ip_count,
            "ports": ports_name if ports_name == "external-default" else compress_ports(ports),
            "port_count": len(ports),
            "full_range_hosts": full_hosts,
            "udp_ports": compress_ports(udp_ports) if udp_on else None,
            "udp_packets": udp_packets,
            "masscan_rate": mrate,
            "packets": packets,
            "est_seconds": int(est),
            "est_human": _fmt_duration(est),
            "scope_note": ", ".join(
                ["IPv4 cidrs only"]
                + (["IPv6 not swept"] if any(n.version == 6 for n in matcher.in_nets) else [])
                + (["ASNs are not scope; only listed cidrs are swept"] if matcher.in_asns else [])),
        }
        if est > SCAN_DURATION_WARN_HOURS * 3600:
            report["warnings"].append(
                f"estimated masscan duration {_fmt_duration(est)} "
                f"({ip_count:,} IPs x {len(ports):,} ports @ {mrate} pkt/s) — consider "
                f"fewer ports or splitting the run.")
        if start and end and end > now:
            remaining = (end - max(now, start)).total_seconds()
            check("masscan pass fits in remaining window", est <= remaining,
                  f"estimated masscan duration {_fmt_duration(est)} exceeds the "
                  f"{_fmt_duration(remaining)} left in the engagement window; narrow "
                  f"scan.ports, reduce scan.full_range_on, or split scope across runs")

    # 4. safety rails must remain off
    scan = scope.get("scan") or {}
    check("vuln scripts disabled",
          not scan.get("allow_vuln_scripts", False),
          "scan.allow_vuln_scripts must be false — this skill runs no vuln NSE")
    check("intrusive NSE disabled",
          not scan.get("allow_intrusive_nse", False),
          "scan.allow_intrusive_nse must be false — this skill runs no intrusive NSE")

    # 5. cloud-provider notification reminder (warn, do not fail)
    if not auth.get("cloud_provider_notified", False):
        report["warnings"].append(
            "If scanning from cloud infra, confirm the provider abuse team was "
            "notified; set authorization.cloud_provider_notified."
        )

    # 6. emergency contacts — who to call if the scan causes impact. Most RoEs
    #    require them; the report header and abort procedure print them.
    contacts = eng.get("emergency_contacts") or []
    report["emergency_contacts"] = contacts
    if not contacts:
        report["warnings"].append(
            "engagement.emergency_contacts is empty — record who to call (client and "
            "your side) if scanning causes impact. See SKILL.md 'Abort procedure'.")

    report["passed"] = len(report["reasons"]) == 0
    report["status"] = "ok" if report["passed"] else "failed"
    return report["passed"], report


def _print_human(report):
    eng = report.get("engagement") or {}
    print("=" * 64)
    print(" Phase 0 — Authorization Gate")
    print("=" * 64)
    if eng.get("id"):
        print(f" Engagement: {eng.get('id')}  ({eng.get('client')})")
    for c in report["checks"]:
        mark = "PASS" if c["ok"] else "FAIL"
        line = f"  [{mark}] {c['name']}"
        if c.get("note"):
            line += f"\n         note: {c['note']}"
        print(line)
    plan = report.get("scan_plan")
    if plan:
        print("-" * 64)
        print(" Masscan plan (estimate):")
        print(f"   targets : {plan['target_ips']:,} IPs ({plan['scope_note']})")
        print(f"   ports   : {plan['port_count']:,} ({plan['ports'] if len(plan['ports']) < 40 else plan['ports'][:37] + '...'})"
              + (f" + full range on {plan['full_range_hosts']} host(s)" if plan['full_range_hosts'] else ""))
        print(f"   udp     : {plan['udp_ports'] or 'off (scan.udp: false)'}")
        print(f"   rate    : {plan['masscan_rate']:,} pkt/s  ->  ~{plan['est_human']} "
              f"({plan['packets']:,} packets"
              + (f", incl. {plan['udp_packets']:,} UDP — a lower bound, targets rate-limit ICMP"
                 if plan['udp_packets'] else "") + ")")
    for c in report.get("emergency_contacts") or []:
        print(f" Emergency contact: {c}")
    if report.get("warnings"):
        print("-" * 64)
        print(" Warnings (non-fatal — review these):")
        for w in report["warnings"]:
            print(f"   ! {w}")
    print("-" * 64)
    if report["passed"]:
        print(" RESULT: GATE PASSED — active scanning authorized.")
    else:
        print(" RESULT: GATE FAILED — do NOT run host-touching phases.")
        print(" Fix the following before proceeding:")
        for r in report["reasons"]:
            print(f"   - {r}")
    print("=" * 64)


def excludes_for_scanner(matcher):
    """
    Newline-separated exclude list for masscan/nmap --excludefile: every
    out_of_scope cidr and IP host, collapsed. Always includes 255.255.255.255
    (masscan's own recommended baseline) so the file is never empty.
    """
    nets = list(matcher.out_nets) + [ipaddress.ip_network(h) for h in matcher.out_hosts]
    nets.append(ipaddress.ip_network("255.255.255.255/32"))
    lines = []
    for version in (4, 6):
        lines += [str(n) for n in sorted(ipaddress.collapse_addresses(
            n for n in nets if n.version == version))]
    return "\n".join(lines)


def _is_ip_or_cidr(asset):
    try:
        ipaddress.ip_network(asset.strip(), strict=False)
        return True
    except ValueError:
        return False


def resolve_host(host):
    """Resolve a hostname to its A/AAAA addresses via the system resolver.
    Returns a sorted list of IP strings (empty if it does not resolve)."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return []
    return sorted({info[4][0] for info in infos})


def _check_cli(args):
    """
    --check handler. Always exits.

    Active mode (default) runs the full gate FIRST: if the gate fails, the asset
    is reported as not authorized regardless of the matcher, so a script keyed
    off exit 0 can never scan under an unconfirmed / expired / empty scope.
    Passive mode (--passive) skips the gate requirement, matching SKILL.md's
    "passive OSINT may run on seeds before confirmation", and says so.
    """
    asset = args.check.strip()
    out = {"asset": asset, "mode": "passive" if args.passive else "active",
           "in_scope": False, "reason": None, "gate": None,
           "resolved_ips": None, "warnings": []}

    def finish(ok, why, code=None):
        out["in_scope"] = bool(ok)
        out["reason"] = why
        if args.json:
            print(json.dumps(out, indent=2))
        else:
            verdict = "IN-SCOPE" if ok else "OUT-OF-SCOPE"
            if args.passive and ok:
                verdict = "PASSIVE-ELIGIBLE"
            print(f"{verdict}: {asset}  ({why})")
            if out["resolved_ips"] is not None:
                print(f"  resolved: {', '.join(out['resolved_ips']) or '(none)'}")
            for w in out["warnings"]:
                sys.stderr.write(f"  ! {w}\n")
        sys.exit(code if code is not None else (0 if ok else 2))

    passed, report = validate(args.scope)
    out["gate"] = report["status"]
    out["warnings"].extend(report.get("warnings", []))
    if report["status"] == "file_error":
        finish(False, "; ".join(report["reasons"]), code=3)
    if not args.passive and not passed:
        finish(False, "authorization gate FAILED — nothing is in scope for active "
                      "scanning: " + "; ".join(report["reasons"]))

    with open(args.scope, "r", encoding="utf-8") as f:
        scope = yaml.safe_load(f)
    matcher = InScope(scope)

    resolved = None
    if not args.passive and not _is_ip_or_cidr(asset):
        if args.ips:
            resolved = [p.strip() for p in args.ips.split(",") if p.strip()]
        else:
            resolved = resolve_host(asset.rstrip("."))
        out["resolved_ips"] = resolved

    ok, why = matcher.is_in_scope(asset, resolved_ips=resolved,
                                  active=not args.passive)
    finish(ok, why)


def main():
    ap = argparse.ArgumentParser(description="Phase 0 authorization gate / scope matcher")
    ap.add_argument("--scope", required=True, help="path to scope.yaml")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of text")
    ap.add_argument("--check", metavar="ASSET",
                    help="test whether one IP/CIDR/hostname is in scope, then exit")
    ap.add_argument("--ips", metavar="IP[,IP...]",
                    help="with --check on a hostname: its resolved IPs. If omitted, "
                         "the hostname is resolved via the system resolver")
    ap.add_argument("--passive", action="store_true",
                    help="with --check: passive eligibility only (domain match; "
                         "does not require the gate to pass)")
    ap.add_argument("--print-ports", action="store_true",
                    help="print the masscan -p argument resolved from scan.ports, then exit")
    ap.add_argument("--print-targets", action="store_true",
                    help="print validated in_scope cidrs (one per line) for masscan -iL; "
                         "refuses (exit 2) unless the gate passes")
    ap.add_argument("--print-excludes", action="store_true",
                    help="print out_of_scope cidrs/IPs (one per line) for masscan/nmap "
                         "--excludefile")
    args = ap.parse_args()

    if args.print_targets:
        # The active target list is only ever produced by a passing gate.
        passed, report = validate(args.scope)
        if not passed:
            sys.stderr.write("REFUSED: authorization gate did not pass; no targets emitted.\n")
            for r in report["reasons"]:
                sys.stderr.write(f"  - {r}\n")
            sys.exit(3 if report["status"] == "file_error" else 2)
        with open(args.scope, "r", encoding="utf-8") as f:
            matcher = InScope(yaml.safe_load(f))
        for net in sorted(ipaddress.collapse_addresses(n for n in matcher.in_nets if n.version == 4)):
            print(net)
        v6 = [str(n) for n in matcher.in_nets if n.version == 6]
        if v6:
            # Never hand masscan an IPv6 block: a /64 is 2^64 addresses.
            sys.stderr.write(
                "note: IPv6 cidrs are not emitted for the masscan sweep (" + ", ".join(v6) +
                "). Scan IPv6 hosts found via AAAA records individually after --check.\n")
        sys.exit(0)

    if args.print_excludes:
        # Second line of defense: the scanner itself drops these even if a bad
        # target list slips through. Emitted without a gate pass, because an
        # exclusion list can only ever reduce what gets scanned.
        try:
            with open(args.scope, "r", encoding="utf-8") as f:
                matcher = InScope(yaml.safe_load(f) or {})
        except (FileNotFoundError, yaml.YAMLError) as e:
            sys.stderr.write(f"ERROR: {e}\n")
            sys.exit(3)
        print(excludes_for_scanner(matcher))
        host_excl = sorted(d for d in matcher.out_domains)
        if host_excl:
            sys.stderr.write(
                "note: hostname/domain exclusions cannot go in an IP exclude file and are "
                "enforced by the matcher (--check) instead: " + ", ".join(host_excl) + "\n")
        sys.exit(0)

    if args.print_ports:
        # Scan scripts take their port list from here so the ports scanned are
        # exactly the ones the gate's duration estimate was computed for.
        try:
            with open(args.scope, "r", encoding="utf-8") as f:
                _, ports = resolve_ports(yaml.safe_load(f) or {})
        except (FileNotFoundError, yaml.YAMLError, ValueError) as e:
            sys.stderr.write(f"ERROR: {e}\n")
            sys.exit(3)
        print(compress_ports(ports))
        sys.exit(0)

    if args.check:
        _check_cli(args)  # always exits

    passed, report = validate(args.scope)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        _print_human(report)

    # Exit codes keyed off explicit status, not string matching:
    #   0 = pass, 2 = gate failed, 3 = scope file missing/unparseable.
    if report["status"] == "file_error":
        sys.exit(3)
    sys.exit(0 if passed else 2)


if __name__ == "__main__":
    main()
