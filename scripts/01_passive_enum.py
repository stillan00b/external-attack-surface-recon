#!/usr/bin/env python3
"""
01_passive_enum.py — Phase 1: asset discovery.

Two tiers, kept separate because their authorization differs:

  PASSIVE (runs before scope confirmation, on seeds + in_scope domains)
    crt.sh CT search, subfinder, amass -passive, assetfinder, Shodan DNS (if
    keyed), WHOIS, DNS record pulls and hostname resolution through the normal
    recursive resolver, RIPEstat ASN -> announced prefixes (third-party data).

  LIGHT-ACTIVE (only if the Phase 0 gate passes; --no-light-active to skip)
    AXFR attempts against the in_scope domains' own nameservers, and a PTR
    sweep of in_scope IPv4 cidrs. Both send queries to the client's
    infrastructure, so they are not passive and must not run pre-confirmation.

Announced ASN prefixes are reported, never added to scope: announced is not
authorized. Prefixes outside in_scope.cidrs are flagged for the operator to
confirm with the client.

Output: <run>/phase1/assets.json, dns.json, whois.json, asn_prefixes.json

Usage:
  python3 01_passive_enum.py --scope scope.yaml                 # new run dir
  python3 01_passive_enum.py --scope scope.yaml --domain example.com   # validate small
  python3 01_passive_enum.py --scope scope.yaml --run-dir runs/ENG_...  # re-run into a run
"""

import ipaddress
import os
import re
import socket
from concurrent.futures import ThreadPoolExecutor

import common as C

HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def norm(name):
    return name.strip().lower().rstrip(".").lstrip("*.").strip()


def under(name, domain):
    return name == domain or name.endswith("." + domain)


class Collector:
    def __init__(self, domains):
        self.domains = domains
        self.hosts = {}

    def add(self, name, source):
        name = norm(name)
        if not HOST_RE.match(name):
            return False
        if not any(under(name, d) for d in self.domains):
            return False
        rec = self.hosts.setdefault(name, {"sources": [], "first_seen": C.iso()})
        if source not in rec["sources"]:
            rec["sources"].append(source)
        return True

    def add_text(self, text, source, domain):
        pat = re.compile(r"[a-z0-9_.*-]+\." + re.escape(domain), re.I)
        n = 0
        for m in pat.findall(text or ""):
            n += self.add(m, source)
        return n


# ----- passive sources -------------------------------------------------------
# Each source returns an int (names added) on success, or a str (why it
# produced nothing) so the status ledger and report carry the real reason.
def src_crtsh(ctx, col, domain):
    ctx.api_pace()
    ctx.audit_note(f"crt.sh CT query for %.{domain}")
    data = C.http_get_json(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=90, retries=1)
    if data is None:
        return "crt.sh unavailable or timed out (common for large domains; retry later)"
    n = 0
    for row in data:
        for name in str(row.get("name_value", "")).splitlines():
            n += col.add(name, "crt.sh")
    return n


def src_tool(ctx, col, domain, tool, argv, timeout):
    if not C.have(tool):
        return "not installed"
    rc, out = ctx.run(argv, name=f"{tool}_{domain}", timeout=timeout)
    n = col.add_text(out, tool, domain)
    if ctx.last_timed_out:
        return n if n else f"timed out after {timeout}s with no output"
    if rc not in (0, None) and not n:
        return f"exit {rc} — see raw/p1_{tool}_{domain}.err"
    return n


def src_shodan(ctx, col, domain):
    key = os.environ.get("SHODAN_API_KEY")
    if not key:
        return "SHODAN_API_KEY unset"
    ctx.api_pace()
    ctx.audit_note(f"Shodan DNS API query for {domain}")  # key deliberately not logged
    data = C.http_get_json(f"https://api.shodan.io/dns/domain/{domain}?key={key}", timeout=60)
    if not data:
        return "Shodan API error or plan without DNS access"
    n = 0
    for sub in data.get("subdomains", []) or []:
        n += col.add(f"{sub}.{domain}" if sub else domain, "shodan")
    return n


def whois_info(ctx, domain):
    if not C.have("whois"):
        return None
    rc, out = ctx.run(["whois", domain], name=f"whois_{domain}", timeout=60)
    info = {"registrar": None, "created": None, "registrant_org": None, "name_servers": []}
    for line in out.splitlines():
        k, _, v = line.partition(":")
        k, v = k.strip().lower(), v.strip()
        if not v:
            continue
        if k in ("registrar",) and not info["registrar"]:
            info["registrar"] = v
        elif k in ("creation date", "created", "registered on") and not info["created"]:
            info["created"] = v
        elif k in ("registrant organization", "registrant org", "org") and not info["registrant_org"]:
            info["registrant_org"] = v
        elif k in ("name server", "nserver") and v.lower() not in info["name_servers"]:
            info["name_servers"].append(v.lower().rstrip("."))
    return info


def dns_records(domain):
    return {t: C.records(domain, t) for t in ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA")}


def asn_prefixes(ctx, asn):
    ctx.api_pace()
    ctx.audit_note(f"RIPEstat announced-prefixes for AS{asn}")
    data = C.http_get_json(
        f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}", timeout=60)
    if not data:
        return None
    raw = [p.get("prefix") for p in (data.get("data") or {}).get("prefixes", []) or []
           if isinstance(p, dict) and p.get("prefix")]
    # Classified by the matcher, never added to scope (announced != authorized).
    return [dict(r, asn=f"AS{asn}") for r in ctx.matcher.classify_announced(raw)]


# ----- light-active ----------------------------------------------------------
def try_axfr(ctx, col, domain):
    results = []
    for ns in C.records(domain, "NS"):
        ns = ns.rstrip(".")
        rc, out = ctx.run(["dig", "AXFR", domain, "@" + ns, "+time=5", "+tries=1"],
                          name=f"axfr_{domain}_{ns}", timeout=60)
        ok = "XFR size" in out and "Transfer failed" not in out
        added = col.add_text(out, "axfr", domain) if ok else 0
        results.append({"ns": ns, "transfer_allowed": ok, "names_added": added})
    return results


def ptr_sweep(ctx, col, max_ips):
    ips = []
    for net in ctx.matcher.in_nets:
        if net.version != 4:
            continue
        for ip in net.hosts() if net.num_addresses > 2 else net:
            if len(ips) >= max_ips:
                break
            if not ctx.matcher._ip_excluded(ip):
                ips.append(str(ip))
    ctx.audit_note(f"PTR sweep of {len(ips)} in-scope IPv4 addresses")

    def one(ip):
        try:
            return ip, socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            return ip, None

    found = {}
    with ThreadPoolExecutor(max_workers=10) as ex:
        for ip, name in ex.map(one, ips):
            if name:
                found[ip] = name.lower().rstrip(".")
                col.add(name, "ptr")
    return {"swept": len(ips), "ptr_records": found,
            "truncated": sum(n.num_addresses for n in ctx.matcher.in_nets if n.version == 4) > max_ips}


# ----- main ------------------------------------------------------------------
def main():
    ap = C.base_argparser("Phase 1 — asset discovery")
    ap.add_argument("--domain", action="append",
                    help="restrict to this domain (repeatable) — use to validate small first")
    ap.add_argument("--no-light-active", action="store_true",
                    help="skip AXFR + PTR sweep even if the gate passes")
    ap.add_argument("--amass-minutes", type=int, default=10)
    ap.add_argument("--ptr-max", type=int, default=4096,
                    help="cap on PTR lookups (default 4096)")
    args = ap.parse_args()
    ctx = C.open_run(args, 1, create=True)
    C.log(f"run directory: {ctx.run_dir}", "ok")

    seeds = [norm(d) for d in ((ctx.scope.get("seeds") or {}).get("domains") or [])]
    in_dom = sorted(ctx.matcher.in_domains)
    domains = sorted(set(seeds) | set(in_dom))
    if args.domain:
        want = {norm(d) for d in args.domain}
        unknown = want - set(domains)
        if unknown:
            C.log(f"--domain not in seeds/in_scope: {', '.join(sorted(unknown))}", "err")
            raise SystemExit(2)
        domains = sorted(want)
    if not domains:
        C.log("no seed or in_scope domains to enumerate", "err")
        raise SystemExit(2)
    C.log(f"enumerating: {', '.join(domains)}")
    col = Collector(domains)
    for d in domains:
        col.add(d, "seed")

    # passive sources
    counts = {}
    for d in domains:
        for name, fn in (
            ("crt.sh", lambda: src_crtsh(ctx, col, d)),
            ("subfinder", lambda: src_tool(ctx, col, d, "subfinder",
                                           ["subfinder", "-d", d, "-silent"], 900)),
            ("amass", lambda: src_tool(ctx, col, d, "amass",
                                       ["amass", "enum", "-passive", "-d", d,
                                        "-timeout", str(args.amass_minutes)],
                                       args.amass_minutes * 60 + 180)),
            ("assetfinder", lambda: src_tool(ctx, col, d, "assetfinder",
                                             ["assetfinder", "--subs-only", d], 600)),
            ("shodan", lambda: src_shodan(ctx, col, d)),
        ):
            counts.setdefault(name, {})[d] = fn()
    for name, per in counts.items():
        vals = [v for v in per.values() if isinstance(v, int)]
        errs = sorted({f"{d}: {v}" if len(per) > 1 else v
                       for d, v in per.items() if isinstance(v, str)})
        if not vals:
            ctx.module(name, "skipped", "; ".join(errs))
        elif errs:
            ctx.module(name, "degraded", f"{sum(vals)} names; failed: " + "; ".join(errs))
        else:
            ctx.module(name, "ran", f"{sum(vals)} names")
    ctx.module("censys", "skipped",
               "not automated (Censys API changed); search the Censys platform manually if licensed")

    whois = {d: whois_info(ctx, d) for d in domains}
    ctx.module("whois", "ran" if any(whois.values()) else "skipped",
               "" if any(whois.values()) else "whois absent")
    C.write_json(ctx.path("phase1", "whois.json"), whois)

    dns = {d: dns_records(d) for d in domains} if C.have("dig") else {}
    ctx.module("dns-records", "ran" if dns else "skipped", "" if dns else "dig absent")
    C.write_json(ctx.path("phase1", "dns.json"), dns)

    asns = sorted(ctx.matcher.in_asns)
    prefixes = []
    for a in asns:
        r = asn_prefixes(ctx, a)
        if r is None:
            ctx.module(f"asn-AS{a}", "failed", "RIPEstat unavailable")
        else:
            prefixes += r
    if asns:
        unauth = [p for p in prefixes if p["status"] != "authorized"]
        ctx.module("asn-expansion", "ran",
                   f"{len(prefixes)} announced prefixes; {len(unauth)} NOT in in_scope.cidrs "
                   "(reported for client confirmation, never scanned)")
    C.write_json(ctx.path("phase1", "asn_prefixes.json"), prefixes)

    # light-active
    light = {"axfr": None, "ptr": None}
    if args.no_light_active:
        ctx.module("light-active", "skipped", "--no-light-active")
    elif not ctx.gate_passes():
        ctx.module("light-active", "skipped",
                   "authorization gate not passed — AXFR/PTR touch client nameservers")
    else:
        if C.have("dig"):
            light["axfr"] = {d: try_axfr(ctx, col, d) for d in domains if d in in_dom}
            allowed = [f"{d}@{r['ns']}" for d, rs in light["axfr"].items() for r in rs
                       if r["transfer_allowed"]]
            ctx.module("axfr", "ran", ("ZONE TRANSFER ALLOWED: " + ", ".join(allowed))
                       if allowed else "refused everywhere (expected)")
        else:
            ctx.module("axfr", "skipped", "dig absent")
        light["ptr"] = ptr_sweep(ctx, col, args.ptr_max)
        ctx.module("ptr-sweep", "degraded" if light["ptr"]["truncated"] else "ran",
                   f"{light['ptr']['swept']} IPs, {len(light['ptr']['ptr_records'])} PTRs"
                   + (f" (capped at --ptr-max {args.ptr_max})" if light["ptr"]["truncated"] else ""))
    C.write_json(ctx.path("phase1", "light_active.json"), light)
    ctx.module("bucket-checks", "skipped",
               "not automated — storage-bucket guessing hits cloud providers; do manually if the RoE allows")

    # resolve + classify
    names = sorted(col.hosts)
    C.log(f"resolving {len(names)} hostnames")
    ctx.audit_note(f"DNS resolution of {len(names)} hostnames via recursive resolver")
    resolved = C.resolve_many(names)
    for h in names:
        r = resolved.get(h) or {"ips": [], "cnames": [], "status": "ERROR"}
        rec = col.hosts[h]
        rec.update(ips=r["ips"], cnames=r["cnames"], dns_status=r["status"])
        rec["passive_ok"] = ctx.matcher.is_in_scope(h, active=False)[0]
        ok, why = ctx.matcher.is_in_scope(h, resolved_ips=r["ips"], active=True)
        rec["active_ok"], rec["active_reason"] = ok, why

    assets = {"generated": C.iso(), "engagement_id": ctx.engagement_id,
              "domains": domains, "hosts": col.hosts}
    C.write_json(ctx.path("phase1", "assets.json"), assets)
    live = sum(1 for r in col.hosts.values() if r["ips"])
    act = sum(1 for r in col.hosts.values() if r["active_ok"])
    C.log(f"{len(names)} hostnames, {live} resolve, {act} eligible for active scanning "
          f"(all IPs inside authorized cidrs)", "ok")
    C.log(f"wrote {ctx.path('phase1', 'assets.json')}", "ok")
    ctx.finish()


if __name__ == "__main__":
    main()
