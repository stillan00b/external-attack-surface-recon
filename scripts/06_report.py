#!/usr/bin/env python3
"""
06_report.py — Phase 6: aggregation, coverage badge, ledger, report.

Reads whatever phases produced (missing phases become intelligence gaps, not
errors) and writes into the run directory:
  report.md     the report, sections in the order SKILL.md mandates
  report.json   the same content, machine-readable
  assets.csv / assets.json   consolidated inventory

Badge rule (computed, never chosen):
  coverage = IPv4 addresses masscan swept / non-excluded authorized IPv4 addresses
  FULL     >= 95% and no failed nmap hosts and the scan was not a --only run
  PARTIAL  >= 50%
  MINIMAL  < 50%, or Phase 4 never ran
"""

import csv
import json
import os
import re

import common as C

FULL_PCT, PARTIAL_PCT = 95.0, 50.0

# Exposed-service severity. Matched on port OR nmap service name, so a service
# on a non-standard port is still caught.
EXPOSURE = [
    # (severity, label, ports, service-name substrings)
    ("high", "Remote desktop / VNC", {3389, 5900, 5901, 5800}, ("ms-wbt-server", "vnc", "rdp")),
    ("high", "Telnet", {23}, ("telnet",)),
    ("high", "SMB / NetBIOS / MSRPC", {135, 139, 445}, ("microsoft-ds", "netbios", "msrpc")),
    ("high", "Database", {1433, 1434, 1521, 3306, 5432, 27017, 9042, 7474},
     ("ms-sql", "oracle", "mysql", "postgresql", "mongodb", "cassandra", "neo4j")),
    ("high", "Cache / search / queue (often unauthenticated)", {6379, 11211, 9200, 9300, 9092, 2181},
     ("redis", "memcache", "elasticsearch", "kafka", "zookeeper")),
    ("high", "Container / orchestration API", {2375, 2379, 2380, 10250, 8500},
     ("docker", "etcd", "kubelet", "consul")),
    ("high", "NFS / rpcbind", {2049, 111}, ("nfs", "rpcbind")),
    ("high", "Industrial / OOB management", {102, 502, 623}, ("modbus", "iso-tsap", "ipmi")),
    ("medium", "Windows remote management", {5985, 5986}, ("wsman", "winrm")),
    ("medium", "SSH", {22, 2222}, ("ssh",)),
    ("medium", "FTP", {21, 990}, ("ftp",)),
    ("medium", "LDAP / directory", {389, 636, 3268, 3269}, ("ldap",)),
    ("medium", "Kubernetes API / TLS Docker", {6443, 2376}, ()),
    ("medium", "Admin console", {5601, 8834, 10000, 15672, 4848, 9090},
     ("kibana", "webmin", "nessus")),
]
CONSOLE_PRODUCTS = ("jenkins", "kibana", "grafana", "phpmyadmin", "webmin", "tomcat",
                    "rabbitmq", "big-ip", "fortigate", "pulse secure", "citrix", "globalprotect",
                    "openvpn", "gitlab", "sonarqube", "argocd", "portainer")


UDP_EXPOSURE = {
    161: ("high", "SNMP (UDP) — check for default communities manually; often leaks config"),
    53: ("medium", "DNS (UDP) — check manually whether it is an open recursive resolver"),
    123: ("low", "NTP (UDP) — check manually for mode 6/7 (amplification) responses"),
    500: ("info", "IKE / IPsec VPN gateway (UDP)"),
    4500: ("info", "IPsec NAT-T VPN gateway (UDP)"),
    1194: ("info", "OpenVPN (UDP)"),
    51820: ("info", "WireGuard (UDP)"),
}


def classify_exposure(r):
    if r.get("protocol") == "udp":
        return UDP_EXPOSURE.get(r["port"], ("low", f"UDP service {r.get('service') or r['port']}"))
    svc = (r.get("service") or "").lower()
    for sev, label, ports, names in EXPOSURE:
        if r["port"] in ports or any(n in svc for n in names):
            return sev, label
    prod = (r.get("product") or "").lower()
    for p in CONSOLE_PRODUCTS:
        if p in prod:
            return "medium", f"Management / edge product exposed ({r.get('product')})"
    return None, None


def vtuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", v or "")[:4]) or None


def in_range(version, spec):
    """'<=17.1.0', '<2.4', '>=1.0,<1.2', '1.0-1.5', or an exact version."""
    v = vtuple(version)
    if v is None:
        return False
    for part in (spec or "").split(","):
        part = part.strip()
        m = re.match(r"^(<=|>=|<|>|==)?\s*([\d.]+)$", part)
        if m:
            op, t = m.group(1) or "==", vtuple(m.group(2))
            ok = {"<=": v <= t, ">=": v >= t, "<": v < t, ">": v > t, "==": v[:len(t)] == t}[op]
            if not ok:
                return False
            continue
        m = re.match(r"^([\d.]+)\s*-\s*([\d.]+)$", part)
        if m and not (vtuple(m.group(1)) <= v <= vtuple(m.group(2))):
            return False
        if not m:
            return False
    return True


def md_table(headers, rows):
    if not rows:
        return "_None._\n"
    esc = lambda x: str("" if x is None else x).replace("|", "\\|").replace("\n", " ")
    out = "| " + " | ".join(headers) + " |\n|" + "---|" * len(headers) + "\n"
    for r in rows:
        out += "| " + " | ".join(esc(x) for x in r) + " |\n"
    return out


def main():
    ap = C.base_argparser("Phase 6 — aggregate + report")
    args = ap.parse_args()
    ctx = C.open_run(args, 6)
    rd = ctx.path
    scope = ctx.scope
    eng = scope.get("engagement") or {}
    auth = scope.get("authorization") or {}

    assets = C.read_json(rd("phase1", "assets.json"), {}) or {}
    asn = C.read_json(rd("phase1", "asn_prefixes.json"), []) or []
    light = C.read_json(rd("phase1", "light_active.json"), {}) or {}
    look = C.read_json(rd("phase2", "lookalikes.json"), {}) or {}
    take = C.read_json(rd("phase3", "takeover.json"), {}) or {}
    svc = (C.read_json(rd("phase4", "services.json"), {}) or {}).get("records", [])
    web = C.read_json(rd("phase4", "web.json"), []) or []
    cov = C.read_json(rd("phase4", "coverage.json"))
    post = C.read_json(rd("phase5", "posture.json"), {}) or {}
    status = C.read_json(rd("status.json"), {"phases": {}})
    with open(rd("scope_snapshot.yaml"), "r", encoding="utf-8") as f:
        scope_text = f.read()
    sha = (C.read_json(rd("scope_snapshot.sha256.json"), {}) or {}).get("sha256")

    confirmed = [r for r in svc if r.get("confidence") == "confirmed"]
    unconfirmed = [r for r in svc if r.get("confidence") == "unconfirmed"]

    # ---- findings ----
    findings = []
    for c in take.get("candidates", []):
        findings.append({"severity": c["severity"], "category": "takeover",
                         "target": c["hostname"], "title": f"Subdomain takeover candidate ({c['service']})",
                         "detail": c.get("validation", ""), "source": c.get("source")})
    for r in confirmed:
        sev, label = classify_exposure(r)
        if sev:
            findings.append({"severity": sev, "category": "exposure",
                             "target": f"{r.get('hostname') or r['host']}:{r['port']}",
                             "title": f"{label} exposed to the internet",
                             "detail": " ".join(x for x in (r.get("service"), r.get("product"),
                                                            r.get("version")) if x)
                                       + (" — CDN edge, not origin" if r.get("cdn_fronted") else ""),
                             "source": r.get("source")})
    for f in post.get("findings", []):
        findings.append({"severity": f["severity"], "category": "posture", "target": f["target"],
                         "title": f["title"], "detail": f["detail"], "source": f["source"]})
    # High-risk lookalikes are listed one by one; medium ones are rolled into one
    # finding (typo domains with catch-all MX are common and would flood the list).
    lk = look.get("lookalikes", [])
    for l in lk:
        if l.get("risk") == "high":
            findings.append({"severity": "high", "category": "lookalike", "target": l["domain"],
                             "title": "Lookalike domain", "detail": l.get("risk_reason", ""),
                             "source": "02_lookalike"})
    med = [l["domain"] for l in lk if l.get("risk") == "medium"]
    if med:
        findings.append({"severity": "medium", "category": "lookalike",
                         "target": f"{len(med)} domains",
                         "title": "Lookalike domains with MX, a certificate or a live page",
                         "detail": ", ".join(med[:10]) + (" … (see Lookalike table)" if len(med) > 10 else ""),
                         "source": "02_lookalike"})
    for d, rs in (light.get("axfr") or {}).items():
        for r in rs:
            if r.get("transfer_allowed"):
                findings.append({"severity": "high", "category": "dns", "target": f"{d} @ {r['ns']}",
                                 "title": "DNS zone transfer (AXFR) allowed",
                                 "detail": "The full zone is readable by anyone.",
                                 "source": "01_passive_enum"})

    # ---- prioritization channel (ranking only; never selects targets) ----
    prio_path = (scope.get("integrations") or {}).get("prioritization_feed_path")
    prio_hits, gaps_extra = [], []
    if prio_path:
        feed = C.read_json(prio_path)
        if not feed:
            gaps_extra.append(f"prioritization feed unreadable: {prio_path}")
        else:
            for r in confirmed:
                for item in feed.get("items", []):
                    if item.get("product", "").lower() in (r.get("product") or "").lower() and item.get("product"):
                        if not r.get("version"):
                            gaps_extra.append(f"{r['host']}:{r['port']} {r.get('product')}: version unknown "
                                              f"— cannot rank against {item.get('cve')}")
                        elif in_range(r["version"], item.get("version_range")):
                            prio_hits.append({"target": f"{r.get('hostname') or r['host']}:{r['port']}",
                                              "product": r.get("product"), "version": r.get("version"),
                                              **{k: item.get(k) for k in ("cve", "cvss", "exploit_status",
                                                                          "kev_listed", "source")}})
            for h in prio_hits:
                findings.append({"severity": "high", "category": "priority", "target": h["target"],
                                 "title": f"Runs a product under active exploitation ({h['cve']})",
                                 "detail": f"{h['product']} {h['version']} — VERIFY MANUALLY; "
                                           "no vulnerability check was run.", "source": h["source"]})

    rank = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings.sort(key=lambda f: (rank.get(f["severity"], 4), f["category"], f["target"]))
    sev_count = {s: sum(1 for f in findings if f["severity"] == s) for s in rank}

    # ---- coverage badge + ledger ----
    p4_abort = ((status.get("phases", {}).get("4") or {}).get("modules") or {}).get("ABORT")
    if p4_abort:
        pct, badge = 0.0, "MINIMAL"
        badge_note = (f"Phase 4 was ABORTED ({p4_abort.get('detail')}) at {p4_abort.get('at')} — "
                      "coverage incomplete; partial results in raw/ and phase4/.")
        blocks, cov = [], None
    elif not cov:
        pct, badge = 0.0, "MINIMAL"
        badge_note = "Phase 4 (active scan) did not run — no port coverage."
        blocks = []
    else:
        blocks = cov["blocks"]
        v4 = [b for b in blocks if b["version"] == 4]
        denom = sum(b["enumerated"] - b.get("excluded", 0) for b in v4)
        num = sum(b["scanned"] for b in v4)
        pct = 100.0 * num / denom if denom else 0.0
        badge = "FULL" if pct >= FULL_PCT else "PARTIAL" if pct >= PARTIAL_PCT else "MINIMAL"
        reasons = []
        if cov.get("validation_only"):
            badge, reasons = "MINIMAL", ["--only validation run"]
        if badge == "FULL" and cov.get("failed_hosts"):
            badge = "PARTIAL"
            reasons.append(f"{len(cov['failed_hosts'])} nmap host job(s) failed")
        badge_note = f"{num:,} of {denom:,} authorized IPv4 addresses swept ({pct:.1f}%)" \
                     + (f"; {'; '.join(reasons)}" if reasons else "") \
                     + f"; {cov['port_count']} ports per IP."
    host_rows = (cov or {}).get("hostnames") or [
        {"hostname": h, "ips": r.get("ips", []), "active_ok": r.get("active_ok"),
         "reason": r.get("active_reason"), "cdn_fronted": False, "dns_status": r.get("dns_status")}
        for h, r in (assets.get("hosts") or {}).items()]

    def skip_reason(h):
        if h["active_ok"]:
            return None
        if h.get("cdn_fronted"):
            return f"CDN-fronted ({h.get('cdn_provider') or 'CDN'})"
        reason = h.get("reason") or ""
        if "out_of_scope" in reason:
            return "out-of-scope"
        if "did not resolve" in reason:
            return "unresolved"
        if "outside authorized cidrs" in reason:
            return "resolves outside authorized CIDRs"
        return reason or "not eligible"

    domain_rows = []
    for d in sorted(set(ctx.matcher.in_domains)):
        hs = [h for h in host_rows if h["hostname"] == d or h["hostname"].endswith("." + d)]
        reasons = {}
        for h in hs:
            r = skip_reason(h)
            if r:
                reasons[r] = reasons.get(r, 0) + 1
        domain_rows.append([d, len(hs), sum(1 for h in hs if h["active_ok"]),
                            ", ".join(f"{k}: {v}" for k, v in sorted(reasons.items())) or "—"])

    # ---- gaps ----
    gaps = []
    for ph, info in sorted(status.get("phases", {}).items()):
        for name, m in (info.get("modules") or {}).items():
            if m["state"] != "ran":
                gaps.append(f"Phase {ph} · {name}: {m['state']} — {m.get('detail', '')}")
    for p in ("1", "2", "3", "4", "5"):
        if p not in status.get("phases", {}):
            gaps.append(f"Phase {p} did not run.")
    unauth = [p for p in asn if p.get("status") != "authorized"]
    if unauth:
        gaps.append(f"{len(unauth)} prefix(es) announced by in-scope ASNs are NOT in in_scope.cidrs "
                    f"and were not scanned — confirm with the client: "
                    + ", ".join(p["prefix"] for p in unauth[:15]) + (" …" if len(unauth) > 15 else ""))
    if any(b["version"] == 6 for b in blocks):
        gaps.append("IPv6 blocks were not swept; only AAAA-discovered hosts were scanned.")
    udp = (cov or {}).get("udp") or {"reason": "not recorded by this Phase 4 run"}
    if cov and not udp.get("ran"):
        gaps.append(f"UDP not scanned ({udp.get('reason') or 'unknown'}) — VPN/SNMP/DNS/NTP "
                    "exposure over UDP is not covered.")
    elif udp.get("open_filtered"):
        gaps.append(f"UDP: {udp['open_filtered']} port(s) gave no reply (open|filtered); UDP "
                    "cannot distinguish open from filtered without a response.")
    cdn = (cov or {}).get("cdn") or {}
    for o in cdn.get("in_scope_overlap") or []:
        gaps.append(f"SCOPE CHECK: in_scope cidr {o} edge ranges — those IPs serve other "
                    "customers too; confirm with the client that they are really in scope.")
    if any(h.get("cdn_method") == "cname-heuristic" for h in host_rows):
        gaps.append("Some CDN detections are CNAME-name heuristics (provider publishes no IP list).")
    gaps += gaps_extra

    # ---- inventory ----
    ports_by_ip = {}
    for r in confirmed:
        ports_by_ip.setdefault(r["host"], []).append(r["port"])
    inv = []
    for h, rec in sorted((assets.get("hosts") or {}).items()):
        row = next((x for x in host_rows if x["hostname"] == h), {})
        inv.append({"hostname": h, "ips": rec.get("ips", []), "cnames": rec.get("cnames", []),
                    "sources": rec.get("sources", []), "first_seen": rec.get("first_seen"),
                    "active_ok": row.get("active_ok", rec.get("active_ok")),
                    "not_scanned_reason": skip_reason(row) if row else rec.get("active_reason"),
                    "cdn_fronted": row.get("cdn_fronted", False),
                    "open_ports": sorted({p for ip in rec.get("ips", []) for p in ports_by_ip.get(ip, [])})})
    C.write_json(rd("assets.json"), {"generated": C.iso(), "hosts": inv, "services": svc})
    with open(rd("assets.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["hostname", "ips", "cnames", "sources", "first_seen", "active_ok",
                    "not_scanned_reason", "cdn_fronted", "open_ports"])
        for r in inv:
            w.writerow([r["hostname"], " ".join(r["ips"]), " ".join(r["cnames"]),
                        " ".join(r["sources"]), r["first_seen"], r["active_ok"],
                        r["not_scanned_reason"] or "", r["cdn_fronted"],
                        " ".join(map(str, r["open_ports"]))])

    # ---- markdown ----
    egress = eng.get("scanner_egress_ips") or []
    days = (scope.get("output") or {}).get("retention_days")
    retention_note = "CONFIDENTIAL — contains client asset data. "
    try:
        import datetime as _d
        end_dt = C.scope_gate._parse_dt((eng.get("window") or {}).get("end"))[0]
        if days is not None and end_dt:
            retention_note += (f"Delete this run directory by "
                               f"{(end_dt + _d.timedelta(days=int(days))).date().isoformat()} "
                               f"({int(days)} days after the window, output.retention_days).")
        else:
            retention_note += "No retention period set (output.retention_days) — agree one with the client."
    except (TypeError, ValueError):
        retention_note += "output.retention_days is invalid."
    phases = status.get("phases", {})
    timeline = [[p, phases[p].get("started"), phases[p].get("finished") or "incomplete"]
                for p in sorted(phases)]
    hi = [f for f in findings if f["severity"] == "high"]
    md = []
    md.append(f"# External Attack Surface Report — {eng.get('client', '')}\n")
    md.append(f"**`COVERAGE: {badge}`** — {badge_note}\n")
    md.append(md_table(["Field", "Value"], [
        ["Engagement", eng.get("id")], ["Client", eng.get("client")],
        ["Operator", eng.get("operator")],
        ["Window", f"{(eng.get('window') or {}).get('start')} → {(eng.get('window') or {}).get('end')}"],
        ["Authorization reference", auth.get("reference")],
        ["Cloud provider notified", f"{auth.get('cloud_provider_notified')} {auth.get('cloud_provider_notes') or ''}"],
        ["Scanner egress IP(s)", ", ".join(egress) if egress else
         "NOT RECORDED — set engagement.scanner_egress_ips"],
        ["Emergency contacts", "; ".join(map(str, eng.get("emergency_contacts") or [])) or
         "NOT RECORDED — set engagement.emergency_contacts"],
        ["Data handling", retention_note],
        ["Generated", C.iso()], ["Run directory", ctx.run_dir], ["scope.yaml sha256", sha]]))
    md.append("\n<details><summary>Scope (verbatim from scope.yaml)</summary>\n\n```yaml\n"
              + scope_text.rstrip() + "\n```\n</details>\n")
    md.append("\n## Executive summary\n\n_Auto-generated draft — review and rewrite for the "
              "audience before delivery._\n")
    md.append(f"- {len(inv)} hostnames discovered; {sum(1 for r in inv if r['active_ok'])} sit "
              f"entirely on authorized IP space and were eligible for scanning.")
    md.append(f"- {len(confirmed)} confirmed open services on {len(ports_by_ip)} hosts"
              f" ({len(unconfirmed)} masscan hits could not be confirmed and are listed separately).")
    md.append(f"- Findings: {sev_count['high']} high, {sev_count['medium']} medium, "
              f"{sev_count['low']} low, {sev_count['info']} info.")
    for f in hi[:5]:
        md.append(f"- **High:** {f['title']} — `{f['target']}`")
    md.append("")
    md.append("\n## Findings\n")
    md.append(md_table(["Severity", "Category", "Target", "Finding", "Detail", "Source"],
                       [[f["severity"], f["category"], f["target"], f["title"], f["detail"], f["source"]]
                        for f in findings]))
    md.append("\n## Asset inventory\n")
    live_inv = [r for r in inv if r["ips"] or r["cnames"]]
    md.append(f"{len(inv)} hostnames discovered; {len(live_inv)} resolve (shown below). "
              f"The {len(inv) - len(live_inv)} that don't resolve are kept in `assets.csv` / "
              f"`assets.json` with their sources.\n\n")
    md.append(md_table(["Hostname", "IPs", "CNAME", "Sources", "First seen", "Scanned?", "Open ports"],
                       [[r["hostname"], " ".join(r["ips"]) or "—", " → ".join(r["cnames"]) or "",
                         ", ".join(r["sources"]), r["first_seen"],
                         "yes" if r["active_ok"] else f"no ({r['not_scanned_reason']})",
                         " ".join(map(str, r["open_ports"])) or "—"] for r in live_inv]))
    md.append("\n## Lookalike domains\n")
    md.append(md_table(["Risk", "Domain", "Fuzzer", "MX", "CT certs", "Created", "Why"],
                       [[l["risk"], l["domain"], l.get("fuzzer"), "yes" if l.get("mx") else "",
                         l.get("ct_certs"), l.get("created"), l.get("risk_reason")]
                        for l in look.get("lookalikes", [])]))
    md.append("\n## Subdomain-takeover candidates\n\n_Candidates only. Nothing was claimed._\n\n")
    md.append(md_table(["Severity", "Hostname", "Service", "CNAME", "Evidence", "Validation"],
                       [[c["severity"], c["hostname"], c["service"], " → ".join(c.get("cnames", [])),
                         (f"CNAME target unresolved ({(c.get('evidence') or {}).get('dns_status')}); "
                          if (c.get("evidence") or {}).get("cname_target_unresolved") else "")
                         + ("fingerprint: " + str(((c.get("evidence") or {}).get("http") or {}).get("fingerprint"))
                            if ((c.get("evidence") or {}).get("http") or {}).get("fingerprint") else ""),
                         c.get("validation")] for c in take.get("candidates", [])]))
    md.append("\n## Port / service matrix (confirmed)\n")
    md.append(md_table(["Host", "Hostname(s)", "Port", "Proto", "Service", "Product", "Version",
                        "CDN edge", "Source"],
                       [[r["host"], ", ".join(r.get("hostnames") or []), r["port"], r.get("protocol", "tcp"),
                         r.get("service"), r.get("product"), r.get("version"),
                         (r.get("cdn_provider") or "yes") if r.get("cdn_fronted") else "",
                         r.get("source")] for r in sorted(confirmed, key=lambda r: (r["host"], r.get("protocol", "tcp"), r["port"]))]))
    md.append("\n### Unconfirmed (masscan hit, nmap could not confirm — NOT reported as open)\n")
    md.append(md_table(["Host", "Port", "nmap state"],
                       [[r["host"], r["port"], r["state"]] for r in unconfirmed]))
    if web:
        md.append("\n### Web services\n")
        md.append(md_table(["URL", "Status", "Title", "Server/Tech"],
                           [[w.get("url"), w.get("status"), w.get("title"),
                             w.get("server") or ", ".join(w.get("tech") or [])] for w in web]))
    if prio_hits:
        md.append("\n### Prioritized by threat intel (ranking only — verify manually)\n")
        md.append(md_table(["Target", "Product", "Version", "CVE", "KEV", "Exploit status", "Source"],
                           [[h["target"], h["product"], h["version"], h["cve"], h.get("kev_listed"),
                             h.get("exploit_status"), h.get("source")] for h in prio_hits]))
    md.append("\n## Posture (email / DNS / TLS)\n")
    md.append(md_table(["Severity", "Target", "Finding", "Detail"],
                       [[f["severity"], f["target"], f["title"], f["detail"]]
                        for f in post.get("findings", [])]))
    md.append("\n## Intelligence gaps\n")
    md.append("\n".join(f"- {g}" for g in gaps) + "\n" if gaps else "_None recorded._\n")
    md.append("\n## Appendix A — Scan-coverage ledger\n")
    md.append(md_table(["Authorized block", "Enumerated", "Excluded", "Scanned", "Skipped", "Reason",
                        "Hosts w/ candidates", "Hosts confirmed"],
                       [[b["block"], b["enumerated"], b.get("excluded", 0), b["scanned"], b["skipped"],
                         b.get("skip_reason") or b.get("note") or "—", b.get("hosts_with_candidates", ""),
                         b.get("hosts_confirmed", "")] for b in blocks]))
    if cov:
        md.append(f"\n**UDP** (ports {udp.get('ports') or '—'}): "
                  + (f"scanned — {udp.get('open', 0)} open, {udp.get('open_filtered', 0)} no reply "
                     "(open|filtered)." if udp.get("ran") else f"not scanned — {udp.get('reason')}.")
                  + "\n")
    md.append("\n" + md_table(["Authorized domain", "Hostnames found", "Eligible (all IPs authorized)",
                               "Not scanned (reason: count)"], domain_rows))
    md.append("\n## Appendix B — Timeline & audit\n")
    md.append(md_table(["Phase", "Started (UTC)", "Finished (UTC)"], timeline))
    try:
        with open(rd("commands.log"), "r", encoding="utf-8") as f:
            n_cmd = sum(1 for _ in f)
    except FileNotFoundError:
        n_cmd = 0
    md.append(f"\nEvery external command and network action ({n_cmd} entries) is logged in "
              f"`commands.log` in the run directory, with raw tool output under `raw/`.\n")
    with open(rd("report.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(md))

    C.write_json(rd("report.json"), {
        "generated": C.iso(), "engagement": {"id": eng.get("id"), "client": eng.get("client"),
                                             "window": eng.get("window"),
                                             "scanner_egress_ips": egress},
        "scope_sha256": sha, "badge": badge, "coverage_pct": round(pct, 2), "badge_note": badge_note,
        "severity_counts": sev_count, "findings": findings, "inventory": inv,
        "services": svc, "lookalikes": look.get("lookalikes", []),
        "takeover_candidates": take.get("candidates", []), "posture": post,
        "prioritized": prio_hits, "intelligence_gaps": gaps,
        "ledger": {"blocks": blocks, "domains": domain_rows}, "timeline": timeline})
    ctx.module("report", "ran", f"COVERAGE: {badge}")
    C.log(f"report: {rd('report.md')}", "ok")
    ctx.finish()


if __name__ == "__main__":
    main()
