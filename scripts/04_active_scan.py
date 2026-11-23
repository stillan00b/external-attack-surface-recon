#!/usr/bin/env python3
"""
04_active_scan.py — Phase 4: masscan -> nmap handover (GATED).

  0. Re-run the Phase 0 gate; refuse if it fails.
  1. Build inputs FROM THE GATE: targets (in_scope IPv4 cidrs), excludes
     (out_of_scope cidrs/IPs, passed to masscan AND nmap), ports (scan.ports).
  2. Re-resolve Phase 1 hostnames and run the active check on each: a hostname
     is scanned only via IPs that are all inside authorized cidrs. Others are
     recorded in the ledger with the reason (third-party / CDN / unresolved).
  3. Stage A: masscan breadth pass at rate.masscan_max_rate (one process, so
     the global ceiling holds). Full-range pass for scan.full_range_on, run
     sequentially after it.
  4. Every masscan hit is re-checked against the matcher. Anything out of
     scope is dropped and logged as an error (belt and braces).
  5. Stage B: nmap -sV on candidate ports only, in a pool of
     rate.parallel_workers, each worker given --max-rate ceiling/workers so the
     per-worker caps sum to the ceiling. No scripts, ever.
  6. Optional --fallback: nmap scan.top_ports on in-scope hostname IPs that
     masscan found nothing on (masscan false negatives, SYN-proxies).
  7. UDP pass (root only): one nmap -sU over the same targets/excludes for
     scan.udp_ports, with nmap's protocol payloads only (no -sV, no scripts).
     "open" = replied; "open|filtered" = no reply, counted but not reported.
  8. Web probe (PD httpx, else stdlib) + whatweb -a 1 on confirmed TCP web
     ports, by IP and by each checked hostname mapped to that IP (vhosts).

CDN detection uses the providers' published edge ranges (Cloudflare, Fastly,
CloudFront) plus a CNAME-name heuristic for providers with no public list. An
in_scope cidr overlapping a CDN edge is flagged as a likely scope mistake.

Abort: Ctrl-C, SIGTERM, `touch <run>/STOP`, or the engagement window ending
all kill every running masscan/nmap and record the abort (exit code 4).

--dry-run writes every input file and prints the exact commands without
sending a packet. Use it to review a plan with the operator.

Output: <run>/phase4/services.json (result records), web.json, coverage.json,
        units.json, targets.txt, excludes.txt, nmap/*.xml, masscan_*.txt
"""

import ipaddress
import json
import os
import shutil
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor

import common as C
import scope_gate

WEB_TLS_PORTS = {443, 444, 2083, 2087, 2096, 3443, 4443, 5001, 6443, 7443, 8443, 9443, 10443}


def scan_privileges(ctx):
    """masscan needs raw sockets; nmap -sS too. Returns (masscan_ok, nmap_scan_flag)."""
    if C.is_root():
        return True, "-sS"
    caps_ok = False
    if C.have("getcap") and C.have("masscan"):
        rc, out = ctx.run(["getcap", shutil.which("masscan")], name="getcap", timeout=10)
        caps_ok = "cap_net_raw" in out
    return caps_ok, "-sT"


def parse_nmap_udp(path):
    """UDP results for every host in one nmap XML: [(ip, port, state, service)].
    None if the file is missing/corrupt."""
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, FileNotFoundError):
        return None
    out = []
    for host in root.iter("host"):
        addr = next((a.get("addr") for a in host.iter("address")
                     if a.get("addrtype") in ("ipv4", "ipv6")), None)
        for port in host.iter("port"):
            if port.get("protocol") != "udp" or not addr:
                continue
            st = port.find("state")
            svc = port.find("service")
            out.append((addr, int(port.get("portid")),
                        st.get("state") if st is not None else "unknown",
                        (svc.get("name") if svc is not None else "") or ""))
    return out


def block_ips(matcher, net):
    """Non-excluded addresses in one in_scope block (same rule as the gate's
    duration estimate: nested-or-disjoint overlap after collapsing)."""
    outs = list(ipaddress.collapse_addresses(
        [o for o in matcher.out_nets if o.version == net.version] +
        [ipaddress.ip_network(h) for h in matcher.out_hosts if h.version == net.version]))
    excluded = sum(o.num_addresses if o.subnet_of(net) else
                   net.num_addresses if net.subnet_of(o) else 0 for o in outs)
    return max(net.num_addresses - excluded, 0)


def parse_masscan(path):
    hits = set()
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[0] == "open" and parts[1] == "tcp":
                    hits.add((parts[3], int(parts[2])))
    except FileNotFoundError:
        pass
    return hits


def parse_nmap_xml(path):
    """Returns {port: {...}} for the single host in the file, or None if the
    file is missing/corrupt (scan failed)."""
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, FileNotFoundError):
        return None
    out = {}
    for port in root.iter("port"):
        if port.get("protocol") != "tcp":
            continue
        st = port.find("state")
        svc = port.find("service")
        out[int(port.get("portid"))] = {
            "state": st.get("state") if st is not None else "unknown",
            "service": (svc.get("name") if svc is not None else "") or "",
            "product": (svc.get("product") if svc is not None else "") or "",
            "version": (svc.get("version") if svc is not None else "") or "",
            "extrainfo": (svc.get("extrainfo") if svc is not None else "") or "",
            "tunnel": (svc.get("tunnel") if svc is not None else "") or "",
        }
    return out


def main():
    ap = C.base_argparser("Phase 4 — masscan -> nmap active scan (gated)")
    ap.add_argument("--dry-run", action="store_true", help="write inputs, print commands, send nothing")
    ap.add_argument("--fallback", action="store_true",
                    help="nmap scan.top_ports on in-scope hostname IPs with no masscan hits")
    ap.add_argument("--only", metavar="IP",
                    help="validate small: restrict the scan to one in-scope IP")
    ap.add_argument("--no-web", action="store_true", help="skip httpx/whatweb")
    args = ap.parse_args()
    ctx = C.open_run(args, 4)
    gate_report = ctx.require_gate()
    # Abort paths: Ctrl-C / SIGTERM, `touch <run>/STOP`, or the engagement
    # window ending mid-scan. All of them kill every running masscan/nmap.
    C.install_abort_handlers(ctx)
    C.start_watchdog(ctx)
    C.log(f"kill switch: touch {ctx.path('STOP')}   (or Ctrl-C)")
    pd = ctx.phase_dir()
    os.makedirs(os.path.join(pd, "nmap"), exist_ok=True)

    # 1. inputs from the gate
    _, ports = scope_gate.resolve_ports(ctx.scope)
    ports_arg = scope_gate.compress_ports(ports)
    v4 = sorted(ipaddress.collapse_addresses(n for n in ctx.matcher.in_nets if n.version == 4))
    if args.only:
        ok, why = ctx.matcher.is_in_scope(args.only)
        if not ok or ":" in args.only or "/" in args.only:
            C.log(f"--only {args.only} refused: {why if not ok else 'must be one IPv4 address'}", "err")
            raise SystemExit(2)
        v4 = [ipaddress.ip_network(args.only + "/32")]
    targets = os.path.join(pd, "targets.txt")
    excludes = os.path.join(pd, "excludes.txt")
    with open(targets, "w") as f:
        f.write("\n".join(str(n) for n in v4) + "\n")
    with open(excludes, "w") as f:
        f.write(scope_gate.excludes_for_scanner(ctx.matcher) + "\n")

    # 2. hostname check
    assets = C.load_assets(ctx)
    hosts = {h: r for h, r in (assets.get("hosts") or {}).items() if r.get("passive_ok")}
    checked = C.checked_hosts(ctx, {"hosts": hosts}) if hosts else {}

    # CDN detection: published provider ranges first (Cloudflare, Fastly,
    # CloudFront), CNAME-name heuristic for providers without a public list.
    ranges, cdn_failed = C.cdn_ranges(ctx)
    for h, c in checked.items():
        prov = next((p for p in (C.cdn_for_ip(ranges, ip) for ip in c["ips"]) if p), None)
        method = "ip-range" if prov else None
        if not prov:
            prov = C.cdn_for_cnames(c["cnames"])
            method = "cname-heuristic" if prov else None
        c.update(cdn_fronted=bool(prov), cdn_provider=prov, cdn_method=method)
    ctx.module("cdn-detection", "degraded" if cdn_failed else "ran",
               f"ranges: {', '.join(sorted(ranges)) or 'none'}"
               + (f"; could not fetch {', '.join(cdn_failed)} (CNAME heuristic only)" if cdn_failed else "")
               + f"; {sum(1 for c in checked.values() if c['cdn_fronted'])} hostnames CDN-fronted")
    # An authorized block that overlaps a CDN's edge is almost always a scope
    # mistake: those IPs serve thousands of other customers.
    cdn_overlap = [f"{n} overlaps {prov}" for n in ctx.matcher.in_nets
                   for prov, nets in ranges.items()
                   if any(n.version == r.version and n.overlaps(r) for r in nets)]
    for o in cdn_overlap:
        C.log(f"in_scope cidr {o} edge ranges — those IPs are shared with other customers; "
              "confirm with the client before scanning", "warn")
    ok_hosts = {h: c for h, c in checked.items() if c["ok"]}
    v6_direct = sorted({ip for c in ok_hosts.values() for ip in c["ips"] if ":" in ip})
    if args.only:
        v6_direct = []
    ctx.module("hostname-check", "ran",
               f"{len(ok_hosts)} of {len(checked)} hostnames resolve entirely to authorized "
               f"cidrs; {len(checked) - len(ok_hosts)} recorded as not scanned")

    # full-range hosts: IPs that pass, or hostnames via their checked IPs
    full = set()
    for entry in ((ctx.scope.get("scan") or {}).get("full_range_on") or []):
        e = str(entry).strip().lower()
        try:
            ipaddress.ip_address(e)
            if ctx.matcher.is_in_scope(e)[0] and ":" not in e:
                full.add(e)
            else:
                C.log(f"full_range_on {e} refused (out of scope or IPv6)", "warn")
        except ValueError:
            c = checked.get(e) or {}
            if c.get("ok"):
                full |= {ip for ip in c["ips"] if ":" not in ip}
            else:
                C.log(f"full_range_on {e} refused: {c.get('reason', 'not a Phase 1 hostname')}", "warn")
    if args.only:
        full &= {args.only}
    full_path = os.path.join(pd, "full_range_hosts.txt")
    with open(full_path, "w") as f:
        f.write("\n".join(sorted(full)) + ("\n" if full else ""))

    masscan_ok, nmap_scan = scan_privileges(ctx)
    rate = ctx.masscan_rate
    est = (gate_report.get("scan_plan") or {}).get("est_seconds")
    est = 3600 if est is None else est
    m1 = ["masscan", "-iL", targets, "--excludefile", excludes, "-p", ports_arg,
          "--max-rate", str(rate), "--open-only", "--wait", "5",
          "-oL", os.path.join(pd, "masscan_raw.txt")]
    m2 = ["masscan", "-iL", full_path, "--excludefile", excludes, "-p", "1-65535",
          "--max-rate", str(rate), "--open-only", "--wait", "5",
          "-oL", os.path.join(pd, "masscan_full_raw.txt")]
    per_worker = max(1, rate // max(ctx.workers, 1))
    udp_on, udp_ports = scope_gate.resolve_udp(ctx.scope)
    udp_xml = os.path.join(pd, "nmap", "udp.xml")
    # One nmap process after TCP finishes, at the full ceiling (sequential, so
    # the ceiling still holds). nmap's built-in UDP payloads only: no -sV (its
    # SNMP probes try community strings), no scripts.
    u1 = ["nmap", "-sU", "-Pn", "-n", "-p", "U:" + scope_gate.compress_ports(udp_ports),
          "--max-retries", str(scope_gate.UDP_RETRIES), "--max-rate", str(rate),
          "-" + ctx.nmap_timing, "--excludefile", excludes, "-iL", targets, "-oX", udp_xml]

    if args.dry_run:
        print("\n# DRY RUN — nothing sent. Planned commands:")
        print(" ".join(m1))
        if full:
            print(" ".join(m2))
        print(f"# then per candidate host ({ctx.workers} workers, --max-rate {per_worker} each):")
        print(f"nmap {nmap_scan} -sV -Pn --version-intensity 5 -{ctx.nmap_timing} -p <candidate ports> "
              f"--max-retries 2 --max-rate {per_worker} --excludefile {excludes} -oX nmap/<ip>.xml <ip>")
        if v6_direct:
            print(f"# + IPv6 hosts individually (-6): {', '.join(v6_direct)}")
        if udp_on:
            print("# then UDP (needs root):")
            print(" ".join(u1))
        print(f"# masscan privileges: {'ok' if masscan_ok else 'MISSING (run as root or setcap)'}")
        for o in cdn_overlap:
            print(f"# WARNING: in_scope {o} — shared CDN edge, confirm with client")
        ctx.module("phase", "skipped", "--dry-run")
        ctx.finish()
        return

    if not C.have("masscan") or not C.have("nmap"):
        ctx.module("phase", "failed", "masscan and nmap are both required")
        ctx.finish()
        raise SystemExit(1)
    if not masscan_ok:
        C.log("masscan needs raw-socket privileges. Run this phase as root, or grant them once:", "err")
        C.log("  sudo setcap cap_net_raw,cap_net_admin=eip $(command -v masscan)", "err")
        ctx.module("masscan", "failed", "no raw-socket privileges")
        ctx.finish()
        raise SystemExit(1)
    if C.is_wsl():
        C.log("WSL detected: masscan behind WSL2's default NAT is unreliable (false negatives). "
              "Prefer networkingMode=mirrored or a native Linux host.", "warn")

    # A real scan starts clean: results from an earlier Phase 4 attempt in this
    # run must not be mistaken for this one's (e.g. if this one is aborted).
    for stale in ("services.json", "coverage.json", "web.json", "units.json"):
        try:
            os.remove(os.path.join(pd, stale))
        except FileNotFoundError:
            pass

    # units (work-units.md shape) — one masscan unit, then one nmap unit per host
    units = [{"unit_id": "u-masscan-1", "engagement_id": ctx.engagement_id, "phase": "active_scan",
              "stage": "masscan", "targets": [str(n) for n in v4], "ports": ports_arg,
              "rate_budget": rate, "created_at": C.iso(), "attempt": 1, "max_attempts": 1,
              "status": "pending"}]

    # 3. Stage A
    C.log(f"masscan: {len(v4)} block(s), {len(ports)} ports @ {rate} pkt/s (est. "
          f"{scope_gate._fmt_duration(est)})")
    rc, _ = ctx.run(m1, name="masscan", timeout=int(est * 1.5) + 900)
    units[0]["status"] = "done" if rc == 0 else "failed"
    masscan_completed = rc == 0
    ctx.module("masscan", "ran" if rc == 0 else "failed",
               "" if rc == 0 else f"exit {rc} — see raw/p4_masscan.err")
    hits = parse_masscan(os.path.join(pd, "masscan_raw.txt"))
    if full:
        rc2, _ = ctx.run(m2, name="masscan_full", timeout=len(full) * 65535 // rate * 2 + 900)
        ctx.module("masscan-full-range", "ran" if rc2 == 0 else "failed", f"{len(full)} host(s)")
        hits |= parse_masscan(os.path.join(pd, "masscan_full_raw.txt"))

    # 4. re-check every hit
    clean = set()
    for ip, port in hits:
        if ctx.matcher.is_in_scope(ip)[0]:
            clean.add((ip, port))
        else:
            C.log(f"DROPPED out-of-scope masscan hit {ip}:{port} — investigate target list", "err")
    by_host = {}
    for ip, port in clean:
        by_host.setdefault(ip, set()).add(port)
    C.log(f"{len(clean)} candidate ports on {len(by_host)} hosts", "ok")

    # 5. Stage B (+ IPv6 direct + optional fallback)
    jobs = [(ip, sorted(p), "confirm") for ip, p in sorted(by_host.items())]
    jobs += [(ip, ports, "ipv6-direct") for ip in v6_direct]
    if args.fallback:
        hosted = {ip for c in ok_hosts.values() for ip in c["ips"] if ":" not in ip}
        top = int((ctx.scope.get("scan") or {}).get("top_ports") or 1000)
        if args.only:
            hosted &= {args.only}
        jobs += [(ip, top, "fallback") for ip in sorted(hosted - set(by_host))]

    def nmap_job(job):
        ip, plist, stage = job
        xml = os.path.join(pd, "nmap", f"{stage}_{ip.replace(':', '_')}.xml")
        argv = ["nmap", nmap_scan, "-sV", "-Pn", "--version-intensity", "5",
                "-" + ctx.nmap_timing, "--max-retries", "2", "--max-rate", str(per_worker),
                "--excludefile", excludes, "-oX", xml]
        argv += ["--top-ports", str(plist)] if isinstance(plist, int) else \
            ["-p", scope_gate.compress_ports(plist)]
        if ctx.nmap_min_rate:
            argv += ["--min-rate", str(min(ctx.nmap_min_rate, per_worker))]
        if ":" in ip:
            argv.append("-6")
        argv.append(ip)
        ctx.run(argv, name=f"nmap_{stage}_{ip}", timeout=3600)
        return job, parse_nmap_xml(xml)

    records, failed_hosts = [], []
    with ThreadPoolExecutor(max_workers=max(ctx.workers, 1)) as ex:
        for (ip, plist, stage), res in ex.map(nmap_job, jobs):
            units.append({"unit_id": f"u-nmap-{stage}-{ip}", "engagement_id": ctx.engagement_id,
                          "phase": "active_scan", "stage": "nmap", "targets": [ip],
                          "ports": plist if isinstance(plist, int) else scope_gate.compress_ports(plist),
                          "rate_budget": per_worker, "created_at": C.iso(), "attempt": 1,
                          "max_attempts": 1, "status": "done" if res is not None else "failed"})
            if res is None:
                failed_hosts.append(ip)
                continue
            names = sorted(h for h, c in ok_hosts.items() if ip in c["ips"])
            cdn_prov = C.cdn_for_ip(ranges, ip) or next(
                (checked[h]["cdn_provider"] for h in names if checked[h]["cdn_provider"]), None)
            cdn = bool(cdn_prov)
            want = plist if isinstance(plist, list) else sorted(res)
            for port in want:
                r = res.get(port, {"state": "no-response", "service": "", "product": "",
                                   "version": "", "extrainfo": "", "tunnel": ""})
                is_open = r["state"] == "open"
                if stage != "confirm" and not is_open:
                    continue  # direct/fallback passes: only report what's open
                records.append({
                    "unit_id": f"u-nmap-{stage}-{ip}", "engagement_id": ctx.engagement_id,
                    "host": ip, "hostname": names[0] if names else None, "hostnames": names,
                    "port": port, "protocol": "tcp", "state": r["state"],
                    "service": ("ssl/" if r["tunnel"] == "ssl" else "") + r["service"],
                    "product": r["product"], "version": r["version"],
                    "extrainfo": r["extrainfo"],
                    "source": "nmap" if stage == "confirm" else f"nmap-{stage}",
                    "stage": stage, "confidence": "confirmed" if is_open else "unconfirmed",
                    "first_seen": C.iso(), "cdn_fronted": cdn, "cdn_provider": cdn_prov,
                    "notes": "" if is_open else "masscan hit; nmap could not confirm"})

    # 5b. UDP pass
    udp_info = {"enabled": udp_on, "ports": scope_gate.compress_ports(udp_ports) if udp_on else None,
                "ran": False, "reason": None, "open": 0, "open_filtered": 0}
    if not udp_on:
        udp_info["reason"] = "scan.udp is false"
        ctx.module("udp", "skipped", "scan.udp is false")
    elif not C.is_root():
        udp_info["reason"] = "nmap -sU needs root"
        ctx.module("udp", "skipped", "nmap -sU needs root — run Phase 4 as root to cover UDP")
    else:
        udp_est = (gate_report.get("scan_plan") or {}).get("udp_packets", 0) / max(rate, 1)
        C.log(f"UDP: ports {udp_info['ports']} on {len(v4)} block(s)")
        rc, _ = ctx.run(u1, name="nmap_udp", timeout=int(udp_est * 4) + 900)
        res = parse_nmap_udp(udp_xml)
        if res is None:
            udp_info["reason"] = f"nmap -sU failed (exit {rc})"
            ctx.module("udp", "failed", udp_info["reason"])
        else:
            udp_info["ran"] = True
            for ip, port, state, svc in res:
                if not ctx.matcher.is_in_scope(ip)[0]:
                    C.log(f"DROPPED out-of-scope UDP result {ip}:{port}", "err")
                    continue
                if state == "open|filtered":
                    udp_info["open_filtered"] += 1   # no reply: can't tell open from filtered
                    continue
                if state != "open":
                    continue
                udp_info["open"] += 1
                names = sorted(h for h, c in ok_hosts.items() if ip in c["ips"])
                records.append({
                    "unit_id": "u-nmap-udp", "engagement_id": ctx.engagement_id,
                    "host": ip, "hostname": names[0] if names else None, "hostnames": names,
                    "port": port, "protocol": "udp", "state": "open", "service": svc,
                    "product": "", "version": "", "extrainfo": "", "source": "nmap-udp",
                    "stage": "udp", "confidence": "confirmed", "first_seen": C.iso(),
                    "cdn_fronted": False, "cdn_provider": None,
                    "notes": "replied to nmap's protocol payload"})
            ctx.module("udp", "ran", f"{udp_info['open']} open; {udp_info['open_filtered']} "
                                     "open|filtered (no reply — not reported as open)")
    ctx.module("nmap", "ran" if not failed_hosts else "degraded",
               f"{len(jobs)} host jobs" + (f"; {len(failed_hosts)} failed: "
                                           + ", ".join(failed_hosts[:10]) if failed_hosts else "")
               + ("" if nmap_scan == "-sS" else " (connect scan -sT: not root)"))
    C.write_json(os.path.join(pd, "services.json"), {"generated": C.iso(), "records": records})
    C.write_json(os.path.join(pd, "units.json"), units)

    # 7. web probe on confirmed web ports
    web = []
    if args.no_web:
        ctx.module("web-probe", "skipped", "--no-web")
    else:
        urls = set()
        for r in records:
            if r["confidence"] != "confirmed" or r.get("protocol") != "tcp":
                continue
            svc = r["service"]
            if "http" not in svc and r["port"] not in WEB_TLS_PORTS and r["port"] not in (80, 8080, 8000):
                continue
            tls = svc.startswith("ssl/") or "https" in svc or r["port"] in WEB_TLS_PORTS
            scheme = "https" if tls else "http"
            for name in [r["host"]] + r["hostnames"]:
                hostpart = f"[{name}]" if ":" in name else name
                urls.add(f"{scheme}://{hostpart}:{r['port']}/")
        urls = sorted(urls)
        ufile = os.path.join(pd, "web_urls.txt")
        with open(ufile, "w") as f:
            f.write("\n".join(urls) + ("\n" if urls else ""))
        if urls and C.pd_httpx():
            rc, out = ctx.run(["httpx", "-l", ufile, "-json", "-silent", "-title", "-tech-detect",
                               "-status-code", "-rl", str(min(per_worker, 50))],
                              name="httpx", timeout=3600)
            for line in out.splitlines():
                try:
                    j = json.loads(line)
                except ValueError:
                    continue
                web.append({"url": j.get("url"), "status": j.get("status_code") or j.get("status-code"),
                            "title": j.get("title"), "tech": j.get("tech") or j.get("technologies"),
                            "source": "httpx"})
            ctx.module("web-probe", "ran", f"httpx: {len(urls)} URLs")
        elif urls:
            ctx.audit_note(f"stdlib HTTP GET of {len(urls)} confirmed web URLs")
            with ThreadPoolExecutor(max_workers=5) as ex:
                for u, (st, hd, body) in zip(urls, ex.map(lambda u: C.http_get(u, timeout=12), urls)):
                    web.append({"url": u, "status": st, "title": C.html_title(body) if st else "",
                                "server": hd.get("Server") if st else None,
                                "error": None if st else body, "source": "stdlib"})
            ctx.module("web-probe", "degraded" if not C.have("httpx") or not C.pd_httpx() else "ran",
                       f"{len(urls)} URLs via stdlib (ProjectDiscovery httpx not found)")
        else:
            ctx.module("web-probe", "ran", "no confirmed web services")
        if urls and C.have("whatweb"):
            wj = os.path.join(pd, "whatweb.json")
            ctx.run(["whatweb", "-a", "1", "--no-errors", f"--log-json={wj}", "-i", ufile],
                    name="whatweb", timeout=3600)
            ctx.module("whatweb", "ran", f"aggression 1 on {len(urls)} URLs")
        elif urls:
            ctx.module("whatweb", "skipped", "whatweb absent")
    C.write_json(os.path.join(pd, "web.json"), web)

    # coverage data for the Phase 6 ledger
    blocks = []
    for n in ctx.matcher.in_nets:
        if n.version == 6:
            v6_here = [ip for ip in v6_direct if ipaddress.ip_address(ip) in n]
            blocks.append({"block": str(n), "version": 6, "enumerated": len(v6_here),
                           "scanned": len(v6_here), "skipped": 0,
                           "note": "IPv6 block not swept; AAAA-discovered hosts scanned individually"})
            continue
        total = block_ips(ctx.matcher, n)
        excluded = n.num_addresses - total
        in_only = (not args.only) or ipaddress.ip_address(args.only) in n
        scanned = (1 if args.only else total) if (masscan_completed and in_only) else 0
        blocks.append({"block": str(n), "version": 4, "enumerated": n.num_addresses,
                       "excluded": excluded, "scanned": scanned,
                       "skipped": total - scanned,
                       "skip_reason": None if scanned == total else
                       ("--only validation run" if args.only else "masscan did not complete"),
                       "hosts_with_candidates": sum(1 for ip in by_host if ipaddress.ip_address(ip) in n),
                       "hosts_confirmed": len({r["host"] for r in records if r["confidence"] == "confirmed"
                                               and ipaddress.ip_address(r["host"]) in n})})
    host_rows = [{"hostname": h, "ips": c["ips"], "active_ok": c["ok"], "reason": c["reason"],
                  "cdn_fronted": c["cdn_fronted"], "cdn_provider": c["cdn_provider"],
                  "cdn_method": c["cdn_method"], "dns_status": c["status"]}
                 for h, c in sorted(checked.items())]
    C.write_json(os.path.join(pd, "coverage.json"),
                 {"generated": C.iso(), "masscan_completed": masscan_completed,
                  "validation_only": bool(args.only), "ports": ports_arg,
                  "port_count": len(ports), "rate": rate, "workers": ctx.workers,
                  "nmap_scan_type": nmap_scan, "blocks": blocks, "hostnames": host_rows,
                  "failed_hosts": failed_hosts, "udp": udp_info,
                  "cdn": {"ranges_loaded": sorted(ranges), "fetch_failed": cdn_failed,
                          "in_scope_overlap": cdn_overlap}})
    conf = sum(1 for r in records if r["confidence"] == "confirmed")
    unconf = sum(1 for r in records if r["confidence"] == "unconfirmed")
    C.log(f"{conf} confirmed open, {unconf} unconfirmed -> phase4/services.json", "ok")
    ctx.finish()


if __name__ == "__main__":
    main()
