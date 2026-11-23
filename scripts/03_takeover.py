#!/usr/bin/env python3
"""
03_takeover.py — Phase 3: subdomain-takeover CANDIDATE detection.

Two evidence tiers:

  DNS (passive): every Phase 1 hostname under an in-scope domain is
    re-resolved. A CNAME into a known provider (signatures file) and/or a CNAME
    whose target is NXDOMAIN is a dangling-DNS signal.

  HTTP fingerprint (gated): one GET over https and http to the client's own
    hostname, matching the provider's "unclaimed resource" page. That request
    lands on the third-party provider the CNAME points at. This is the one
    sanctioned exception to "only scan authorized IPs", because the hostname
    is the client's and the check is a single page fetch. It needs the gate
    to pass, and can be turned off with takeover.http_fingerprint: false.

Nothing is ever claimed. Every result is a CANDIDATE with a manual validation
note. subzy is used as an extra source if installed (gated, same reason).

Output: <run>/phase3/takeover.json
"""

import datetime as dt
import os

import common as C

SIG_PATH = os.path.join(C.SKILL_ROOT, "signatures", "takeover_fingerprints.json")
STALE_DAYS = 90


def load_signatures(ctx):
    data = C.read_json(SIG_PATH)
    if not data:
        ctx.module("signatures", "failed", f"cannot read {SIG_PATH}")
        return []
    reviewed = (data.get("_meta") or {}).get("last_reviewed")
    try:
        s = str(reviewed).strip()
        if len(s) == 7:          # "YYYY-MM" — count from the start of that month
            s += "-01"
        age = (dt.date.today() - dt.date.fromisoformat(s[:10])).days
        if age > STALE_DAYS:
            ctx.module("signatures", "degraded",
                       f"last_reviewed {reviewed} ({age} days) — reconcile with can-i-take-over-xyz")
        else:
            ctx.module("signatures", "ran", f"{len(data['signatures'])} services, reviewed {reviewed}")
    except (TypeError, ValueError):
        ctx.module("signatures", "degraded", "no valid _meta.last_reviewed date")
    return data.get("signatures", [])


def match_sig(cnames, sigs):
    for s in sigs:
        for pat in s.get("cname_patterns", []):
            pat = pat.lower().lstrip("*.")
            if any(c == pat or c.endswith("." + pat) or pat in c for c in cnames):
                return s
    return None


def http_evidence(host, sig):
    for scheme in ("https", "http"):
        st, _, body = C.http_get(f"{scheme}://{host}/", timeout=12)
        if st is None:
            continue
        for fp in sig.get("fingerprints", []) if sig else []:
            if fp.lower() in body.lower():
                return {"url": f"{scheme}://{host}/", "status": st, "fingerprint": fp}
        return {"url": f"{scheme}://{host}/", "status": st, "fingerprint": None}
    return None


def severity(sig, evidence_strong):
    if not evidence_strong:
        return None
    if sig is None:
        return "medium"
    return {"vulnerable": "high", "edge": "medium"}.get(sig.get("status"), "low")


def main():
    ap = C.base_argparser("Phase 3 — subdomain-takeover candidate detection")
    args = ap.parse_args()
    ctx = C.open_run(args, 3)
    sigs = load_signatures(ctx)
    assets = C.load_assets(ctx)
    if not assets.get("hosts"):
        ctx.module("takeover", "skipped", "no Phase 1 assets — run 01_passive_enum.py first")
        ctx.finish()
        return

    hosts = {h: r for h, r in assets["hosts"].items() if r.get("passive_ok")}
    checked = C.checked_hosts(ctx, {"hosts": hosts})
    with_cname = {h: c for h, c in checked.items() if c["cnames"]}
    ctx.module("dns", "ran", f"{len(with_cname)} of {len(checked)} hostnames have CNAMEs")

    http_on = (ctx.scope.get("takeover") or {}).get("http_fingerprint", True) is not False
    gate = ctx.gate_passes()
    do_http = http_on and gate
    if not http_on:
        ctx.module("http-fingerprint", "skipped", "takeover.http_fingerprint is false")
    elif not gate:
        ctx.module("http-fingerprint", "skipped",
                   "authorization gate not passed — DNS evidence only")

    candidates = []
    http_count = 0
    for h, c in sorted(with_cname.items()):
        sig = match_sig(c["cnames"], sigs)
        # Dangling = the CNAME chain ends without an address. NXDOMAIN is the
        # classic signal, but many providers answer NOERROR-with-no-data for
        # names that don't exist (e.g. Cloudflare), so "CNAME but no IPs" counts too.
        dangling = c["status"] == "NXDOMAIN" or not c["ips"]
        if not sig and not dangling:
            continue
        ev = None
        if do_http and c["ips"]:
            ev = http_evidence(h, sig)
            http_count += 1
        fp_hit = bool(ev and ev.get("fingerprint"))
        sev = severity(sig, dangling or fp_hit)
        if sev is None:
            continue
        candidates.append({
            "hostname": h, "cnames": c["cnames"], "dns_status": c["status"],
            "service": sig["service"] if sig else "unknown (dangling CNAME)",
            "signature_status": sig.get("status") if sig else None,
            "evidence": {"cname_target_unresolved": dangling,
                         "dns_status": c["status"], "http": ev},
            "severity": sev, "confidence": "candidate",
            "source": "03_takeover" + ("+http" if ev else ""),
            "first_seen": C.iso(),
            "notes": (sig or {}).get("notes", ""),
            "validation": "MANUAL: confirm `dig CNAME " + h + "`, confirm the backing "
                          "resource is genuinely registrable, and only attempt a claim if "
                          "the RoE explicitly allows it. The skill never claims resources.",
        })
    if do_http:
        ctx.audit_note(f"HTTP fingerprint GETs to {http_count} CNAME'd client hostnames")
        ctx.module("http-fingerprint", "ran", f"{http_count} hostnames fetched")

    if C.have("subzy") and do_http and with_cname:
        lst = ctx.path("phase3", "subzy_targets.txt")
        with open(lst, "w") as f:
            f.write("\n".join(sorted(with_cname)) + "\n")
        rc, out = ctx.run(["subzy", "run", "--targets", lst, "--hide_fails"],
                          name="subzy", timeout=1800)
        known = {c["hostname"] for c in candidates}
        for line in out.splitlines():
            if "VULNERABLE" in line.upper():
                host = next((h for h in with_cname if h in line), None)
                if host and host not in known:
                    candidates.append({
                        "hostname": host, "cnames": with_cname[host]["cnames"],
                        "service": "per subzy", "severity": "medium",
                        "confidence": "candidate", "source": "subzy",
                        "evidence": {"subzy_line": line.strip()}, "first_seen": C.iso(),
                        "validation": "MANUAL: verify subzy's claim as above."})
        ctx.module("subzy", "ran" if rc is not None else "failed")
    elif not C.have("subzy"):
        ctx.module("subzy", "skipped", "subzy absent — built-in signature check used")

    rank = {"high": 0, "medium": 1, "low": 2}
    candidates.sort(key=lambda c: (rank.get(c["severity"], 3), c["hostname"]))
    C.write_json(ctx.path("phase3", "takeover.json"),
                 {"generated": C.iso(), "hostnames_checked": len(checked),
                  "with_cname": len(with_cname), "candidates": candidates})
    C.log(f"{len(candidates)} takeover candidates -> phase3/takeover.json", "ok")
    ctx.finish()


if __name__ == "__main__":
    main()
