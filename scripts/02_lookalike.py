#!/usr/bin/env python3
"""
02_lookalike.py — Phase 2: lookalike / phishing-domain detection.

Lookalike domains are THIRD-PARTY infrastructure (often an attacker's), never
the client's. So this phase is DNS / CT / WHOIS only by default — data pulled
from resolvers, registries and CT logs, with no packets sent to the lookalike's
own hosts.

Optional live probe (one HTTP GET per registered lookalike, to spot cloned
login pages) requires BOTH:
  * the Phase 0 gate to pass, and
  * lookalike.live_probe: true in scope.yaml (record the RoE clause that
    permits contacting third-party infrastructure).

Permutations come from dnstwist if installed (never with --mxcheck, which
sends SMTP to the lookalike's mail server), else from a built-in generator.

Output: <run>/phase2/lookalikes.json
"""

import ipaddress
import json
import re
from concurrent.futures import ThreadPoolExecutor

import common as C


def _is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False

QWERTY = {
    "1": "2q", "2": "3wq1", "3": "4ew2", "4": "5re3", "5": "6tr4", "6": "7yt5", "7": "8uy6",
    "8": "9iu7", "9": "0oi8", "0": "po9", "q": "12wa", "w": "3esaq2", "e": "4rdsw3",
    "r": "5tfde4", "t": "6ygfr5", "y": "7uhgt6", "u": "8ijhy7", "i": "9okju8", "o": "0plki9",
    "p": "lo0", "a": "qwsz", "s": "edxzaw", "d": "rfcxse", "f": "tgvcdr", "g": "yhbvft",
    "h": "ujnbgy", "j": "ikmnhu", "k": "olmji", "l": "kop", "z": "asx", "x": "zsdc",
    "c": "xdfv", "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk",
}
HOMOGLYPH = {"o": ["0"], "0": ["o"], "l": ["1", "i"], "i": ["1", "l"], "1": ["l", "i"],
             "m": ["rn", "nn"], "w": ["vv"], "e": ["3"], "a": ["4"], "s": ["5"],
             "g": ["9", "q"], "b": ["d"], "d": ["b", "cl"], "rn": ["m"], "vv": ["w"]}
TLDS = ["com", "net", "org", "co", "io", "info", "biz", "us", "app", "online", "site",
        "xyz", "top", "shop", "cc", "me", "support", "services", "cloud", "live"]
WORDS = ["login", "secure", "account", "support", "portal", "mail", "online", "my",
         "verify", "auth", "sso", "pay", "help", "service", "hr", "web"]
VALID = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def split_domain(domain):
    label, _, suffix = domain.partition(".")
    return label, suffix


def permutations(domain, brand_terms):
    label, suffix = split_domain(domain)
    out = {}

    def add(lbl, fuzzer, sfx=None):
        lbl = lbl.lower()
        if VALID.match(lbl) and "--" not in lbl[2:4]:
            d = f"{lbl}.{sfx or suffix}"
            if d != domain:
                out.setdefault(d, fuzzer)

    n = len(label)
    for i in range(n):
        add(label[:i] + label[i + 1:], "omission")
        add(label[:i] + label[i] + label[i:], "repetition")
        if i < n - 1:
            add(label[:i] + label[i + 1] + label[i] + label[i + 2:], "transposition")
            add(label[:i + 1] + "-" + label[i + 1:], "hyphenation")
        for k in QWERTY.get(label[i], ""):
            add(label[:i] + k + label[i + 1:], "replacement")
            add(label[:i] + k + label[i:], "insertion")
        for g in HOMOGLYPH.get(label[i], []):
            add(label[:i] + g + label[i + 1:], "homoglyph")
        if i < n - 1 and label[i:i + 2] in HOMOGLYPH:
            for g in HOMOGLYPH[label[i:i + 2]]:
                add(label[:i] + g + label[i + 2:], "homoglyph")
        if label[i] in "aeiou":
            for v in "aeiou":
                if v != label[i]:
                    add(label[:i] + v + label[i + 1:], "vowel-swap")
        for bit in range(8):
            c = chr(ord(label[i]) ^ (1 << bit))
            if c.isascii() and (c.isalnum() or c == "-") and c.lower() == c:
                add(label[:i] + c + label[i + 1:], "bitsquatting")
    for c in "abcdefghijklmnopqrstuvwxyz0123456789":
        add(label + c, "addition")
    for t in TLDS:
        add(label, "tld-swap", t)
    for term in sorted({label} | {t.lower() for t in brand_terms}):
        for w in WORDS:
            add(f"{term}-{w}", "dictionary", "com")
            add(f"{w}-{term}", "dictionary", "com")
            add(f"{term}{w}", "dictionary", "com")
        if term != label:
            add(term, "brand-term", "com")
    return out


def dnstwist_perms(ctx, domain):
    rc, out = ctx.run(["dnstwist", "--format", "json", domain], name=f"dnstwist_{domain}",
                      timeout=1800)
    try:
        rows = json.loads(out)
    except ValueError:
        return None
    return {r["domain"]: r.get("fuzzer", "dnstwist") for r in rows
            if r.get("domain") and r.get("domain") != domain}


def check_dns(name):
    if C.have("dig"):
        ns = C.dig(name, "NS")
        if ns["status"] == "NXDOMAIN":
            return None
        a = C.records(name, "A")
        mx = C.records(name, "MX")
        nss = [d.rstrip(".").lower() for _, t, d in ns["answers"] if t == "NS"]
        if ns["status"] != "NOERROR" and not a:
            return None
        return {"a": a, "mx": mx, "ns": nss}
    r = C.resolve(name)
    return {"a": r["ips"], "mx": [], "ns": []} if r["ips"] else None


def main():
    ap = C.base_argparser("Phase 2 — lookalike / phishing-domain detection")
    ap.add_argument("--max-candidates", type=int, default=4000,
                    help="cap on permutations resolved per domain")
    ap.add_argument("--ct-max", type=int, default=40, help="CT lookups for top candidates")
    ap.add_argument("--whois-max", type=int, default=40, help="WHOIS lookups for top candidates")
    args = ap.parse_args()
    ctx = C.open_run(args, 2)

    seeds = [d.lower().rstrip(".") for d in ((ctx.scope.get("seeds") or {}).get("domains") or [])]
    brand = (ctx.scope.get("seeds") or {}).get("brand_terms") or []
    if not seeds:
        ctx.module("lookalike", "skipped", "no seeds.domains in scope.yaml")
        ctx.finish()
        return
    client_ns = set()
    for recs in (C.read_json(ctx.path("phase1", "dns.json"), {}) or {}).values():
        client_ns |= {n.rstrip(".").lower() for n in recs.get("NS", [])}
    own = set(ctx.matcher.in_domains) | set(seeds)

    candidates = {}
    if C.have("dnstwist"):
        for d in seeds:
            p = dnstwist_perms(ctx, d)
            if p is None:
                ctx.module(f"dnstwist-{d}", "degraded", "dnstwist output unparseable; built-in used")
                p = permutations(d, brand)
            for k, v in p.items():
                candidates.setdefault(k, {"fuzzer": v, "target": d})
        ctx.module("permutation", "ran", f"dnstwist: {len(candidates)} candidates")
    else:
        for d in seeds:
            p = dict(list(permutations(d, brand).items())[:args.max_candidates])
            for k, v in p.items():
                candidates.setdefault(k, {"fuzzer": v, "target": d})
        ctx.module("permutation", "degraded",
                   f"dnstwist absent — built-in generator ({len(candidates)} candidates; "
                   "no IDN homoglyphs)")
    for o in own:
        candidates.pop(o, None)

    names = sorted(candidates)
    C.log(f"resolving {len(names)} lookalike candidates (DNS only)")
    ctx.audit_note(f"DNS lookups for {len(names)} lookalike candidates via recursive resolver")
    with ThreadPoolExecutor(max_workers=20) as ex:
        dns = dict(zip(names, ex.map(check_dns, names)))
    reg = {n: dict(candidates[n], **dns[n]) for n in names if dns[n]}
    ctx.module("dns", "ran", f"{len(reg)} of {len(names)} registered")

    for n, r in reg.items():
        in_cidr = any(ctx.matcher._ip_included(ipaddress.ip_address(ip))
                      for ip in r["a"] if _is_ip(ip))
        r["client_owned_hint"] = bool(in_cidr or (client_ns and set(r["ns"]) & client_ns))

    # rank before the capped enrichment so the budget goes to the riskiest
    order = sorted(reg, key=lambda n: (not reg[n]["mx"], not reg[n]["a"], n))
    for n in order[:args.ct_max]:
        ctx.api_pace()
        data = C.http_get_json(f"https://crt.sh/?q={n}&output=json", timeout=60, retries=1)
        reg[n]["ct_certs"] = len(data) if isinstance(data, list) else None
        reg[n]["ct_latest"] = max((c.get("not_before", "") for c in data), default=None) \
            if isinstance(data, list) and data else None
    ctx.audit_note(f"crt.sh lookups for {min(len(order), args.ct_max)} lookalikes")
    ctx.module("ct-enrichment", "ran" if len(order) <= args.ct_max else "degraded",
               f"{min(len(order), args.ct_max)} of {len(order)} checked (--ct-max)")

    if C.have("whois"):
        for n in order[:args.whois_max]:
            rc, out = ctx.run(["whois", n], name=f"whois_{n}", timeout=60)
            m = re.search(r"(?im)^\s*(?:creation date|created|registered on)\s*:\s*(\S+)", out)
            reg[n]["created"] = m.group(1) if m else None
            m = re.search(r"(?im)^\s*registrar\s*:\s*(.+)$", out)
            reg[n]["registrar"] = m.group(1).strip() if m else None
        ctx.module("whois", "ran" if len(order) <= args.whois_max else "degraded",
                   f"{min(len(order), args.whois_max)} of {len(order)} (--whois-max)")
    else:
        ctx.module("whois", "skipped", "whois absent")

    live_cfg = bool((ctx.scope.get("lookalike") or {}).get("live_probe"))
    if not live_cfg:
        ctx.module("live-probe", "skipped",
                   "lookalike.live_probe is false — lookalikes are third-party hosts")
    elif not ctx.gate_passes():
        ctx.module("live-probe", "skipped", "authorization gate not passed")
    else:
        targets = [n for n in order if reg[n]["a"] and not reg[n]["client_owned_hint"]]
        ctx.audit_note(f"live HTTP probe of {len(targets)} third-party lookalike domains "
                       "(lookalike.live_probe: true)")
        for n in targets:
            for scheme in ("https", "http"):
                st, _, body = C.http_get(f"{scheme}://{n}/", timeout=10)
                if st:
                    reg[n]["live"] = {"url": f"{scheme}://{n}/", "status": st,
                                      "title": C.html_title(body)}
                    break
        ctx.module("live-probe", "ran", f"{len(targets)} probed")

    for n, r in reg.items():
        if r.get("client_owned_hint"):
            r["risk"] = "info"
            r["risk_reason"] = "likely client-owned (defensive registration) — confirm"
            continue
        has_cert = bool(r.get("ct_certs"))
        live = bool(r.get("live"))
        if r["mx"] and (has_cert or live):
            r["risk"] = "high"
        elif r["mx"] or has_cert or live:
            r["risk"] = "medium"
        else:
            r["risk"] = "low"
        r["risk_reason"] = ", ".join(x for x, ok in (("MX", r["mx"]), ("cert", has_cert),
                                                     ("live page", live)) if ok) or "registered only"
    rank = {"high": 0, "medium": 1, "low": 2, "info": 3}
    rows = [dict(domain=n, **reg[n]) for n in sorted(reg, key=lambda n: (rank[reg[n]["risk"]], n))]
    C.write_json(ctx.path("phase2", "lookalikes.json"),
                 {"generated": C.iso(), "candidates_checked": len(names),
                  "registered": len(rows), "lookalikes": rows})
    hi = sum(1 for r in rows if r["risk"] == "high")
    C.log(f"{len(rows)} registered lookalikes ({hi} high risk) -> phase2/lookalikes.json", "ok")
    ctx.finish()


if __name__ == "__main__":
    main()
