#!/usr/bin/env python3
"""
05_posture.py — Phase 5: posture checks.

  EMAIL / DNS (passive — DNS lookups via the recursive resolver)
    SPF (presence, qualifier, multiple records, >10 DNS-lookup limit, ptr),
    DMARC (presence, policy, pct, sp, rua), common DKIM selectors (info only —
    absence is not proof), MTA-STS, TLS-RPT, CAA, DNSSEC (DS).

  TLS (GATED — makes real TLS connections)
    Weak protocol support cannot be read from earlier banners; it takes a
    handshake. For each CONFIRMED TLS service from Phase 4 (IP re-checked
    against the matcher), up to ~6 handshakes: one verified (chain + hostname),
    one to read the certificate, one per protocol version TLS1.0..1.3. No
    cipher enumeration, no NSE (nmap's ssl-enum-ciphers is in the "intrusive"
    category, which this skill never runs).

Output: <run>/phase5/posture.json
"""

import os
import re
import socket
import ssl
import subprocess
import tempfile
import warnings
from concurrent.futures import ThreadPoolExecutor

# Testing whether a server still ACCEPTS TLS 1.0/1.1 is the point of the
# check; Python's deprecation warning for those constants is noise here.
warnings.filterwarnings("ignore", category=DeprecationWarning, message=".*TLSv1.*")

import common as C

DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "k2", "s1", "s2",
                  "mail", "dkim", "smtp", "mandrill", "mxvault", "everlytickey1"]
TLS_PORTS = {443, 444, 465, 636, 990, 993, 995, 2083, 2087, 2096, 3269, 3443, 4443, 5001,
             5986, 6443, 7443, 8443, 8883, 9443, 10443}


def finding(sev, domain, title, detail):
    return {"severity": sev, "target": domain, "title": title, "detail": detail,
            "source": "05_posture", "first_seen": C.iso()}


# ----- SPF -------------------------------------------------------------------
def spf_lookups(domain, depth=0, seen=None):
    """Count DNS-querying mechanisms per RFC 7208 §4.6.4, following
    include/redirect. Returns (count, error)."""
    seen = seen if seen is not None else set()
    if depth > 10 or domain in seen:
        return 0, "include loop or excessive depth"
    seen.add(domain)
    recs = [t for t in (C.txt_records(domain) or []) if t.lower().startswith("v=spf1")]
    if not recs:
        return 0, f"included domain {domain} has no SPF" if depth else None
    count = 0
    for term in recs[0].split()[1:]:
        t = term.lstrip("+-~?").lower()
        if t.startswith(("include:", "redirect=")):
            count += 1
            sub = t.split(":", 1)[1] if t.startswith("include:") else t.split("=", 1)[1]
            n, err = spf_lookups(sub, depth + 1, seen)
            count += n
            if err:
                return count, err
        elif t in ("a", "mx", "ptr") or t.startswith(("a:", "a/", "mx:", "mx/", "ptr:", "exists:")):
            count += 1
    return count, None


def check_spf(domain, has_mx):
    out = []
    recs = [t for t in (C.txt_records(domain) or []) if t.lower().startswith("v=spf1")]
    if not recs:
        out.append(finding("medium", domain, "No SPF record",
                           "Anyone can send mail claiming this domain. "
                           + ("Publish an SPF record listing your senders." if has_mx else
                              "Non-mail domain: publish 'v=spf1 -all'.")))
        return out, None
    if len(recs) > 1:
        out.append(finding("medium", domain, "Multiple SPF records",
                           "RFC 7208 permerror — receivers may ignore SPF entirely."))
    spf = recs[0]
    terms = spf.lower().split()
    alls = [t for t in terms if t.endswith("all")]
    q = alls[-1][0] if alls and alls[-1][0] in "+-~?" else ("+" if alls else None)
    if q == "+":
        out.append(finding("high", domain, "SPF allows all senders (+all)", spf))
    elif q == "?":
        out.append(finding("medium", domain, "SPF neutral (?all)", "No enforcement: " + spf))
    elif q == "~":
        out.append(finding("low", domain, "SPF softfail (~all)",
                           "Acceptable with DMARC enforcement; '-all' is stricter."))
    elif q is None and not any(t.startswith("redirect=") for t in terms):
        out.append(finding("medium", domain, "SPF has no 'all' mechanism", spf))
    if any(t.lstrip("+-~?").startswith("ptr") for t in terms):
        out.append(finding("low", domain, "SPF uses deprecated 'ptr' mechanism", spf))
    n, err = spf_lookups(domain)
    if n > 10:
        out.append(finding("medium", domain, f"SPF exceeds 10 DNS lookups ({n})",
                           "RFC 7208 permerror — SPF fails for every message."))
    if err:
        out.append(finding("low", domain, "SPF include problem", err))
    return out, {"record": spf, "lookups": n}


# ----- DMARC -----------------------------------------------------------------
def check_dmarc(domain):
    recs = [t for t in (C.txt_records("_dmarc." + domain) or []) if t.lower().startswith("v=dmarc1")]
    if not recs:
        return [finding("medium", domain, "No DMARC record",
                        "No policy for spoofed mail and no reporting. Start with p=none + rua, "
                        "move to quarantine/reject.")], None
    tags = {}
    for part in recs[0].split(";"):
        k, _, v = part.strip().partition("=")
        if k:
            tags[k.strip().lower()] = v.strip()
    out = []
    p = tags.get("p", "").lower()
    if p not in ("none", "quarantine", "reject"):
        out.append(finding("medium", domain, "DMARC policy missing or invalid", recs[0]))
    elif p == "none":
        out.append(finding("medium", domain, "DMARC policy is p=none (monitor only)",
                           "Spoofed mail is still delivered."))
    try:
        if int(tags.get("pct", "100")) < 100:
            out.append(finding("low", domain, f"DMARC pct={tags['pct']}",
                               "Policy applies to only part of failing mail."))
    except ValueError:
        pass
    if tags.get("sp", "").lower() == "none" and p in ("quarantine", "reject"):
        out.append(finding("low", domain, "DMARC sp=none",
                           "Subdomains are unprotected even though the parent enforces."))
    if "rua" not in tags:
        out.append(finding("low", domain, "DMARC has no rua",
                           "No aggregate reports — spoofing goes unseen."))
    return out, {"record": recs[0], "tags": tags}


def check_extras(domain, has_mx):
    info = {}
    info["dkim_selectors_found"] = [s for s in DKIM_SELECTORS
                                    if any("p=" in t for t in (C.txt_records(f"{s}._domainkey.{domain}") or []))]
    info["mta_sts"] = bool([t for t in (C.txt_records("_mta-sts." + domain) or []) if "v=STSv1" in t])
    info["tls_rpt"] = bool([t for t in (C.txt_records("_smtp._tls." + domain) or []) if "v=TLSRPTv1" in t])
    info["caa"] = C.records(domain, "CAA")
    info["dnssec_ds"] = bool(C.records(domain, "DS"))
    out = []
    if has_mx and not info["mta_sts"]:
        out.append(finding("info", domain, "No MTA-STS", "Inbound SMTP TLS can be downgraded."))
    if not info["caa"]:
        out.append(finding("info", domain, "No CAA record", "Any public CA may issue for this domain."))
    if not info["dnssec_ds"]:
        out.append(finding("info", domain, "DNSSEC not enabled (no DS record)", ""))
    return out, info


# ----- TLS -------------------------------------------------------------------
def _handshake(ip, port, sni, ctx, timeout=8):
    with socket.create_connection((ip, port), timeout=timeout) as s:
        with ctx.wrap_socket(s, server_hostname=sni) as t:
            return t.version(), t.getpeercert(binary_form=True), t.getpeercert()


def cert_details(der):
    if not der or not C.have("openssl"):
        return None
    with tempfile.NamedTemporaryFile(delete=False, suffix=".der") as f:
        f.write(der)
        path = f.name
    try:
        p = subprocess.run(["openssl", "x509", "-inform", "DER", "-in", path, "-noout",
                            "-subject", "-issuer", "-enddate", "-startdate",
                            "-ext", "subjectAltName"], capture_output=True, text=True, timeout=15)
        txt = p.stdout
        p2 = subprocess.run(["openssl", "x509", "-inform", "DER", "-in", path, "-noout",
                             "-checkend", "0"], capture_output=True, text=True, timeout=15)
        p3 = subprocess.run(["openssl", "x509", "-inform", "DER", "-in", path, "-noout",
                             "-checkend", str(30 * 86400)], capture_output=True, text=True, timeout=15)
    finally:
        os.unlink(path)
    get = lambda k: (re.search(rf"(?m)^{k}\s*=?\s*(.+)$", txt) or [None, None])[1]
    sans = re.findall(r"DNS:([^,\s]+)", txt)
    return {"subject": get("subject"), "issuer": get("issuer"), "not_after": get("notAfter"),
            "not_before": get("notBefore"), "sans": sans,
            "expired": p2.returncode != 0, "expires_30d": p3.returncode != 0,
            "self_signed": bool(get("subject")) and get("subject") == get("issuer")}


def check_tls(ip, port, sni):
    res = {"host": ip, "port": port, "sni": sni, "protocols": {}, "verify": None, "cert": None}
    # 1. verified handshake (chain + hostname when we have one)
    vctx = ssl.create_default_context()
    if not sni:
        vctx.check_hostname = False
    try:
        _handshake(ip, port, sni, vctx)
        res["verify"] = "ok"
    except ssl.SSLCertVerificationError as e:
        res["verify"] = e.verify_message or str(e)
    except (OSError, ssl.SSLError) as e:
        res["verify"] = f"handshake failed: {e}"
    # 2. read the cert without trusting it
    nctx = ssl.create_default_context()
    nctx.check_hostname = False
    nctx.verify_mode = ssl.CERT_NONE
    try:
        _, der, _ = _handshake(ip, port, sni, nctx)
        res["cert"] = cert_details(der)
    except (OSError, ssl.SSLError) as e:
        res["error"] = str(e)
        return res
    # 3. protocol versions
    for name, ver in (("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
                      ("TLSv1.2", ssl.TLSVersion.TLSv1_2), ("TLSv1.3", ssl.TLSVersion.TLSv1_3)):
        pctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        pctx.check_hostname = False
        pctx.verify_mode = ssl.CERT_NONE
        try:
            if ver < ssl.TLSVersion.TLSv1_2:
                pctx.set_ciphers("ALL:@SECLEVEL=0")
            pctx.minimum_version = ver
            pctx.maximum_version = ver
        except (ValueError, ssl.SSLError):
            res["protocols"][name] = "untestable (local OpenSSL)"
            continue
        try:
            _handshake(ip, port, sni, pctx)
            res["protocols"][name] = "accepted"
        except ssl.SSLError as e:
            msg = str(e).lower()
            res["protocols"][name] = "untestable (local OpenSSL)" \
                if "no protocols available" in msg or "no_protocols_available" in msg else "rejected"
        except OSError:
            res["protocols"][name] = "rejected"
    return res


def tls_findings(r):
    tgt = f"{r['sni'] or r['host']}:{r['port']}"
    out = []
    c = r.get("cert") or {}
    if c.get("expired"):
        out.append(finding("high", tgt, "TLS certificate expired", f"notAfter {c.get('not_after')}"))
    elif c.get("expires_30d"):
        out.append(finding("medium", tgt, "TLS certificate expires within 30 days",
                           f"notAfter {c.get('not_after')}"))
    v = r.get("verify") or ""
    if v and v != "ok" and not v.startswith("handshake failed"):
        sev = "low" if "hostname mismatch" in v.lower() or "doesn't match" in v.lower() else "medium"
        out.append(finding(sev, tgt, "TLS certificate not trusted", v
                           + (" (self-signed)" if c.get("self_signed")
                              and "self-signed" not in v.lower() else "")))
    weak = [p for p in ("TLSv1.0", "TLSv1.1") if r["protocols"].get(p) == "accepted"]
    if weak:
        out.append(finding("medium", tgt, "Legacy TLS accepted: " + ", ".join(weak),
                           "Disable TLS 1.0/1.1."))
    return out


def main():
    ap = C.base_argparser("Phase 5 — posture checks")
    ap.add_argument("--no-tls", action="store_true", help="skip the (gated) TLS handshakes")
    args = ap.parse_args()
    ctx = C.open_run(args, 5)

    seeds = [d.lower() for d in ((ctx.scope.get("seeds") or {}).get("domains") or [])]
    domains = sorted(set(ctx.matcher.in_domains) | set(seeds))
    findings, email = [], {}
    if not C.have("dig"):
        ctx.module("email-dns", "skipped", "dig absent")
    else:
        ctx.audit_note(f"email/DNS posture lookups for {len(domains)} domains")
        for d in domains:
            has_mx = bool(C.records(d, "MX"))
            f1, spf = check_spf(d, has_mx)
            f2, dmarc = check_dmarc(d)
            f3, extra = check_extras(d, has_mx)
            findings += f1 + f2 + f3
            email[d] = {"has_mx": has_mx, "spf": spf, "dmarc": dmarc, **extra}
        ctx.module("email-dns", "ran", f"{len(domains)} domains")

    tls = []
    if args.no_tls:
        ctx.module("tls", "skipped", "--no-tls")
    elif not ctx.gate_passes():
        ctx.module("tls", "skipped", "authorization gate not passed — TLS checks connect to hosts")
    else:
        recs = (C.read_json(ctx.path("phase4", "services.json"), {}) or {}).get("records", [])
        targets = {}
        for r in recs:
            if r.get("confidence") != "confirmed" or r.get("protocol", "tcp") != "tcp":
                continue
            svc = r.get("service", "")
            if not (svc.startswith("ssl/") or "https" in svc or r["port"] in TLS_PORTS):
                continue
            if not ctx.matcher.is_in_scope(r["host"])[0]:
                C.log(f"skipping {r['host']}: no longer in scope", "warn")
                continue
            for sni in (r.get("hostnames") or [None]):
                targets[(r["host"], r["port"], sni)] = True
        if not recs:
            ctx.module("tls", "skipped", "no Phase 4 results — run 04_active_scan.py first")
        else:
            ctx.audit_note(f"TLS handshakes (<=6 each) to {len(targets)} confirmed TLS endpoints")
            with ThreadPoolExecutor(max_workers=5) as ex:
                tls = list(ex.map(lambda t: check_tls(*t), sorted(targets, key=str)))
            for r in tls:
                findings += tls_findings(r)
            untestable = any("untestable" in v for r in tls for v in r["protocols"].values())
            ctx.module("tls", "degraded" if untestable else "ran",
                       f"{len(tls)} endpoints" + ("; local OpenSSL cannot test some legacy "
                                                  "protocols" if untestable else ""))
    ctx.module("screenshots", "skipped",
               "not automated — run gowitness/aquatone on phase4/web_urls.txt if wanted")
    ctx.module("starttls", "skipped",
               "SMTP/IMAP/POP STARTTLS not tested (needs protocol-specific negotiation)")

    rank = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings.sort(key=lambda f: (rank[f["severity"]], f["target"], f["title"]))
    C.write_json(ctx.path("phase5", "posture.json"),
                 {"generated": C.iso(), "email": email, "tls": tls, "findings": findings})
    C.log(f"{len(findings)} posture findings -> phase5/posture.json", "ok")
    ctx.finish()


if __name__ == "__main__":
    main()
