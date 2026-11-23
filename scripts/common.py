#!/usr/bin/env python3
"""
common.py — shared plumbing for the phase scripts (01..06).

Everything a phase needs that is not phase-specific lives here:
  * RunContext   — the run directory, scope, matcher, status ledger, audit log
  * run()        — execute an external tool, logging the exact command (audit)
  * dns helpers  — resolve A/AAAA with the CNAME chain and NXDOMAIN status
  * http_probe() — minimal stdlib HTTP(S) fetch (used when PD httpx is absent)
  * json helpers — atomic read/write

Conventions every phase follows:
  * Every external command is appended to <run>/commands.log (JSONL) with its
    timestamp, phase, argv, exit code and duration. That file is the audit trail
    of what actually touched the network.
  * Every module records ran / degraded / skipped (+ reason) in
    <run>/status.json. Phase 6 turns that into "Intelligence gaps".
  * Host-touching phases call ctx.require_gate() first. It re-runs the full
    Phase 0 gate (window, rates, duration) every time, so a phase started after
    the window closes is refused.
"""

import datetime as _dt
import hashlib
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import yaml  # noqa: E402  (scope_gate already enforces PyYAML presence)
import scope_gate  # noqa: E402

SKILL_ROOT = os.path.dirname(HERE)
USER_AGENT = "external-attack-surface-recon (authorized assessment)"
_lock = threading.Lock()

# Run output is sensitive client data: everything this process creates is
# owner-only (dirs 0700, files 0600).
os.umask(0o077)

# ----- abort machinery -------------------------------------------------------
# Tools run in their own process group (so a timeout can kill helpers too).
# The flip side: Ctrl-C reaches only Python, not the tools. So every live child
# is tracked here and killed explicitly on any abort.
_ACTIVE = set()
_ABORT = {"reason": None}


def kill_children():
    import signal
    with _lock:
        procs = list(_ACTIVE)
    for p in procs:
        try:
            if hasattr(os, "killpg"):
                os.killpg(p.pid, signal.SIGKILL)
            else:
                p.kill()
        except (ProcessLookupError, PermissionError, OSError):
            pass


def install_abort_handlers(ctx):
    """SIGINT/SIGTERM: kill every running tool, record the abort in
    status.json, exit 4. The watchdog triggers the same path."""
    import signal

    def handler(signum, frame):
        reason = _ABORT["reason"] or ("Ctrl-C" if signum == signal.SIGINT else f"signal {signum}")
        kill_children()
        try:
            ctx.module("ABORT", "aborted", reason)
            ctx.finish()
        finally:
            log(f"ABORTED: {reason}. Running tools were killed. Results so far are in "
                f"{ctx.run_dir}; Phase 6 will report this phase as incomplete.", "err")
            os._exit(4)

    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)


def start_watchdog(ctx, interval=2.0):
    """
    Background thread that aborts the phase when either:
      * <run>/STOP exists (operator kill switch: `touch <run>/STOP`), or
      * the engagement window has ended (authorization expired mid-scan).
    """
    import signal
    end, _ = scope_gate._parse_dt(((ctx.scope.get("engagement") or {}).get("window") or {}).get("end"))
    stop = ctx.path("STOP")

    def loop():
        while True:
            reason = None
            if os.path.exists(stop):
                reason = f"STOP file present ({stop})"
            elif end and utcnow() > end:
                reason = f"engagement window ended at {end.isoformat()}"
            if reason:
                _ABORT["reason"] = reason
                kill_children()
                os.kill(os.getpid(), signal.SIGTERM)
                return
            time.sleep(interval)

    if os.path.exists(stop):
        log(f"STOP file present in run directory — remove {stop} to run this phase.", "err")
        sys.exit(4)
    threading.Thread(target=loop, daemon=True).start()


# ----- time ------------------------------------------------------------------
def utcnow():
    return _dt.datetime.now(_dt.timezone.utc)


def iso(dt=None):
    return (dt or utcnow()).strftime("%Y-%m-%dT%H:%M:%SZ")


# ----- json ------------------------------------------------------------------
def read_json(path, default=None):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def write_json(path, data):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=False, default=str)
    os.replace(tmp, path)


def log(msg, level="info"):
    prefix = {"info": "[*]", "ok": "[+]", "warn": "[!]", "err": "[x]"}.get(level, "[*]")
    print(f"{prefix} {msg}", file=sys.stderr if level in ("warn", "err") else sys.stdout,
          flush=True)


# ----- tools -----------------------------------------------------------------
def have(tool):
    return shutil.which(tool) is not None


_PD_HTTPX = None


def pd_httpx():
    """True only if `httpx` on PATH is ProjectDiscovery's binary, not the
    Python library's CLI (which shares the name and takes different flags)."""
    global _PD_HTTPX
    if _PD_HTTPX is None:
        _PD_HTTPX = False
        if have("httpx"):
            try:
                out = subprocess.run(["httpx", "-version"], capture_output=True,
                                     text=True, timeout=20)
                blob = (out.stdout + out.stderr).lower()
                _PD_HTTPX = "projectdiscovery" in blob or "current version" in blob
            except (OSError, subprocess.TimeoutExpired):
                pass
    return _PD_HTTPX


def is_root():
    return hasattr(os, "geteuid") and os.geteuid() == 0


def is_wsl():
    try:
        with open("/proc/version", "r") as f:
            return "microsoft" in f.read().lower()
    except OSError:
        return False


# ----- run context -----------------------------------------------------------
class RunContext:
    def __init__(self, scope_path, run_dir, phase):
        self.scope_path = os.path.abspath(scope_path)
        self.run_dir = os.path.abspath(run_dir)
        self.phase = str(phase)
        with open(self.scope_path, "r", encoding="utf-8") as f:
            self.scope = yaml.safe_load(f) or {}
        self.matcher = scope_gate.InScope(self.scope)
        eng = self.scope.get("engagement") or {}
        self.engagement_id = str(eng.get("id") or "UNSET")
        rate = self.scope.get("rate") or {}
        self.masscan_rate = scope_gate._as_int(rate.get("masscan_max_rate")) \
            or scope_gate.MASSCAN_RATE_DEFAULT
        t = str(rate.get("nmap_timing") or scope_gate.NMAP_TIMING_DEFAULT).upper().lstrip("-")
        self.nmap_timing = t if t.startswith("T") else "T" + t
        self.workers = scope_gate._as_int(rate.get("parallel_workers")) or 1
        self.nmap_min_rate = scope_gate._as_int(rate.get("nmap_min_rate"))
        qps = rate.get("passive_api_qps") or 1
        try:
            self.api_interval = 1.0 / max(float(qps), 0.01)
        except (TypeError, ValueError):
            self.api_interval = 1.0
        self._last_api = 0.0
        os.makedirs(self.path("raw"), exist_ok=True)
        os.makedirs(self.phase_dir(), exist_ok=True)
        self._phase_start()

    # paths
    def path(self, *parts):
        return os.path.join(self.run_dir, *parts)

    def phase_dir(self, phase=None):
        return self.path(f"phase{phase or self.phase}")

    # status ledger
    def _status(self):
        return read_json(self.path("status.json"), {"phases": {}})

    def _save_status(self, st):
        write_json(self.path("status.json"), st)

    def _phase_start(self):
        with _lock:
            st = self._status()
            st["phases"][self.phase] = {"started": iso(), "finished": None, "modules": {}}
            self._save_status(st)

    def module(self, name, state, detail=""):
        """state: ran | degraded | skipped | failed"""
        with _lock:
            st = self._status()
            ph = st["phases"].setdefault(self.phase, {"modules": {}})
            ph["modules"][name] = {"state": state, "detail": detail, "at": iso()}
            self._save_status(st)
        level = {"ran": "ok", "degraded": "warn", "skipped": "warn", "failed": "err",
                 "aborted": "err"}[state]
        log(f"{name}: {state}" + (f" — {detail}" if detail else ""), level)

    def finish(self):
        with _lock:
            st = self._status()
            st["phases"].setdefault(self.phase, {})["finished"] = iso()
            self._save_status(st)

    # gate
    def require_gate(self):
        passed, report = scope_gate.validate(self.scope_path)
        if not passed:
            log("authorization gate FAILED — this phase touches hosts and will not run:", "err")
            for r in report["reasons"]:
                log(f"  - {r}", "err")
            self.module("phase", "skipped", "authorization gate failed: "
                        + "; ".join(report["reasons"]))
            self.finish()
            sys.exit(2)
        return report

    def gate_passes(self):
        return scope_gate.validate(self.scope_path)[0]

    # passive API pacing (rate.passive_api_qps)
    def api_pace(self):
        with _lock:
            wait = self._last_api + self.api_interval - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            self._last_api = time.monotonic()

    # external commands
    def run(self, argv, name=None, timeout=600, stdin_text=None):
        """
        Run an external tool. Logs the exact argv to commands.log, saves stdout
        and stderr to raw/<name>.out/.err. Returns (rc, stdout); rc is None if
        the tool could not be started or timed out.
        """
        name = name or os.path.basename(argv[0])
        start = time.monotonic()
        rec = {"ts": iso(), "phase": self.phase, "argv": argv}
        # Log the START too: if the phase is aborted mid-command, the audit
        # trail still shows what was running and since when.
        with _lock, open(self.path("commands.log"), "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": rec["ts"], "phase": self.phase, "event": "start",
                                "argv": argv}) + "\n")
        self.last_timed_out = False
        try:
            # Own process group, so a timeout kills the tool AND anything it
            # spawned (amass, for one, leaves helper processes behind).
            p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 stdin=subprocess.PIPE if stdin_text is not None else subprocess.DEVNULL,
                                 text=True, errors="replace",
                                 start_new_session=hasattr(os, "killpg"))
            with _lock:
                _ACTIVE.add(p)
            try:
                out, err = p.communicate(input=stdin_text, timeout=timeout)
                rc = p.returncode
                if _ABORT["reason"]:
                    err = (err or "") + f"\nkilled: {_ABORT['reason']}"
            except subprocess.TimeoutExpired:
                if hasattr(os, "killpg"):
                    try:
                        os.killpg(p.pid, 9)
                    except (ProcessLookupError, PermissionError):
                        pass
                else:
                    p.kill()
                out, err = p.communicate()
                rc = None
                self.last_timed_out = True
                err = (err or "") + f"\ntimed out after {timeout}s (process group killed)"
            finally:
                with _lock:
                    _ACTIVE.discard(p)
        except FileNotFoundError:
            rc, out, err = None, "", f"not found: {argv[0]}"
        rec.update(rc=rc, seconds=round(time.monotonic() - start, 1),
                   timed_out=self.last_timed_out)
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", name)[:120]
        with open(self.path("raw", f"p{self.phase}_{safe}.out"), "w", encoding="utf-8") as f:
            f.write(out or "")
        if err:
            with open(self.path("raw", f"p{self.phase}_{safe}.err"), "w", encoding="utf-8") as f:
                f.write(err)
        with _lock, open(self.path("commands.log"), "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
        return rc, out or ""

    def audit_note(self, what):
        """Record a network action that is not an external command (stdlib HTTP,
        DNS bursts) so commands.log stays a complete account of traffic."""
        with _lock, open(self.path("commands.log"), "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": iso(), "phase": self.phase, "note": what}) + "\n")


def open_run(args, phase, create=False):
    """
    Resolve the run directory from --run-dir. Phase 1 may create a new one
    (create=True); every later phase must be pointed at an existing run so
    results from different runs never mix.
    """
    if args.run_dir:
        run_dir = args.run_dir
        if not os.path.isdir(run_dir) and not create:
            log(f"run directory not found: {run_dir}", "err")
            sys.exit(3)
    elif create:
        with open(args.scope, "r", encoding="utf-8") as f:
            scope = yaml.safe_load(f) or {}
        base = (scope.get("output") or {}).get("dir") or "./runs"
        eid = re.sub(r"[^A-Za-z0-9._-]+", "_",
                     str((scope.get("engagement") or {}).get("id") or "run"))
        run_dir = os.path.join(base, f"{eid}_{utcnow().strftime('%Y%m%dT%H%M%SZ')}")
    else:
        log("--run-dir is required for this phase (use the directory Phase 1 created)", "err")
        sys.exit(3)
    os.makedirs(run_dir, exist_ok=True)
    # Keep client data out of version control even if the output dir sits in a repo.
    base_dir = os.path.dirname(os.path.abspath(run_dir))
    gi = os.path.join(base_dir, ".gitignore")
    if not os.path.exists(gi):
        try:
            with open(gi, "w") as f:
                f.write("# engagement output: sensitive client data — never commit\n*\n")
        except OSError:
            pass
    snap = os.path.join(run_dir, "scope_snapshot.yaml")
    with open(args.scope, "rb") as f:
        blob = f.read()
    digest = hashlib.sha256(blob).hexdigest()
    if not os.path.exists(snap):
        with open(snap, "wb") as f:
            f.write(blob)
        write_json(os.path.join(run_dir, "scope_snapshot.sha256.json"),
                   {"sha256": digest, "source": os.path.abspath(args.scope), "at": iso()})
    else:
        prev = (read_json(os.path.join(run_dir, "scope_snapshot.sha256.json"), {}) or {}).get("sha256")
        if prev and prev != digest:
            log("scope.yaml has CHANGED since this run started. Start a new run "
                "(omit --run-dir in Phase 1) so the report matches one authorization.", "err")
            sys.exit(3)
    return RunContext(args.scope, run_dir, phase)


def base_argparser(desc):
    import argparse
    ap = argparse.ArgumentParser(description=desc)
    ap.add_argument("--scope", default="scope.yaml", help="path to scope.yaml")
    ap.add_argument("--run-dir", help="run directory (created by Phase 1)")
    return ap


# ----- DNS -------------------------------------------------------------------
_DIG_LINE = re.compile(r"^(\S+)\s+\d+\s+IN\s+(\S+)\s+(.+)$")


def dig(name, rtype="A", server=None, timeout=5):
    """
    Query via dig. Returns {"status": "NOERROR"/"NXDOMAIN"/..., "answers":
    [(owner, type, data), ...]}. status "ERROR" if dig failed to run.
    """
    argv = ["dig", "+noall", "+comments", "+answer", f"+time={timeout}", "+tries=2",
            name, rtype]
    if server:
        argv.insert(1, "@" + server)
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout * 3 + 5)
    except (OSError, subprocess.TimeoutExpired):
        return {"status": "ERROR", "answers": []}
    status, answers = "ERROR", []
    for line in p.stdout.splitlines():
        m = re.search(r"status:\s*([A-Z]+)", line)
        if m:
            status = m.group(1)
            continue
        if line.startswith(";") or not line.strip():
            continue
        m = _DIG_LINE.match(line.strip())
        if m:
            answers.append((m.group(1).rstrip(".").lower(), m.group(2).upper(),
                            m.group(3).strip()))
    return {"status": status, "answers": answers}


def resolve(name):
    """
    Resolve a hostname. Returns {"ips": [...], "cnames": [...], "status": str}.
    Uses dig (keeps the CNAME chain); falls back to the system resolver.
    """
    name = name.rstrip(".").lower()
    if have("dig"):
        a = dig(name, "A")
        aaaa = dig(name, "AAAA")
        cnames, ips = [], []
        for r in (a, aaaa):
            for owner, t, data in r["answers"]:
                if t == "CNAME":
                    tgt = data.rstrip(".").lower()
                    if tgt not in cnames:
                        cnames.append(tgt)
                elif t in ("A", "AAAA") and data not in ips:
                    ips.append(data)
        status = a["status"] if a["status"] != "ERROR" else aaaa["status"]
        return {"ips": ips, "cnames": cnames, "status": status}
    try:
        infos = socket.getaddrinfo(name, None)
        ips = sorted({i[4][0] for i in infos})
        return {"ips": ips, "cnames": [], "status": "NOERROR"}
    except socket.gaierror:
        return {"ips": [], "cnames": [], "status": "NXDOMAIN"}


def _dig_batch(names, rtype, timeout=5):
    """
    Resolve many names with ONE dig process (dig -f). Returns
    {name: {"status": str, "answers": [(owner, type, data), ...]}}.
    Each query in dig's batch output starts with a ->>HEADER<<- line (status)
    followed by the question line, so the output is parsed block by block.
    """
    import tempfile
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as f:
        for n in names:
            f.write(f"{n} {rtype}\n")
        path = f.name
    try:
        p = subprocess.run(["dig", "+noall", "+comments", "+question", "+answer",
                            f"+time={timeout}", "+tries=2", "-f", path],
                           capture_output=True, text=True,
                           timeout=max(120, len(names) * timeout), errors="replace")
        text = p.stdout
    except (OSError, subprocess.TimeoutExpired):
        text = ""
    finally:
        os.unlink(path)
    out, cur, status = {}, None, "ERROR"
    for line in text.splitlines():
        m = re.search(r"->>HEADER<<-.*status:\s*([A-Z]+)", line)
        if m:
            status, cur = m.group(1), None
            continue
        m = re.match(r"^;([^;\s]\S*)\s+IN\s+(\S+)\s*$", line.strip())
        if m:
            cur = m.group(1).rstrip(".").lower()
            out[cur] = {"status": status, "answers": []}
            continue
        if cur and line and not line.startswith(";"):
            m = _DIG_LINE.match(line.strip())
            if m:
                out[cur]["answers"].append((m.group(1).rstrip(".").lower(), m.group(2).upper(),
                                            m.group(3).strip()))
    return out


def resolve_many(names, chunk=400, procs=6):
    """Bulk version of resolve(): batches through dig -f in parallel chunks.
    Names dig didn't answer for fall back to resolve() one at a time."""
    from concurrent.futures import ThreadPoolExecutor
    names = sorted({n.rstrip(".").lower() for n in names})
    if not have("dig") or len(names) < 20:
        with ThreadPoolExecutor(max_workers=10) as ex:
            return dict(zip(names, ex.map(resolve, names)))
    chunks = [names[i:i + chunk] for i in range(0, len(names), chunk)]
    res = {}
    for rtype in ("A", "AAAA"):
        with ThreadPoolExecutor(max_workers=procs) as ex:
            for part in ex.map(lambda c: _dig_batch(c, rtype), chunks):
                for n, r in part.items():
                    res.setdefault(n, {}).update({rtype: r})
    out, missing = {}, []
    for n in names:
        r = res.get(n)
        if not r or "A" not in r or "AAAA" not in r:
            missing.append(n)
            continue
        cnames, ips = [], []
        for rr in (r["A"], r["AAAA"]):
            for owner, t, data in rr["answers"]:
                if t == "CNAME":
                    tgt = data.rstrip(".").lower()
                    if tgt not in cnames:
                        cnames.append(tgt)
                elif t in ("A", "AAAA") and data not in ips:
                    ips.append(data)
        out[n] = {"ips": ips, "cnames": cnames,
                  "status": r["A"]["status"] if r["A"]["status"] != "ERROR" else r["AAAA"]["status"]}
    if missing:
        with ThreadPoolExecutor(max_workers=10) as ex:
            out.update(zip(missing, ex.map(resolve, missing)))
    return out


def txt_records(name):
    if not have("dig"):
        return None
    r = dig(name, "TXT")
    out = []
    for _, t, data in r["answers"]:
        if t == "TXT":
            # join split strings: "v=spf1 ..." "more"
            out.append("".join(re.findall(r'"((?:[^"\\]|\\.)*)"', data)) or data)
    return out


def records(name, rtype):
    if not have("dig"):
        return []
    return [d for _, t, d in dig(name, rtype)["answers"] if t == rtype.upper()]


# ----- HTTP ------------------------------------------------------------------
def http_get(url, timeout=15, max_bytes=65536, headers=None):
    """GET a URL with the stdlib. Returns (status, headers_dict, body_text) or
    (None, {}, error_string). TLS verification is OFF: we're fingerprinting,
    not trusting, and misconfigured certs are common on exactly these hosts."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, dict(r.headers), r.read(max_bytes).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            body = e.read(max_bytes).decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, dict(e.headers or {}), body
    except Exception as e:  # URLError, timeout, ssl errors, resets
        return None, {}, f"{type(e).__name__}: {e}"


def http_get_json(url, timeout=60, retries=2):
    for attempt in range(retries + 1):
        status, _, body = http_get(url, timeout=timeout, max_bytes=50 * 1024 * 1024,
                                   headers={"Accept": "application/json"})
        if status == 200:
            try:
                return json.loads(body)
            except json.JSONDecodeError:
                return None
        time.sleep(2 * (attempt + 1))
    return None


def html_title(body):
    m = re.search(r"<title[^>]*>(.*?)</title>", body or "", re.I | re.S)
    return re.sub(r"\s+", " ", m.group(1)).strip()[:200] if m else ""


# ----- assets ----------------------------------------------------------------
# ----- CDN detection ---------------------------------------------------------
# Providers that publish their edge ranges. Akamai, Azure Front Door, Imperva
# and others don't publish a stable public list, so they are still detected by
# CNAME name (CDN_CNAME_HINTS) — recorded as heuristic.
CDN_SOURCES = {
    "Cloudflare": ["https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"],
    "Fastly": ["https://api.fastly.com/public-ip-list"],
    "Amazon CloudFront": ["https://ip-ranges.amazonaws.com/ip-ranges.json"],
}
CDN_CNAME_HINTS = {
    "cloudfront.net": "Amazon CloudFront", "akamaiedge.net": "Akamai", "akamai.net": "Akamai",
    "edgekey.net": "Akamai", "edgesuite.net": "Akamai", "akamaized.net": "Akamai",
    "fastly.net": "Fastly", "fastlylb.net": "Fastly", "cdn.cloudflare.net": "Cloudflare",
    "cloudflare.net": "Cloudflare", "azureedge.net": "Azure CDN", "azurefd.net": "Azure Front Door",
    "b-cdn.net": "Bunny CDN", "cdn77.org": "CDN77", "incapdns.net": "Imperva",
    "impervadns.net": "Imperva", "edgecastcdn.net": "Edgecast", "llnwd.net": "Limelight",
    "stackpathdns.com": "StackPath", "sucuri.net": "Sucuri",
}


def cdn_ranges(ctx):
    """
    Fetch published CDN edge ranges (public data from the providers — nothing
    is sent to any target). Cached per run in phase4/cdn_ranges.json. Returns
    ({provider: [ip_network, ...]}, [provider failures]).
    """
    import ipaddress
    cache = ctx.path("phase4", "cdn_ranges.json")
    raw = read_json(cache)
    failed = []
    if not raw:
        raw = {}
        for prov, urls in CDN_SOURCES.items():
            nets = []
            for u in urls:
                ctx.audit_note(f"fetch published CDN ranges: {u}")
                st, _, body = http_get(u, timeout=30, max_bytes=20 * 1024 * 1024)
                if st != 200:
                    continue
                if u.endswith(".json"):          # AWS
                    try:
                        j = json.loads(body)
                        nets += [p["ip_prefix"] for p in j.get("prefixes", []) if p.get("service") == "CLOUDFRONT"]
                        nets += [p["ipv6_prefix"] for p in j.get("ipv6_prefixes", []) if p.get("service") == "CLOUDFRONT"]
                    except (ValueError, KeyError):
                        pass
                elif "fastly" in u:
                    try:
                        j = json.loads(body)
                        nets += j.get("addresses", []) + j.get("ipv6_addresses", [])
                    except ValueError:
                        pass
                else:
                    nets += [l.strip() for l in body.splitlines() if l.strip()]
            if nets:
                raw[prov] = sorted(set(nets))
            else:
                failed.append(prov)
        write_json(cache, raw)
    out = {}
    for prov, nets in raw.items():
        parsed = []
        for n in nets:
            try:
                parsed.append(ipaddress.ip_network(n, strict=False))
            except ValueError:
                pass
        out[prov] = parsed
    return out, failed


def cdn_for_ip(ranges, ip):
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for prov, nets in ranges.items():
        if any(a.version == n.version and a in n for n in nets):
            return prov
    return None


def cdn_for_cnames(cnames):
    for c in cnames or []:
        for hint, prov in CDN_CNAME_HINTS.items():
            if c == hint or c.endswith("." + hint):
                return prov
    return None


def load_assets(ctx):
    return read_json(ctx.path("phase1", "assets.json"), {"hosts": {}, "generated": None})


def checked_hosts(ctx, assets, reresolve=True):
    """
    Re-resolve every Phase 1 hostname NOW and run the active scope check.
    Returns {host: {"ips": [...], "cnames": [...], "ok": bool, "reason": str}}.
    Phases 3-5 use this rather than Phase 1's stale answers, because DNS can
    change between phases.
    """
    hosts = sorted(assets.get("hosts", {}))
    if reresolve and hosts:
        ctx.audit_note(f"DNS re-resolution of {len(hosts)} hostnames for active scope check")
        resolved = resolve_many(hosts)
    else:
        resolved = {h: {"ips": r.get("ips", []), "cnames": r.get("cnames", []),
                        "status": r.get("dns_status", "")}
                    for h, r in assets.get("hosts", {}).items()}
    out = {}
    for h in hosts:
        r = resolved.get(h) or {"ips": [], "cnames": [], "status": "ERROR"}
        ok, why = ctx.matcher.is_in_scope(h, resolved_ips=r["ips"], active=True)
        out[h] = {"ips": r["ips"], "cnames": r["cnames"], "status": r["status"],
                  "ok": ok, "reason": why}
    return out
