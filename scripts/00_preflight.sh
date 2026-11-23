#!/usr/bin/env bash
#
# 00_preflight.sh — environment readiness check for external-attack-surface-recon.
#
# Order matters:
#   1. Core tooling (python3 + PyYAML first: the gate itself needs them).
#   2. Scan privileges (masscan raw sockets; nmap SYN vs connect scan).
#   3. The Phase 0 authorization gate (scope_gate.py), only once it can run.
#   4. Recommended / optional tools, data-source API keys, environment quirks
#      (Kali's amass wrapper, WSL2 networking mode).
#
# A missing OPTIONAL tool disables only its module; the phase scripts fall back
# where they can and record the reason. This script performs NO scanning and
# sends nothing to any target — it only inspects the local machine.
#
# Usage:  ./00_preflight.sh [--scope path/to/scope.yaml]      (default ./scope.yaml)
# Exit:   0 = core tooling present (gate result is reported, not fatal)
#         1 = core tooling missing
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCOPE="./scope.yaml"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --scope) SCOPE="$2"; shift 2 ;;
    *) echo "unknown arg: $1"; exit 1 ;;
  esac
done

bold() { printf "\033[1m%s\033[0m\n" "$*"; }
ok()   { printf "  \033[32m[ok]\033[0m    %s\n" "$*"; }
warn() { printf "  \033[33m[warn]\033[0m  %s\n" "$*"; }
miss() { printf "  \033[31m[miss]\033[0m  %s\n" "$*"; }
info() { printf "  [info]  %s\n" "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

DEGRADED=()
CORE_OK=true
PY_OK=false

# ----- 1. core tooling -------------------------------------------------------
bold "== Core tooling =="
if have python3; then
  ok "python3 ($(python3 -c 'import sys; print(sys.version.split()[0])'))"
  if python3 -c "import yaml" 2>/dev/null; then
    ok "python yaml module"; PY_OK=true
  else
    miss "python yaml (apt install python3-yaml, or pip install pyyaml --break-system-packages)"
    CORE_OK=false
  fi
else
  miss "python3 (required — every phase script and the gate are Python)"; CORE_OK=false
fi
for t in dig nmap masscan; do
  if have "$t"; then ok "$t"; else miss "$t (required)"; CORE_OK=false; fi
done
if have openssl; then ok "openssl"; else
  warn "openssl absent — Phase 5 certificate details degraded"; DEGRADED+=("Phase 5 certificate details"); fi
echo

# ----- 2. scan privileges ----------------------------------------------------
bold "== Scan privileges =="
if [[ $(id -u) -eq 0 ]]; then
  ok "running as root — masscan raw sockets and nmap SYN scan (-sS) available"
else
  if have masscan && have getcap && getcap "$(command -v masscan)" 2>/dev/null | grep -q cap_net_raw; then
    ok "masscan has cap_net_raw — Phase 4 can run without root"
  elif have masscan; then
    miss "masscan has no raw-socket privileges — Phase 4 will refuse to run."
    echo "        Run Phase 4 as root, or once:  sudo setcap cap_net_raw,cap_net_admin=eip \$(command -v masscan)"
  fi
  info "not root: nmap will use a connect scan (-sT) — slower and more visible in target logs"
  warn "not root: the Phase 4 UDP pass (nmap -sU) will be skipped — UDP 53/123/161/500/4500/... not covered"
  DEGRADED+=("Phase 4 UDP pass (needs root)")
fi
echo

# ----- 3. authorization gate -------------------------------------------------
bold "== Phase 0: authorization gate =="
GATE_RC=3
if [[ "$PY_OK" != true ]]; then
  miss "cannot run the gate until python3 + PyYAML are installed (see above)"
elif [[ ! -f "$SCOPE" ]]; then
  miss "scope file not found: $SCOPE"
  echo "        Copy scope.yaml.example to scope.yaml and fill it in."
else
  python3 "${SCRIPT_DIR}/scope_gate.py" --scope "$SCOPE"
  GATE_RC=$?
fi
echo

# ----- 4. recommended tools --------------------------------------------------
bold "== Recommended tooling (module degrades or falls back if absent) =="
check_tool() {  # name  purpose  fallback-text
  if have "$1"; then ok "$1 — $2"; else warn "$1 absent — $2: $3"; DEGRADED+=("$2"); fi
}
check_tool subfinder   "Phase 1 subdomain sources"      "fewer names"
check_tool amass       "Phase 1 subdomain sources"      "fewer names"
check_tool assetfinder "Phase 1 subdomain sources"      "fewer names"
check_tool whois       "Phase 1/2 WHOIS"                "no registrar/creation dates"
check_tool dnstwist    "Phase 2 permutations"           "built-in generator used (no IDN homoglyphs)"
check_tool subzy       "Phase 3 extra takeover source"  "built-in signature check only"
check_tool whatweb     "Phase 4 tech fingerprint"       "skipped"

# ProjectDiscovery httpx vs the Python 'httpx' library's CLI (same name).
# PD's prints "Current Version"; the Python CLI rejects -version.
if have httpx && httpx -version 2>&1 | grep -qiE "projectdiscovery|current version"; then
  ok "httpx (ProjectDiscovery) — Phase 4 web probe"
elif have httpx; then
  warn "'httpx' on PATH is NOT ProjectDiscovery's (likely the Python library) — Phase 4 uses"
  warn "  a basic stdlib probe instead. Install PD httpx: go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
  DEGRADED+=("Phase 4 web probe (stdlib fallback)")
else
  warn "httpx absent — Phase 4 uses a basic stdlib probe"; DEGRADED+=("Phase 4 web probe (stdlib fallback)")
fi

# Kali's /usr/bin/amass is a wrapper that runs `sudo libpostal_data download`
# on first use when the libpostal data is missing. Unattended, that sudo fails
# and amass returns nothing.
if have amass && grep -q libpostal "$(command -v amass)" 2>/dev/null \
   && [[ ! -e /usr/share/libpostal/transliteration ]]; then
  warn "amass wrapper needs libpostal data and will try to sudo on every unattended run."
  warn "  Run once interactively:  sudo libpostal_data download all /var/lib/libpostal"
  DEGRADED+=("Phase 1 amass (libpostal setup pending)")
fi
echo

# ----- 5. data-source API keys -----------------------------------------------
bold "== Data-source API keys (optional; modules degrade if unset) =="
# subfinder: providers configured in provider-config.yaml (list items = keys).
SF_CFG="${HOME}/.config/subfinder/provider-config.yaml"
if have subfinder; then
  if [[ -f "$SF_CFG" ]]; then
    n=$(grep -cE '^[[:space:]]*-[[:space:]]*[^[:space:]#]' "$SF_CFG" 2>/dev/null || true)
    if [[ "${n:-0}" -gt 0 ]]; then ok "subfinder: ${n} API key(s) configured"
    else warn "subfinder: no API keys in $SF_CFG — keyless sources only (much lower yield)"
         DEGRADED+=("Phase 1 subfinder (no API keys)"); fi
  else
    warn "subfinder: no $SF_CFG — keyless sources only (much lower yield)"
    DEGRADED+=("Phase 1 subfinder (no API keys)")
  fi
fi
# amass: v4 reads ~/.config/amass/datasources.yaml (v3: config.ini).
if have amass; then
  if [[ -f "${HOME}/.config/amass/datasources.yaml" || -f "${HOME}/.config/amass/config.ini" ]]; then
    ok "amass: data-source config present"
  else
    warn "amass: no data-source config in ~/.config/amass — keyless sources only"
  fi
fi
if [[ -n "${SHODAN_API_KEY:-}" ]]; then ok "SHODAN_API_KEY set"
else warn "SHODAN_API_KEY unset — Shodan DNS source skipped"; DEGRADED+=("Phase 1 Shodan"); fi
info "Censys is not automated (API changed) — search the Censys platform manually if licensed"
echo

# ----- 6. environment --------------------------------------------------------
bold "== Environment =="
if grep -qi microsoft /proc/version 2>/dev/null; then
  mode=""
  if have wslinfo; then mode=$(wslinfo --networking-mode 2>/dev/null | tr -d '\r' || true); fi
  if [[ -z "$mode" ]]; then
    for cfg in /mnt/c/Users/*/.wslconfig; do
      [[ -f "$cfg" ]] || continue
      m=$(grep -iE '^[[:space:]]*networkingMode[[:space:]]*=' "$cfg" | head -1 | cut -d= -f2 | tr -d ' \r')
      [[ -n "$m" ]] && mode="$m" && break
    done
  fi
  mode=$(echo "${mode:-nat}" | tr '[:upper:]' '[:lower:]')
  if [[ "$mode" == "mirrored" ]]; then
    ok "WSL2 networking: mirrored — masscan sees the real network"
  else
    warn "WSL2 networking: ${mode} — masscan behind WSL2 NAT is unreliable (missed open ports)."
    warn "  Set networkingMode=mirrored in %UserProfile%\\.wslconfig, then 'wsl --shutdown'; or use native Linux."
    DEGRADED+=("Phase 4 masscan accuracy (WSL2 ${mode} networking)")
  fi
else
  ok "not WSL"
fi
for t in gowitness aquatone testssl.sh; do
  if have "$t"; then ok "$t (manual, optional)"; else info "$t absent (manual, optional)"; fi
done
echo

# ----- 7. summary ------------------------------------------------------------
bold "== Summary =="
[[ "$CORE_OK" == true ]] || miss "Core tooling incomplete — install the [miss] items above first."
case "$GATE_RC" in
  0) ok "Gate PASSED — all phases may run, including gated steps and Phase 4." ;;
  2) warn "Gate FAILED — passive parts of Phases 1, 2, 3 and 5 may run; every gated step and"
     warn "  all of Phase 4 will refuse until scope.yaml is fixed." ;;
  *) warn "Gate not evaluated (scope file or Python missing) — only fix-up work possible." ;;
esac
if [[ ${#DEGRADED[@]} -gt 0 ]]; then
  warn "Degraded this run (also recorded per phase in status.json):"
  printf '%s\n' "${DEGRADED[@]}" | sort -u | sed 's/^/         - /'
fi
echo
echo "Next: validate small —  python3 ${SCRIPT_DIR}/01_passive_enum.py --scope $SCOPE --domain <one seed>"

[[ "$CORE_OK" == true ]] || exit 1
exit 0
