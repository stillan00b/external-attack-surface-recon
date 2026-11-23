# Intel integration contract

Two channels, kept strictly separate because their safety properties differ.
The prioritization channel *ranks* discovered assets; the asset-delta channel
*selects* scan targets (and still passes the scope gate). Threat-landscape IOCs
never cross into target selection.

## Table of contents
- [The boundary, restated](#the-boundary-restated)
- [Channel 1 — prioritization feed (ranking only)](#channel-1--prioritization-feed-ranking-only)
- [Channel 2 — asset-delta feed (targets, scope-gated)](#channel-2--asset-delta-feed-targets-scope-gated)
- [Incremental mode](#incremental-mode)
- [Provenance & honesty alignment](#provenance--honesty-alignment)

## The boundary, restated

```
threat-landscape feed ─► PRIORITIZATION channel ─► ranks discovered services
  (CVEs, KEV, GreyNoise,                            (never selects targets,
   exploit status, TTPs)                             never confirms a vuln)

asset-discovery feed  ─► ASSET-DELTA channel ─► proposes scan targets
  (new CT certs, new                              │
   passive DNS, new                               ▼
   Shodan services)                      Phase 0 scope gate ─► scanned only if in-scope

threat-landscape IOCs ─► REPORT context only (read-only "does any asset
  (attacker IPs/domains)   resolve to known-bad infra?") ─► NEVER a scan target
```

The reason the IOC rail exists: an IOC is *attacker* infrastructure. Letting it
flow into target selection would mean scanning a threat actor's servers — the
exact scope violation Phase 0 prevents. IOCs inform the report; they never
inform the scanner.

## Channel 1 — prioritization feed (ranking only)

Path: `integrations.prioritization_feed_path` in `scope.yaml`. Consumed after
Phase 4 to rank confirmed services. It does **not** add targets and does **not**
make the skill confirm a vulnerability (no vuln NSE runs). It lets the report
say "this exposed service runs a product under active exploitation as of
today — verify manually."

Expected shape (aligns with a typical threat-intel "critical vulnerability
summary"):

```json
{
  "generated": "2026-06-25T06:00:00Z",
  "source_coverage": "FULL",
  "items": [
    {
      "product": "F5 BIG-IP",
      "version_range": "<=17.1.0",
      "cve": "CVE-2026-XXXX",
      "cvss": 9.8,
      "exploit_status": "active",
      "kev_listed": true,
      "greynoise_activity": "mass-scanning",
      "source": "CISA KEV",
      "confidence": "high"
    }
  ]
}
```

Matching logic: for each confirmed `product`+`version` from Phase 4, look for a
prioritization item whose `product` matches and whose `version_range` contains
the discovered version. On a match, raise that asset's report priority and
attach the CVE/exploit context with its `source`. No match → no change. A
version you couldn't determine → don't guess; leave it unranked and note it in
intelligence gaps.

## Channel 2 — asset-delta feed (targets, scope-gated)

Path: `integrations.intel_delta_path` in `scope.yaml`. Produced by a *separate*
asset-discovery feed that watches your own surface. Drives incremental mode.
Every entry still passes the Phase 0 in-scope matcher before anything touches
it.

```json
{
  "engagement_id": "ENG-2026-0001",
  "generated": "2026-06-25T06:00:00Z",
  "since": "2026-06-24T06:00:00Z",
  "new_assets": [
    {
      "type": "hostname",
      "value": "new-vpn.example.com",
      "resolved_ips": ["203.0.113.77"],
      "source": "ct-log",
      "first_seen": "2026-06-25T02:14:00Z"
    },
    {
      "type": "service",
      "value": "203.0.113.42:8443",
      "source": "shodan",
      "first_seen": "2026-06-25T03:40:00Z"
    }
  ],
  "new_lookalikes": [
    {
      "value": "examp1e-corp.com",
      "registered": "2026-06-25T01:00:00Z",
      "has_mx": true,
      "source": "dnstwist-daily"
    }
  ]
}
```

Handling:
- `new_assets` of type `hostname`/`service` → candidate scan targets, **subject
  to the scope gate**. An entry resolving outside the authorized ranges is
  logged but not scanned, exactly as in a full run.
- `new_lookalikes` → feed straight into the Phase 2 risk table; "registered
  since last run" is the alert you want.

## Incremental mode

When `intel_delta_path` is set, the orchestration narrows Phases 1–4 to the
delta instead of re-walking the entire surface. Full scans become periodic
(say weekly); daily runs are lightweight diffs. This is also far kinder to rate
ceilings and cloud-provider abuse exposure than blasting full scope every 24h.
The full-scan path remains the default when no delta is supplied.

## Provenance & honesty alignment

Mirror the conventions of a well-run threat-intel pipeline so findings from both
sides merge cleanly into one report:

- Every asset and finding carries a `source` and `first_seen` (≈ the intel
  pipeline's per-claim source field).
- Unverifiable items are marked (`unconfirmed` / `unverified`), never invented
  (≈ no-fabrication rule).
- The report header stamps a coverage badge and includes a coverage ledger
  appendix (≈ the intel pipeline's badge + source ledger).
- An "intelligence gaps" section records what couldn't be determined and why.
