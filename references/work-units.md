# Work-unit & result schema (distribution-ready)

The run is single-node today, but the work is partitioned and results are
schema'd as if it were distributed. This means the jump to a queue + worker
fleet later is a swap of the *execution layer*, not a rewrite of the
methodology. Keep workers dumb; keep the smarts (scope validation, rate
governance, dedup) in the coordinator and the reducer.

## Table of contents
- [The model](#the-model)
- [Work-unit format](#work-unit-format)
- [Result record format](#result-record-format)
- [Idempotency & retries](#idempotency--retries)
- [The reduce step (dedup & merge)](#the-reduce-step-dedup--merge)
- [Single-node execution today](#single-node-execution-today)
- [Distributed execution later](#distributed-execution-later)

## The model

Three roles, regardless of where they run:

- **Coordinator** — reads `scope.yaml`, validates authorization, subtracts
  out-of-scope, and explodes the in-scope set into small work units. Owns the
  global rate ceiling.
- **Workers** — pull a unit, run the scan stage on it, emit result records.
  Stateless, crash-tolerant, idempotent.
- **Reducer** — merges all result records into the canonical asset inventory,
  reconciling overlaps and tagging provenance.

## Work-unit format

A unit is the smallest independently-scannable chunk. Keep units small enough
that one slow target can't stall a worker for an hour.

```json
{
  "unit_id": "u-000123",
  "engagement_id": "ENG-2026-0001",
  "phase": "active_scan",
  "stage": "masscan",
  "targets": ["203.0.113.0/26"],
  "ports": "1-65535",
  "rate_budget": 250,
  "created_at": "2026-06-25T14:00:00Z",
  "attempt": 1,
  "max_attempts": 3,
  "status": "pending"
}
```

Field notes:
- `rate_budget` is this unit's slice of the global ceiling — assigned by the
  coordinator so the **sum across in-flight units stays under** the global cap.
- `targets` is already scope-validated by the coordinator; a worker never
  re-derives scope and never scans anything outside its unit.
- `phase`/`stage` let the same unit format carry passive enum, masscan, and nmap
  work. For nmap confirmation, `targets` is a host and `ports` is that host's
  masscan-confirmed candidate list.

Recommended chunk sizes: masscan units of a /24 or /26; nmap units of a single
host (its candidate ports). Small units = even load and cheap retries.

## Result record format

Every record is source-tagged and timestamped so the reducer can merge and so
the report can show provenance.

```json
{
  "unit_id": "u-000123",
  "engagement_id": "ENG-2026-0001",
  "host": "203.0.113.42",
  "hostname": "vpn.example.com",
  "port": 443,
  "protocol": "tcp",
  "state": "open",
  "service": "https",
  "product": "F5 BIG-IP",
  "version": "17.1.0",
  "source": "nmap",
  "stage": "confirm",
  "confidence": "confirmed",
  "first_seen": "2026-06-25T14:03:12Z",
  "cdn_fronted": false,
  "notes": ""
}
```

`confidence` is one of `confirmed` (nmap verified), `unconfirmed` (masscan hit,
nmap could not verify), or `passive` (seen in an index/CT/DNS, not actively
probed). The report separates `confirmed` from `unconfirmed` and never promotes
the latter.

## Idempotency & retries

Units must be safe to run more than once — a dead worker just means its unit
re-queues. Achieve this by making the result write keyed on
`(unit_id, host, port)`: a re-run overwrites the same records rather than
duplicating them. The reducer also dedups, so a double-run is harmless. On
failure, increment `attempt`; when `attempt > max_attempts`, mark the unit
`failed` and record it in the coverage ledger as skipped-with-reason rather than
silently dropping its targets.

## The reduce step (dedup & merge)

Workers produce overlapping, fragmented views — the same host seen via CT logs,
reverse DNS, and a port hit. The reducer merges on a canonical key:

- Canonical host key: the resolved IP (an asset can have many hostnames → one
  IP, or one hostname → many IPs; keep both relations).
- Merge rule: union the `source` lists, keep the earliest `first_seen`, prefer
  `confirmed` over `unconfirmed` over `passive` for `state`/`service`.
- Carry every contributing source into the final row so provenance survives.

Plan this from the start. Reconciling scattered JSON from many workers *after*
the fact is the painful path.

## Single-node execution today

The coordinator/worker/reducer roles all run in one process tree.
`04_active_scan.py` builds units, spawns a small pool (`rate.parallel_workers`)
of local nmap workers each with `global_ceiling / worker_count` as its
`rate_budget`, collects result records to a local directory, and runs the
reducer at the end. No queue, no network — same schema, local execution.

## Distributed execution later

Swap the local pool for: coordinator pushes units to a queue (SQS or Redis),
a fleet of spot workers pulls units and writes result records to shared storage
(S3) under the engagement ID, a reduce job runs when the queue drains. A shared
token bucket (Redis) enforces the global rate across the whole fleet so
per-worker budgets compose correctly. Nothing about the unit or result schema
changes — that's the point of defining them now.
