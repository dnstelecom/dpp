# RFC 0006 — Adaptive pipeline: staged vs phase-parallel execution

**Status:** Accepted · **Date:** 2025-10-09

## Problem

DPP can overlap packet parsing, flow routing, shard-local matching, deterministic aggregation,
and asynchronous output. Dedicated stage threads suit a 16-core host. On a 2-core host, reserving
threads for routing and aggregation leaves no CPU budget for matcher workers.

A single execution model cannot serve both CPU budgets efficiently.

## Decision

Select the execution model automatically from the effective CPU budget:

| Model | CPU budget | Unit of parallel work |
| --- | --- | --- |
| Staged | Enough CPUs for service threads and matcher workers | Pipeline stages overlap across batches |
| Phase-parallel | Too few CPUs for dedicated service threads | Shards run in parallel within one batch |

### Staged pipeline (high-core hosts)

The staged pipeline assigns explicit roles:

| Role | Runs on | Responsibility |
| --- | --- | --- |
| Parsing/routing | `DPP_Parser` thread | Receive raw packet batches, extract each `CanonicalFlowKey`, and route packets by shard index |
| Matching | `DPP_Matcher_N` workers | Own shard ranges, fully decode DNS, and match within each shard |
| Aggregation | Pipeline's parent thread | Collect all worker results, restore batch-sequence order with `PendingBatchBuffer`, and emit finalized record batches |

Routed batches carry sequence numbers, preserving global ordering even when workers finish out
of order. Record batches reach the output channel in deterministic order.

Bounded crossbeam channels provide backpressure. If matcher workers fall behind, the routing
thread blocks on send. If output is full, the aggregator blocks.

Output capacity is measured in batched record messages. Runtime configuration derives that
capacity from the queued-record backlog and the per-message record limit.

### Phase-parallel pipeline (low-core hosts)

Each batch proceeds through three steps:

1. A single processing thread receives the packet batch.
2. Rayon's `par_iter` runs shard-local work in parallel.
3. Results are collected and emitted in shard-index order.

This avoids dedicating routing and aggregation threads on hosts where those threads would
compete with matcher work.

### How the decision is made

[`src/config.rs`](../../src/config.rs) owns the threshold through `ExecutionBudget`.
`uses_staged_pipeline()` selects staged execution when the effective budget can reserve service
threads and still leave meaningful worker capacity.

Currently, two service roles are reserved: parsing/routing and aggregation. The threshold is a
tuned constant, not a CLI flag.

## Key implementation details

- **Shard count:** `available_cpus × MATCHER_SHARD_FACTOR`. Over-sharding relative to worker count
  improves load balance when flow sizes are skewed.
- **Worker-to-shard mapping:** worker `i` owns the range
  `[i * shard_count / worker_count, (i+1) * shard_count / worker_count)`.
- **Batch ordering:** `PendingBatchBuffer` holds out-of-order results and releases them only when
  the next expected batch sequence is complete.
- **Metadata reuse:** routing extracts UDP/DNS metadata once and passes it with each packet. A
  matcher worker reuses it instead of repeating L3/L4 parsing before DNS question decode.

## Why the execution model remains automatic

Selection follows hardware capacity. Forcing staged execution on a 2-core VM adds contention;
sufficiently large budgets already select it automatically. Operators can cap the effective
budget with `--threads` or `DPP_THREADS`.

Profiling may justify tuning the threshold in `config.rs`; it does not require a user-facing
execution-model switch.

## Consequences

- Both paths must produce identical output for the same input, following the
  [RFC 0004 determinism contract](0004-forward-only-matcher.md#invariants).
- Benchmark performance changes on both low-core and high-core machines.
- Back changes to `MATCHER_SHARD_FACTOR` or the staged threshold with benchmark data.
