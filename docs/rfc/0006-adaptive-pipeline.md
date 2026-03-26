# RFC 0006 — Adaptive Pipeline: Staged vs Phase-Parallel Execution

Status: Accepted  
Date: 2025-10-09

## Problem

DPP's processing pipeline has natural concurrency: packet parsing, flow routing, shard-local
matching, deterministic aggregation, and async output. On a 16-core machine, dedicating threads
to each stage makes sense — the stages overlap in time and the pipeline stays busy. But on a
2-core machine, reserving threads for routing and aggregation leaves zero cores for the actual
matching work. The pipeline stalls instead of speeding up.

A single execution model doesn't fit both ends of the hardware spectrum.

## Decision

DPP picks its execution model automatically based on the available CPU budget:

### Staged pipeline (high-core hosts)

When the CPU budget is large enough to support dedicated service threads without starving
shard workers, DPP runs a **staged pipeline** with explicit thread roles:

- **Parser thread** (`DPP_Parser`) — receives raw packet batches, extracts `CanonicalFlowKey`
  per packet, routes packets to the correct matcher worker by shard index.
- **Matcher workers** (`DPP_Matcher_N`) — each owns a range of shards. Receives routed batches,
  performs full DNS decode, runs shard-local matching. Workers process batches tagged with a
  sequence number to preserve global ordering.
- **Aggregator** (runs on the pipeline's parent thread) — collects results from all workers,
  reorders them by batch sequence number using a `PendingBatchBuffer`, and emits finalized
  records to the output channel in deterministic order.

The staged pipeline uses bounded crossbeam channels between stages. Backpressure propagates
naturally: if matcher workers fall behind, the parser blocks on send; if the output channel
is full, the aggregator blocks.

### Phase-parallel pipeline (low-core hosts)

When the CPU budget is too small for dedicated service threads, DPP falls back to a simpler
**phase-parallel** model:

- A single processing thread receives packet batches.
- Within each batch, shard-local work is parallelized via Rayon's `par_iter`.
- Results are collected and emitted in shard-index order after each batch.

This avoids the overhead of dedicated routing and aggregation threads on machines where those
threads would compete with the actual work.

### How the decision is made

The threshold lives in `src/config.rs` as part of the `ExecutionBudget`. The
`uses_staged_pipeline()` method returns `true` when the available CPU count is high enough to
reserve service threads (currently 2: one for parsing/routing, one implicitly for aggregation)
and still leave meaningful worker capacity. The exact threshold is a tuned constant, not a
CLI flag — it's an implementation detail, not a user-facing policy.

## Key implementation details

- **Shard count** = `available_cpus × MATCHER_SHARD_FACTOR`. Over-sharding relative to worker
  count improves load balance when flow sizes are skewed.
- **Worker-to-shard mapping** is a simple range partition: worker `i` owns shards
  `[i * shard_count / worker_count, (i+1) * shard_count / worker_count)`.
- **Batch sequence numbers** ensure the aggregator emits results in the same order regardless
  of which worker finishes first. The `PendingBatchBuffer` holds out-of-order results and
  releases them only when the next expected sequence is complete.
- **Routing metadata reuse** — the parser stage extracts UDP/DNS metadata once during routing
  and passes it alongside the packet to the matcher worker, so the worker doesn't repeat L3/L4
  parsing for DNS question decode.

## Why not let the user choose?

Because the right choice depends on hardware, not on user preference. A user on a 2-core VM
who forces staged mode gets worse performance, not better. The automatic selection removes a
footgun without losing any capability — on high-core machines, you get the staged pipeline
automatically.

If future profiling shows the threshold needs tuning, it's a one-line change in `config.rs`.

## Consequences

- Both paths must produce identical output for the same input. This is the determinism contract
  from RFC 0004 — the execution model is an implementation detail, not a semantic difference.
- Performance changes to either path should be benchmarked on both low-core and high-core
  machines.
- The `MATCHER_SHARD_FACTOR` and staged-pipeline threshold are tuning constants. Changes should
  be backed by benchmark data, not intuition.
