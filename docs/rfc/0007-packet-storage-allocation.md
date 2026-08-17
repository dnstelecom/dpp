# RFC 0007 - Packet Storage Allocation Experiments

Status: Accepted

Date: 2026-08-17

## Problem

Offline capture ingestion copies every borrowed packet payload into its own `Box<[u8]>` before
the batch crosses a thread boundary. Profiles attributed substantial ingestion cost to allocation,
and the DNS decoder also created temporary per-message vectors. This made batch arenas, slabs, and
inline decoder storage plausible optimizations.

## Experiments

The experiments used byte-identical baseline and candidate builds on one macOS ARM64 host in
staged mode. Final screens used 20 balanced, randomized pairs per fixture, no outlier removal,
CSV output to `/dev/null`, kernel peak RSS, and byte-identical output verification. The chunk-size
sweep used 10 position-balanced blocks. Results are paired geometric ratios: speed above `1.0` is
better; RSS below `1.0` is better.

| Candidate | Dense speed / RSS | Sparse-large speed / RSS | Decisive result |
|-----------|-------------------|--------------------------|-----------------|
| One contiguous batch arena | `1.009 / 1.428` | `0.459 / 1.151` | Severe sparse regression |
| Segmented 1 MiB arena | `1.032 / 1.295` | `0.821 / 1.034` | Dense RSS and sparse throughput regress |
| Best chunk sweep result: 64 KiB | `1.054 / 1.348` | `0.954 / 1.293` | No acceptable throughput/RSS point |
| Small/large hybrid with worker compaction | `0.980 / 0.968` | `0.928 / 1.093` | Large DNS fell to `0.799 / 1.375` |
| Inline one-question decoder storage | `0.999 / 1.082` | `1.020 / 0.990` | Large DNS fell to `0.894 / 1.059` |

The hybrid did reach `1.181x` on small non-DNS packets, confirming that allocation removal can
improve isolated ingestion. It lost that gain once DNS payload ownership crossed into workers.

Jemalloc statistics also confirmed the local optimization: inline question storage reduced small
allocation requests from `816,043` to `616,028` (`-24.51%`) and size-class-weighted requested bytes
from `394,657,800` to `369,054,944` (`-6.49%`). End-to-end throughput still regressed on the
large-DNS fixture. Allocation-call count is therefore diagnostic evidence, not an acceptance
metric.

## Decision

Keep the current per-packet owned payload. Do not replace it with any of the following under the
current pipeline ownership model:

- a contiguous or segmented batch-wide backing;
- chunk-size or capacity-hint tuning of that backing;
- a small/large storage threshold;
- copying routed packets into a second worker-owned arena;
- inline decoded-question storage solely to reduce allocator calls.

Batch-wide ownership couples the lifetime of every packet to the slowest worker and raises peak
RSS. Splitting ownership after routing removes that coupling but introduces another payload copy,
which loses throughput, especially for large DNS frames. Tuning allocation shape only moves the
trade-off; it does not remove it.

## Reconsideration Gate

Reopen this decision only for an architecture that preserves one payload copy without batch-wide
lifetime coupling. The credible direction is to classify borrowed capture bytes before ownership
handoff, then copy accepted DNS packets directly into their final worker-owned storage. That moves
routing into or adjacent to ingestion and therefore requires an explicit ownership-boundary design,
not another container substitution.

Any replacement must also provide:

- byte-identical output and counters;
- a positive dense-workload throughput result and no worse than `0.98x` on sparse and large-DNS
  workloads, with paired 95% confidence intervals;
- peak RSS no higher than `1.10x` baseline on every workload;
- staged and phase-parallel coverage on representative production captures, including Linux.

The measurements above are sufficient to reject the tested designs, but they are not portability
claims: they used synthetic fixtures, macOS ARM64, changing background load, and excluded storage
I/O.
