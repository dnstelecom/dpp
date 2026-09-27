# RFC 0007 — Packet storage allocation experiments

**Status:** Accepted · **Date:** 2026-08-17

## Problem

Offline capture ingestion copies each borrowed packet payload into its own `Box<[u8]>` before
crossing a thread boundary. Profiles attributed substantial ingestion cost to allocation, while
the DNS decoder also created temporary per-message vectors. Batch arenas, slabs, and inline
decoder storage were therefore plausible optimizations.

## Decision

**Keep the current per-packet owned payload.** The accepted decision rejects these tested
replacements under the current pipeline ownership model:

- contiguous or segmented batch-wide backing;
- chunk-size or capacity-hint tuning of that backing;
- a small/large storage threshold;
- copying routed packets into a second worker-owned arena;
- inline decoded-question storage solely to reduce allocator calls.

Batch-wide ownership ties every packet's lifetime to the slowest worker, raising peak RSS.
Splitting ownership after routing removes that coupling but adds another payload copy, reducing
throughput, especially for large DNS frames. Tuning allocation shape shifts this trade-off
without removing it.

## Experiments

### Measurement protocol

Baseline and candidate builds were compared on one macOS ARM64 host in staged mode. Final
screens used:

- 20 balanced, randomized pairs per fixture, with no outlier removal;
- CSV output to `/dev/null` and byte-identical output verification;
- kernel peak RSS.

The chunk-size sweep used 10 position-balanced blocks. Results are paired geometric ratios.
**Speed above `1.0` is better; RSS below `1.0` is better.**

### Results

| Candidate | Dense speed / RSS | Sparse-large speed / RSS | Decisive result |
| --- | --- | --- | --- |
| One contiguous batch arena | `1.009 / 1.428` | `0.459 / 1.151` | Severe sparse regression |
| Segmented 1 MiB arena | `1.032 / 1.295` | `0.821 / 1.034` | Dense RSS and sparse throughput regress |
| Best chunk sweep result: 64 KiB | `1.054 / 1.348` | `0.954 / 1.293` | No acceptable throughput/RSS point |
| Small/large hybrid with worker compaction | `0.980 / 0.968` | `0.928 / 1.093` | Large DNS fell to `0.799 / 1.375` |
| Inline one-question decoder storage | `0.999 / 1.082` | `1.020 / 0.990` | Large DNS fell to `0.894 / 1.059` |

The hybrid reached `1.181x` on small non-DNS packets, confirming that fewer allocations can
improve isolated ingestion. That gain disappeared once DNS payload ownership crossed into workers.

Inline question storage also reduced jemalloc's allocation requests:

| Measurement | Baseline | Candidate | Change |
| --- | --- | --- | --- |
| Small allocation requests | `816,043` | `616,028` | `-24.51%` |
| Size-class-weighted requested bytes | `394,657,800` | `369,054,944` | `-6.49%` |

End-to-end throughput still regressed on the large-DNS fixture. Allocation-call count is
therefore diagnostic evidence, not an acceptance metric.

## Reconsideration gate

Reopen this decision only for an architecture that preserves one payload copy without
batch-wide lifetime coupling.

The proposed direction is to classify borrowed capture bytes before ownership handoff, then
copy accepted DNS packets directly into their final worker-owned storage. This would move
routing into or adjacent to ingestion and requires an explicit ownership-boundary design.
It is a direction to evaluate, not an accepted replacement.

Any replacement must satisfy every requirement:

| Requirement | Acceptance criterion |
| --- | --- |
| Correctness | Byte-identical output and counters |
| Throughput | Positive dense-workload result; no worse than `0.98x` on sparse and large-DNS workloads, with paired 95% confidence intervals |
| Memory | Peak RSS no higher than `1.10x` baseline on every workload |
| Coverage | Staged and phase-parallel execution on representative production captures, including Linux |

The measurements reject the tested designs but do not establish portability. They used
synthetic fixtures on macOS ARM64, changing background load, and no storage I/O.
