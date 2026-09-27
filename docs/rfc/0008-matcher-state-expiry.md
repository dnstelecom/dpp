# RFC 0008 — Matcher state expiry experiments

**Status:** Accepted · **Date:** 2026-08-18

## Problem

In default non-monotonic mode, entries without a counterpart remain until EOF. Monotonic mode
can evict state during processing, but `BTreeMap::retain` visits the complete pending map for
each batch: worst-case `O(state * batches)` work.

Early eviction is unsafe in default mode because later packets may regress to any timestamp.
For example, a query at `1,000 us`, an unrelated high-timestamp packet, and a later matching
response at `1,100 us` must still match. A watermark queue could expire the query too soon.

## Decision

**Keep the current matcher state and eviction behavior.** The accepted decision rejects the
tested expiry replacements:

| Mode | Retained behavior | Rejected replacement |
| --- | --- | --- |
| Default non-monotonic | Retain potentially matchable state until a match or EOF | An expiry queue without a safe bound on future timestamps |
| Monotonic | Exact `retain`-based eviction | The tested `Arc`/`BTreeSet` index, cadence-gated scans, and workload-tuned adaptive activation |

Bounding default-mode state requires a new bounded-lateness, preordering, spilling, or
state-limit contract. An expiry queue alone cannot provide that contract.

Allocation counts or asymptotic improvement alone do not justify a matcher hot-path change.
End-to-end throughput and peak memory are the acceptance metrics.

## Experiments

### Candidate and measurement protocol

The monotonic experiment shared each large matcher identity through `Arc`. The existing
identity-indexed map remained the source of truth; an exact `BTreeSet` expiry index used
`(TimelineKey, identity)` keys. Matches eagerly removed expiry entries. Query expirations were
sorted back into the existing deterministic identity order.

Measurements used separate baseline and candidate release builds on one macOS ARM64 host,
staged execution with 16 available CPUs, and CSV output to `/dev/null`. Main results use 20
position-balanced pairs and paired geometric ratios.

**Speed above `1.0` is better. RSS and retired instructions below `1.0` are better.**

### Results

| Workload | Speed | Peak RSS | Retired instructions |
| --- | --- | --- | --- |
| 2.0 M monotonic query-only packets, 5 s timeout | `1.1096` (`95% CI 1.0766-1.1436`) | `1.0577` (`1.0455-1.0699`) | `1.1159` (`1.1136-1.1183`) |
| 18.0 M representative packets, default mode | `0.9995` (`0.9901-1.0089`) | noisy / inconclusive | `1.0036` (`1.0031-1.0042`) |
| 2.0 M high-rate matched packets, monotonic mode | `0.9961` (`0.9863-1.0060`) | noisy / inconclusive | `1.0037` (`1.0030-1.0043`) |

An exploratory timeout sweep placed the workload-dependent crossover at roughly 9–14 batches
per timeout. The exact index had no reliable gain at 2 seconds, then reached about `1.069x` at
3 seconds and `1.117x` at 4 seconds.

Two alternatives also fell short:

- A cadence-gated `retain` reduced scans but kept stale state longer and raised observed RSS.
- An adaptive index avoided common-case costs only through irreversible, workload-specific
  activation heuristics.

### Identity ownership cost

The large identity is the central constraint. In the original experiment, `DnsNameBuf` was
264 bytes and matcher identity was approximately 312 bytes on the measured target. A safe,
eagerly cancellable secondary index must either share the identity through another allocation
or introduce stable handles and an arena/reverse index.

### Later name-layout change

On 2026-09-26, a separate change reduced inline `DnsNameBuf` capacity from 255 to 64 bytes.
The sizes above describe the original expiry experiment, not the later layout.

Five alternating paired runs on one macOS ARM64 host used the `perf` profile and a 16-CPU budget:

| Synthetic capture | Processing speed, paired geometric mean | Median peak child RSS |
| --- | --- | --- |
| 18.0 M packets | `1.095x` | 307 → 187 MiB |
| 500,612 query-only packets | `1.316x` | 407 → 234 MiB |

CSV output for the query-only subset was byte-identical. These measurements apply to the tested
host and captures; they do not establish a gain for every QNAME distribution.

## Reconsideration gate

Reopen monotonic expiry indexing for a design that stores each identity once and uses compact,
stable generational handles in an eagerly cancellable queue or time wheel. This requires an
ownership change, not merely a different container.

Reopen default-mode eviction only with an explicit contract that provides a safe lower bound
for future timestamps.

Any replacement must satisfy every requirement:

| Requirement | Acceptance criterion |
| --- | --- |
| Correctness | Byte-identical output and counters |
| Large-state throughput | At least a `1.05x` gain on the intended workload |
| Other throughput | Lower 95% speed bound at or above `0.99x` on representative default and matched workloads |
| Memory | Upper 95% peak-RSS ratio at or below `1.05x` |
| Coverage | Phase-parallel and staged execution, timestamp boundaries, response-first matching, cancellation, and production-like Linux captures |

These measurements reject the tested implementations; they do not establish portability.
They used synthetic fixtures, changing background load, and no output storage I/O.
