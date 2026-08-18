# RFC 0008 - Matcher State Expiry Experiments

Status: Accepted

Date: 2026-08-18

## Problem

In the default non-monotonic mode, entries that find no counterpart remain until EOF. In monotonic
mode the matcher can evict state during processing, but the current `BTreeMap::retain` path visits
the complete pending map for every batch, giving worst-case `O(state * batches)` work.

Early eviction is not safe in the default mode. A later capture-order packet may regress to any
timestamp and still match old state. For example, a query at `1,000 us`, an unrelated packet at a
high timestamp, and a later matching response at `1,100 us` must still match. A watermark-based
queue would incorrectly expire the query before reading the response.

## Experiments

The monotonic experiment shared each large matcher identity through `Arc`, retained the existing
identity-indexed map as the source of truth, and added an exact `BTreeSet` expiry index keyed by
`(TimelineKey, identity)`. Matches removed expiry entries eagerly; query expirations were sorted
back into the existing deterministic identity order.

Measurements used separate baseline and candidate release builds on one macOS ARM64 host in
staged mode with 16 available CPUs. CSV output went to `/dev/null`. The main results use 20
position-balanced pairs and paired geometric ratios. Speed above `1.0` is better; RSS and retired
instructions below `1.0` are better.

| Workload | Speed | Peak RSS | Retired instructions |
|----------|-------|----------|----------------------|
| 2.0 M monotonic query-only packets, 5 s timeout | `1.1096` (`95% CI 1.0766-1.1436`) | `1.0577` (`1.0455-1.0699`) | `1.1159` (`1.1136-1.1183`) |
| 18.0 M representative packets, default mode | `0.9995` (`0.9901-1.0089`) | noisy / inconclusive | `1.0036` (`1.0031-1.0042`) |
| 2.0 M high-rate matched packets, monotonic mode | `0.9961` (`0.9863-1.0060`) | noisy / inconclusive | `1.0037` (`1.0030-1.0043`) |

An exploratory timeout sweep placed the workload-dependent crossover between roughly 9 and 14
batches per timeout: the exact index had no reliable gain at 2 seconds, then reached about `1.069x`
at 3 seconds and `1.117x` at 4 seconds. A cadence-gated `retain` reduced scans but deliberately
retained stale state longer and raised observed RSS. An adaptive index avoided common-case costs
only by adding irreversible, workload-specific activation heuristics.

The large identity is the central ownership constraint: `DnsNameBuf` is 264 bytes and the matcher
identity is approximately 312 bytes on the measured target. A safe eagerly cancellable secondary
index must either share that identity through another allocation or introduce stable handles and
an arena/reverse index.

## Decision

Keep the current matcher state and eviction behavior.

- Default non-monotonic mode retains potentially matchable state until a match or EOF. Bounding it
  requires a new bounded-lateness, preordering, spilling, or state-limit contract; an expiry queue
  alone is not correct.
- Monotonic mode keeps exact `retain`-based eviction. Do not add the tested `Arc`/`BTreeSet` index,
  cadence-gated scans, or workload-tuned adaptive activation.
- Allocation counts or asymptotic improvement alone do not justify a matcher hot-path change;
  end-to-end throughput and peak memory are acceptance metrics.

## Reconsideration Gate

Reopen monotonic expiry indexing for a design that stores each identity once and uses compact,
stable generational handles in an eagerly cancellable queue or time wheel. This is an ownership
change, not a container substitution. Reopen default-mode eviction only together with an explicit
contract that provides a safe lower bound for future timestamps.

Any replacement must preserve byte-identical output and counters, show at least a `1.05x` gain on
the intended large-state workload, keep the lower 95% speed bound at or above `0.99x` on
representative default and matched workloads, and keep the upper 95% peak-RSS ratio at or below
`1.05x`. It must also cover phase-parallel and staged execution, timestamp boundaries,
response-first matching, cancellation, and production-like Linux captures.

These measurements reject the tested implementations; they are not portability claims. They used
synthetic fixtures, changing background load, and excluded output storage I/O.
