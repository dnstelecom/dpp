# RFC 0004 — Forward-Only Matcher and Determinism Contract

Status: Accepted  
Date: 2025-06-03

## Problem

DNS query/response matching sounds simple until you try to do it in parallel on a 20 GB capture.
The naive approach — a shared hash map protected by a mutex — serializes the entire pipeline on
the matcher. The "clever" approach — lock-free concurrent maps — makes results depend on thread
scheduling, which means the same input can produce different output on different runs.

Neither is acceptable. DPP needs matching that is both parallel and deterministic.

## Decision

The matcher is **forward-only**: it processes packets in `(timestamp_micros, packet_ordinal)`
order within each shard and never backtracks. The key design choices:

1. **Shard-local state.** Each shard owns its own `QueryMap` and `ResponseMap` (both `BTreeMap`-
   based). There is no shared mutable matcher state between shards.

2. **Canonical flow routing.** Before full DNS decode, the routing stage extracts a cheap
   `CanonicalFlowKey` (client IP, resolver IP, port pair — always ordered so that
   `client < resolver`) and hashes it to a shard index. This guarantees that a query and its
   matching response always land in the same shard.

3. **Deterministic ordering.** Within a shard, packets are processed in strict
   `(timestamp, packet_ordinal, record_ordinal)` order. Tie-breaks are explicit — scheduler
   interleaving and container iteration order are not valid tie-breaks.

4. **Retry deduplication.** If a query with the same identity arrives while an earlier one is
   still pending inside the match-timeout window (1200 ms by default), the duplicate is counted
   but doesn't create a second in-flight entry. One query → one terminal outcome (matched or
   timeout), always.

5. **Closest-match pairing.** When a response arrives, the matcher finds the pending query with
   the closest timestamp (within the timeout window). When a query arrives and a buffered response
   already exists, the same closest-timestamp logic applies in reverse. This handles mild
   reordering without sacrificing determinism.

6. **Batched timeout eviction** (opt-in via `--monotonic-capture`). When the capture is globally
   monotonic, the matcher can evict stale queries in bulk using the batch-maximum timestamp as a
   watermark. The watermark comes from the *routed batch maximum*, not each shard's local maximum,
   so sparse shards still retire state against the global frontier.

## Invariants

These must hold for any valid implementation:

- Each query reaches exactly one terminal outcome: matched once, or emitted once as a timeout.
- For a fixed input PCAP and configuration, output is bit-for-bit deterministic.
- Internal sequencing metadata (`packet_ordinal`, `record_ordinal`) never leaks into the exported
  `DnsRecord`.
- Duplicate responses remain distinguishable in matcher state until matched or discarded.

## Why BTreeMap and not HashMap

The matcher uses `BTreeMap` keyed on `(identity, timestamp, packet_ordinal, record_ordinal)`.
This gives ordered iteration for free, which is essential for closest-match lookups and
deterministic eviction. A `HashMap` would require sorting on every lookup or eviction pass —
possible, but slower and more error-prone.

## Consequences

- The matcher is the authoritative owner of in-flight state. No other module may hold or mutate
  query/response pairing data.
- Adding a new matching strategy (e.g., bidirectional or streaming) requires a new RFC.
- Timeout records encode "no response observed" as `response_timestamp = 0` with
  `response_code = ServFail`. This is a convention, not a protocol truth — downstream consumers
  should be aware.
