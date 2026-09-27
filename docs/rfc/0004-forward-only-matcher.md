# RFC 0004 — Forward-only matcher and determinism contract

**Status:** Accepted · **Date:** 2025-06-03

## Problem

DPP needs DNS query/response matching that is both parallel and deterministic on large captures.
A shared map protected by a mutex serializes matcher work. Concurrent maps alone do not define a
deterministic processing order: the same input can still produce different results as thread
scheduling changes.

## Decision

The matcher is **forward-only**: it processes packets in `(timestamp_micros, packet_ordinal)`
order within each shard and never backtracks. Each shard owns its state; routing and explicit
ordering keep matching independent of worker scheduling.

- [State ownership and routing](#state-ownership-and-routing)
- [Deterministic ordering](#deterministic-ordering)
- [Transaction identity](#transaction-identity)
- [Retry deduplication](#retry-deduplication)
- [Closest-match pairing](#closest-match-pairing)
- [Batched timeout eviction](#batched-timeout-eviction)

### State ownership and routing

Each shard owns its own `QueryMap` and `ResponseMap`, both based on `BTreeMap`. Shards share no
mutable matcher state.

Before full DNS decode, routing extracts a `CanonicalFlowKey`: observed client IP, client port,
and resolver IP, oriented by DNS QR. Hashing this key assigns a shard, including when both ports
are 53. A query and its matching response therefore reach the same shard.

Flow routing is coarser than transaction identity. VLANs with overlapping endpoints may share a
worker, but their transaction state remains distinct.

### Deterministic ordering

Within each shard, candidates are processed in strict `(timestamp, packet_ordinal, record_ordinal)`
order. Scheduler interleaving and container iteration order are never valid tie-breaks.

With full IPv4 reassembly, routing retains ready packet batches while fragment sets remain
unresolved. A reconstructed datagram can carry an earlier final-fragment timestamp. Capping
only timeout eviction would still let a retry or response finalize before that datagram arrives.

Routing releases retained packets and reconstructed datagrams together for timestamp/ordinal
sorting. This also preserves ordering within a batch whose timestamps regress in default mode;
it does not impose global monotonicity on that mode.

The ready-packet backlog is separate from matcher state:

| Constraint or event | Behavior |
| --- | --- |
| Retained-state bound between batches | One packet batch (65,536 packets) or 64 MiB of payloads |
| Either bound exceeded | Resolve pending fragment sets through the existing capacity fallback, then release the backlog |
| Current batch and fallback processing | May temporarily exceed the retained-state bounds |
| EOF or interrupted intake | Drain accepted ready packets under the existing shutdown policy |
| Matcher eviction watermark | Cap at both the oldest unresolved fragment and the oldest retained ready packet |

### Transaction identity

Matcher identity includes:

- DNS ID and observed presentation-form QNAME;
- observed client IP and port, plus resolver IP;
- query type, query class, and opcode;
- canonical VLAN context.

Ethernet decoding owns the ordered TPID/12-bit-VID stack used by matcher and fragment keys.
PCP and DEI bits are excluded. Untagged traffic needs no tag allocation; tagged metadata and keys
share immutable tag storage.

Resolver identity, query class, opcode, and VLAN context remain internal. They are not added to
the exported `DnsRecord` schema.

#### QNAME casing limitation

Community Edition preserves observed presentation-form QNAME bytes without lowercasing them.
This is a deliberate trade-off for the offline caching-resolver workloads it targets, not a
protocol guarantee.

RFC 4343 defines ASCII label comparison as case-insensitive. A valid response may differ from
the query's 0x20 casing, including when compression reuses label bytes from another wire location.
Such query/response pairs may fail to match in Community Edition even on otherwise valid DNS
traffic.

### Retry deduplication

A repeated query with the same identity inside the match-timeout window (`1200 ms` by default)
is counted as a duplicate while the earlier query remains pending. It does not create a second
canonical query. On normal completion, each canonical query has one terminal outcome: matched
once or emitted once as a timeout.

Default mode retains retry timestamps in the pending canonical query's payload. If an earlier
query arrives across batches, the matcher regroups that identity's unresolved attempts into
earliest-first timeout windows. Finalized transactions are never reopened.

For example, attempts observed at 3s, then 2s, then 1s with a 1.2s window leave canonical queries
at 1s and 3s. Transitive deduplication must not absorb the 3s attempt into the earlier window.

Retry history is allocated only when default mode observes a duplicate. Monotonic mode needs
none. Regrouping costs `O(n log n)` in the affected identity's unresolved attempts and occurs
only for earlier-canonical replacements. The canonical query payload is the sole owner of this
history; there is no secondary matcher map.

### Closest-match pairing

When a response arrives, the matcher selects the pending query with the closest timestamp within
the timeout window. When a query arrives and a buffered response already exists, the same logic
applies in reverse. This handles mild reordering while preserving deterministic decisions.

### Batched timeout eviction

`--monotonic-capture` opts into bulk eviction of stale queries using a batch-maximum watermark.
The capture must be globally monotonic under the [RFC 0005 contract](0005-dual-path-pcap-parsing.md#monotonic-timestamp-contract).

The watermark comes from the **routed batch maximum**, not each shard's local maximum. Sparse
shards therefore retire state against the global frontier.

## Invariants

These must hold for any valid implementation:

- On normal completion, each canonical query reaches exactly one terminal outcome: matched once
  or emitted once as a timeout. Interrupted and failed runs follow the separate
  [shutdown policy](../architecture.md#completion-and-failure-handling).
- For a fixed input PCAP and runtime configuration, finalized record values and order are
  deterministic. Output container layout, such as Parquet row-group boundaries, need not be
  byte-identical across runs.
- Internal sequencing metadata (`packet_ordinal`, `record_ordinal`) never enters the exported
  `DnsRecord`.
- Duplicate responses remain distinguishable in matcher state until matched or discarded.
- QNAME identity preserves observed bytes. Case-only query/response mismatches are an accepted
  Community Edition limitation, even on otherwise valid DNS traffic.

## Why BTreeMap and not HashMap

The matcher uses `BTreeMap` for identity-indexed query and response state. Each identity has a
timeline ordered by `(timestamp_micros, packet_ordinal, record_ordinal)`. Ordered iteration
supports closest-match lookups and deterministic eviction; a `HashMap` would require additional
sorting for those operations.

## Consequences

- The matcher is the authoritative owner of in-flight state. No other module may hold or mutate
  query/response pairing data.
- A new matching strategy, such as bidirectional or streaming matching, requires a new RFC.
- Timeout records leave response fields absent because no response was observed. The canonical
  timeout signal is an absent `response_timestamp`; `response_code` is absent because no DNS
  response exists.
