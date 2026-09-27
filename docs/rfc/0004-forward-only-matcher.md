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
   `CanonicalFlowKey` (observed client IP, client port and resolver IP, oriented by DNS QR)
   and hashes it to a shard index. This includes the valid case where both ports are 53 and
   guarantees that a query and its
   matching response always land in the same shard.

3. **Deterministic ordering.** Within a shard, packets are processed in strict
   `(timestamp, packet_ordinal, record_ordinal)` order. Tie-breaks are explicit — scheduler
   interleaving and container iteration order are not valid tie-breaks.

   With full IPv4 reassembly, routing retains ready packet batches while fragment sets remain
   unresolved. A reconstructed datagram can carry an earlier final-fragment timestamp, so merely
   limiting timeout eviction would still let a retry or response finalize before that datagram.
   Routing releases the retained packets and reconstructed datagrams together for the existing
   timestamp/ordinal sort. This also preserves ordering within a batch whose timestamps regress
   in default mode; it does not impose global monotonicity on that mode.

   This packet backlog is separate from matcher state and bounded between batches to one packet
   batch (65,536 packets) or 64 MiB of payloads. On overflow, pending fragment sets use the existing
   capacity fallback before routing releases the backlog. Processing the current input batch and
   fallback packets can temporarily exceed those retained-state limits. EOF and interrupted
   intake drain accepted ready packets through the existing shutdown policy. The matcher eviction
   watermark is capped by both the oldest unresolved fragment and the oldest retained ready packet.

4. **Retry deduplication.** If a query with the same identity arrives while an earlier one is
   still pending inside the match-timeout window (1200 ms by default), the duplicate is counted
   but doesn't create a second canonical query. One canonical query → one terminal outcome
   (matched or timeout), always. Default mode retains retry timestamps inside that pending query's
   payload. If an earlier query arrives across batches, the matcher regroups the identity's
   unresolved attempts into earliest-first timeout windows. For example, pending attempts observed
   at 3s, 2s and then 1s with a 1.2s window leave canonicals at 1s and 3s, rather than losing the
   latter through transitive deduplication. Finalized transactions are never reopened.

   Retry history is allocated only when a duplicate is observed in default mode; monotonic mode
   needs none. Regrouping costs `O(n log n)` in the affected identity's unresolved attempts and is
   restricted to earlier-canonical replacements. The canonical query payload remains the sole owner
   of retry history, with no secondary matcher map.

   Match identity includes the DNS ID, observed name, client IP and port, resolver IP, query
   type, query class and opcode. Resolver identity, query class and opcode remain internal and are
   not added to the exported `DnsRecord` schema.

   The current Community Edition identity key preserves the observed presentation-form QNAME bytes
   and does not lowercase them before matching. This is a deliberate Community Edition trade-off,
   not a protocol guarantee. RFC 4343 defines ASCII label comparison as case-insensitive, and a
   valid response is allowed to differ from the query's 0x20 casing, including when name
   compression reuses label bytes from another wire location. Community Edition still keeps
   byte-preserving identity because that better matches the real behavior it targets on offline
   caching-resolver workloads. Queries and responses that differ only by case may therefore fail
   to pair even on otherwise valid DNS traffic.

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
- For a fixed input PCAP and runtime configuration, finalized record values and order are
  deterministic. Output container layout, such as Parquet row-group boundaries, need not be
  byte-identical across runs.
- Internal sequencing metadata (`packet_ordinal`, `record_ordinal`) never leaks into the exported
  `DnsRecord`.
- Duplicate responses remain distinguishable in matcher state until matched or discarded.
- Community Edition intentionally preserves observed QNAME bytes instead of RFC-4343-style
  case-insensitive canonicalization. Case-only query/response mismatches are therefore an accepted
  limitation even on otherwise valid DNS traffic.

## Why BTreeMap and not HashMap

The matcher uses `BTreeMap` keyed on `(identity, timestamp, packet_ordinal, record_ordinal)`.
This gives ordered iteration for free, which is essential for closest-match lookups and
deterministic eviction. A `HashMap` would require sorting on every lookup or eviction pass —
possible, but slower and more error-prone.

## Consequences

- The matcher is the authoritative owner of in-flight state. No other module may hold or mutate
  query/response pairing data.
- Adding a new matching strategy (e.g., bidirectional or streaming) requires a new RFC.
- Timeout records encode "no response observed" by leaving response fields absent. The canonical
  timeout signal is an absent `response_timestamp`; `response_code` is absent because no DNS
  response exists.
