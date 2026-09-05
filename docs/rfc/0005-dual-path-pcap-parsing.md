# RFC 0005 — Dual-Path PCAP Parsing and Monotonic Timestamp Contract

Status: Accepted  
Date: 2025-08-18

## Problem

PCAP comes in two major flavors: classic PCAP (the original tcpdump format) and PCAPNG (the newer,
more featureful format). Most large DNS captures in production are still classic PCAP, but PCAPNG
shows up often enough that ignoring it isn't an option.

The challenge is that `libpcap` — the standard C library for reading both formats — carries
overhead that matters at scale: FFI crossings on every packet, less control over buffering, and
an opaque internal state machine. For classic PCAP, we can do better with a pure-Rust reader.
For regular-file PCAPNG and other non-classic formats, we still rely on fallback compatibility
today. For stdin streams, however, probing consumes bytes that cannot be rewound safely on pipes,
so the parser must stay stream-native once it has inspected the magic bytes.

Separately, some captures are known to be globally monotonic by timestamp — every packet's
timestamp is ≥ the previous one. When that holds, the matcher can use batch-level watermarks
to evict stale state in bulk instead of checking timeouts per-query. But if the assumption is
wrong, the results are silently incorrect. So the contract needs teeth.

## Decision

### Parsing backends

`PacketParser` (in `src/packet_parser.rs`) picks the backend at open time by inspecting the
file's magic bytes when the input source is a regular file:

- **Classic PCAP** → pure-Rust streaming reader via `pcap-file`. No FFI, no `libpcap` dependency
  on this path. The reader is zero-copy where possible and gives us full control over buffering
  and batch construction.

- **Everything else** (PCAPNG, modified formats) → `libpcap` fallback via the `pcap` crate.
  Correct but slower. This path exists so DPP doesn't reject valid captures — it just won't be
  as fast.

- **EOF-terminated stdin classic PCAP streams** → pure-Rust streaming reader via `pcap-file`,
  using parser-owned probe-and-replay so the same stdin byte stream remains the single source of
  truth.

- **EOF-terminated stdin PCAPNG streams** → parser-owned pure-Rust block framing and one
  section-local interface table, with stateless block/body/option validation via `pcap-file`.
  Once stdin bytes have been inspected, the parser stays stream-native instead of trying to
  reopen the stream through a second owner.

- **EOF-terminated stdin streams with unknown magic** → explicit rejection. DPP does not create a
  temp file or hidden second ingest path to recover fallback compatibility for unsupported stdin
  stream formats.

The detection is a simple 4-byte magic check (`0xa1b2c3d4` or `0xd4c3b2a1` for classic,
`0xa1b23c4d` or `0x4d3cb2a1` for nanosecond-resolution classic, `0x0a0d0d0a` for PCAPNG). For
regular files, everything else goes to `libpcap`. For stdin streams, everything else is rejected.

### PCAPNG timestamp ownership

The parser reads timestamp high/low words separately in section byte order for both Enhanced
Packet Blocks and legacy Packet Blocks. It applies each interface's `if_tsresol` and signed
`if_tsoffset` exactly once. All seven-bit resolution exponents are accepted; the complete raw
counter is scaled before integer rounding to microseconds, including sub-nanosecond units.
The final timestamp saturates to `i64` only after adding the signed offset. New sections reset
the interface table and may change byte order.

The stateful `pcap-file 3.0.0-rc1` reader is deliberately bypassed: it swaps legacy little-endian
timestamp words, mis-scales binary resolutions, ignores offsets, and panics on exponent 30.
The newer `3.0.0-rc.3`, inspected on 2026-09-05, fixes those calculations but still rejects
sub-nanosecond resolutions and dates before the Unix epoch. Upgrading alone does not satisfy
this timestamp contract. The existing stateless decoder accepts the wire resolution field
without applying the faulty conversion, and remains responsible for structural validation.

The parser validates referenced interfaces, captured/original/snap lengths, and uniqueness of
timestamp options. Input buffers grow only as bytes arrive; a huge declared length on a truncated
stream cannot trigger allocation of that entire declared block. Independent manually encoded
fixtures cover both byte orders and packet-block formats, interface offsets, resolution extremes,
section resets, truncation, and malformed lengths/options. Tests must not encode expected
timestamp layouts with the same dependency writer whose decoder they are validating.

### IP and UDP boundaries

The routing stage and shard-local DNS decoder share one `ParsedUdpDnsMeta` value containing the
validated DNS offset and length. IPv4 Total Length or IPv6 Payload Length first bounds the IP
payload; UDP Length then bounds the DNS payload. Bytes outside either declared boundary, including
Ethernet padding and trailing capture bytes, never reach a DNS decoder.

DPP has no IPv4 reassembly stage. IPv4 datagrams with the More Fragments flag or a non-zero fragment
offset are therefore skipped rather than interpreting a fragment body as a complete UDP datagram.
IPv6 extraction traverses Hop-by-Hop, Routing, Destination Options, Authentication and atomic
Fragment headers with per-header bounds checks. Non-atomic fragments require reassembly and are
skipped. The DNS offset can exceed 65535 after a long valid extension chain. Internal metadata
stores a checked `u16` delta from the minimum 42-byte Ethernet/IPv4/UDP prefix and reconstructs
the absolute offset when accessing packet bytes. A maximum IPv6 frame ends at byte 65589 and
must leave at least 12 DNS bytes, so this delta covers the full supported range. The UDP-bounded
DNS length remains `u16`; routing metadata is 42 bytes on the measured macOS ARM64 target.

### DNS QNAME boundary

The standard `hickory` DNS question decoder and the optional custom DNS wire fast path enforce the
same RFC 1035 boundary after name decompression. A QNAME may occupy at most 255 wire octets,
including label-length octets and the terminating root octet. Its escaped presentation form can be
as large as 1003 bytes and remains valid input; DPP preserves it for matching and export rather than
replacing it with an empty name.
Both question decoders reject compression pointers that point forward or overlap the current name.
The fast path's fallback must not become a way to accept a message the semantic decoder rejects.

If any decompressed QNAME exceeds the wire limit, the entire DNS message is rejected before matcher
or writer handoff. The processing counter `oversized_qname_message_count` increments exactly once
for that message, regardless of its question count, and the JSON report exposes the same DNS-message
unit as `metrics.dns_messages_rejected_oversized_qname`. No question from the rejected message may
enter matcher state or output.

### Monotonic timestamp contract

The `--monotonic-capture` flag opts into a strict invariant: packet timestamps must be globally
non-decreasing. When enabled:

- `PacketParser` tracks timestamp regressions and **fails hard** on the first one, instead of
  logging a warning and continuing.
- The pipeline can use the batch-maximum timestamp as a global eviction watermark (see
  RFC 0004), which keeps matcher memory bounded on long captures.

When disabled (the default):

- Timestamp regressions are tracked and reported as a post-run warning with the first offending
  sample.
- The matcher falls back to per-query timeout checks at finalization time — correct but uses
  more memory on long captures with many in-flight queries.

## Why not always use libpcap?

Performance. On a 10 GB classic PCAP, the pure-Rust reader is measurably faster because it
avoids per-packet FFI overhead and gives us direct control over read buffering. The difference
is most visible on high-packet-rate captures where the per-packet cost dominates.

The `pcap-file` crate is currently pinned to a `3.0.0-rc1` release candidate because the stable
line doesn't expose the API we need. This is a known dependency risk — if the RC is abandoned,
we'll need to vendor or fork.

## Why fail-fast on monotonic violations?

Because silent data corruption is worse than a crash. If someone passes `--monotonic-capture` on
a capture that isn't actually monotonic, the batched eviction will retire queries too early and
produce incorrect timeout counts. A hard error on the first regression makes the failure obvious
and actionable.

## Consequences

- Adding support for a new capture format means adding a new `PacketBackend` variant, not
  changing the parser interface.
- The pure-Rust reader is the performance-critical path. Changes to it should be benchmarked.
- Stdin support stays within the offline-processing contract and now uses parser-owned stream-native
  backends for classic PCAP and PCAPNG so stdin probing does not create a second ingest owner.
- Regular-file fallback compatibility for non-classic formats still relies on `libpcap`.
- The `pcap-file` RC dependency should be revisited when a stable release is available.
