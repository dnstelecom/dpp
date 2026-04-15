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

- **EOF-terminated stdin PCAPNG streams** → pure-Rust `pcapng` reader via `pcap-file`, for the
  same reason: once stdin bytes have been inspected, the parser stays stream-native instead of
  trying to reopen the stream through a second owner.

- **EOF-terminated stdin streams with unknown magic** → explicit rejection. DPP does not create a
  temp file or hidden second ingest path to recover fallback compatibility for unsupported stdin
  stream formats.

The detection is a simple 4-byte magic check (`0xa1b2c3d4` or `0xd4c3b2a1` for classic,
`0xa1b23c4d` or `0x4d3cb2a1` for nanosecond-resolution classic, `0x0a0d0d0a` for PCAPNG). For
regular files, everything else goes to `libpcap`. For stdin streams, everything else is rejected.

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
