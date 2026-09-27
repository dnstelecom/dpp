# RFC 0005 — Dual-path PCAP parsing and monotonic timestamp contract

**Status:** Accepted · **Date:** 2025-08-18

## Problem

DPP must read both classic PCAP and PCAPNG. Most large DNS captures use classic PCAP, where
per-packet `libpcap` FFI calls and opaque buffering add avoidable overhead. A pure-Rust reader
gives DPP more control over this common path.

Regular files can retain `libpcap` fallback compatibility. Stdin needs a different approach:
probing consumes bytes that a pipe cannot safely rewind, so the parser must stay stream-native
after inspecting the magic bytes.

Some captures also have globally non-decreasing timestamps. This permits bulk matcher eviction
using batch-level watermarks, but a timestamp regression would make that eviction unsafe.
Enabling the optimization therefore requires strict validation.

## Decision

The parser selects a reader for the input source and format, owns timestamp conversion, and
validates protocol boundaries before handing packets to DNS matching.

- [Parsing backends](#parsing-backends)
- [PCAPNG timestamp ownership](#pcapng-timestamp-ownership)
- [IP and UDP boundaries](#ip-and-udp-boundaries)
- [DNS QNAME boundary](#dns-qname-boundary)
- [Monotonic timestamp contract](#monotonic-timestamp-contract)

### Parsing backends

[`PacketParser`](../../src/packet_parser.rs) selects a backend at open time by inspecting the
first four bytes:

| Input source and format | Backend or outcome |
| --- | --- |
| Regular file: classic PCAP | Pure-Rust streaming reader via `pcap-file`; no FFI or `libpcap` on this path |
| Regular file: PCAPNG or another non-classic format | `libpcap` fallback via the `pcap` crate |
| EOF-terminated stdin: classic PCAP | Pure-Rust reader via `pcap-file`, with parser-owned probe-and-replay |
| EOF-terminated stdin: PCAPNG | Parser-owned block framing and section-local interface table; stateless validation via `pcap-file` |
| EOF-terminated stdin: unknown magic | Explicit rejection |

The pure-Rust classic reader is zero-copy where possible and owns buffering and batch
construction. The regular-file fallback preserves compatibility at a higher processing cost.

Stdin probing replays bytes into the same stream, preserving one input owner. DPP neither reopens
an inspected stdin stream through `libpcap` nor creates a temporary file or hidden second ingest
path for unsupported formats.

| Format | Recognized magic values |
| --- | --- |
| Classic PCAP | `0xa1b2c3d4`, `0xd4c3b2a1` |
| Classic PCAP, nanosecond resolution | `0xa1b23c4d`, `0x4d3cb2a1` |
| PCAPNG | `0x0a0d0d0a` |

Other magic values go to `libpcap` for regular files and are rejected for stdin.

### PCAPNG timestamp ownership

#### Conversion rules

For both Enhanced Packet Blocks and legacy Packet Blocks, the parser:

1. Reads the timestamp high/low words separately in section byte order.
2. Applies the interface's `if_tsresol` exactly once, scaling the complete raw counter before
   integer rounding to microseconds. This includes sub-nanosecond units and all seven-bit
   resolution exponents.
3. Adds the signed `if_tsoffset` exactly once.
4. Saturates the final timestamp to `i64`.

Each new section resets the interface table and may change byte order.

#### Dependency boundary

DPP bypasses the stateful `pcap-file 3.0.0-rc1` reader. That reader swaps legacy little-endian
timestamp words, mis-scales binary resolutions, ignores offsets, and panics on exponent 30.
The stateless decoder accepts the wire resolution field without the faulty conversion and
remains responsible for structural validation.

The newer `3.0.0-rc.3`, inspected on 2026-09-05, fixes those calculations but still rejects
sub-nanosecond resolutions and dates before the Unix epoch. Upgrading alone does not satisfy
this timestamp contract.

#### Structural validation and fixtures

The parser validates referenced interfaces, captured/original/snap lengths, and uniqueness of
timestamp options. Buffers grow only as bytes arrive: a huge declared length on a truncated
stream must not trigger allocation of that entire block.

Manually encoded fixtures cover both byte orders and packet-block formats, interface offsets,
resolution extremes, section resets, truncation, and malformed lengths/options. Expected layouts
must not be encoded with the same dependency writer whose decoder the test is validating.

### IP and UDP boundaries

Routing and shard-local DNS decoding share one `ParsedUdpDnsMeta` value containing the validated
DNS offset and length. IPv4 Total Length or IPv6 Payload Length first bounds the IP payload;
UDP Length then bounds DNS. Ethernet padding and trailing capture bytes outside either boundary
never reach a DNS decoder.

#### IPv4 fragmentation modes

| Mode | Accepted fragment processing |
| --- | --- |
| Default | Skip IPv4 datagrams with More Fragments set or a non-zero fragment offset |
| `--allow-fragments` | Allow inference from a first response fragment containing the complete DNS header and question |
| `--full-fragments` | Reconstruct complete IPv4 datagrams across batches; implies `--allow-fragments` |

With `--allow-fragments`, metadata bounds DNS bytes to the observed fragment and marks the
response as partial. This is inference from a prefix, not validation of the full UDP datagram.
A response code is emitted only if no additional records exist or all declared DNS records fit
in that prefix.

With `--full-fragments`, incomplete responses may use prefix inference on capacity eviction or
EOF. Elapsed capture-time timeout can also trigger fallback when `--monotonic-capture` is enabled.
Fragmented queries require complete reassembly.

The reassembler keys fragments by source, destination, protocol, and IPv4 identification. Payload
bytes use the declared eight-octet offsets. A datagram reaches the existing UDP/DNS parser only
when the first fragment, final fragment, and contiguous coverage are present. Its fragmented IP
payload length must equal UDP Length; mismatches are rejected.

Complete datagrams use the final fragment's (`MF=0`) capture timestamp. Prefix fallbacks retain
the first fragment's timestamp. Incomplete state is bounded to prevent unbounded memory growth.
Neither fragment mode reassembles IPv6.

#### IPv6 extension headers

IPv6 extraction traverses Hop-by-Hop, Routing, Destination Options, Authentication, and atomic
Fragment headers with per-header bounds checks. Non-atomic fragments require reassembly and are
skipped.

#### Compact DNS offsets

A valid IPv6 extension chain can place DNS beyond byte 65535. Internal metadata stores a checked
`u16` delta from the minimum 42-byte Ethernet/IPv4/UDP prefix and reconstructs the absolute offset
when accessing packet bytes.

A maximum IPv6 frame ends at byte 65589 and must leave at least 12 DNS bytes, so the delta covers
the supported range. The UDP-bounded DNS length remains `u16`. Routing metadata measures 42 bytes
on the tested macOS ARM64 target.

### DNS QNAME boundary

#### Shared decoder rules

The standard `hickory` question decoder and optional custom wire fast path enforce the same
RFC 1035 limit after decompression: at most **255 wire octets**, including label-length octets
and the terminating root. An escaped presentation form can reach **1003 bytes** and remains
valid; DPP preserves it for matching and export.

Both decoders also enforce these rules:

- Reject compression pointers that point forward or overlap the current name. Fast-path fallback
  must not accept a message the semantic decoder rejects.
- Reject ordinary QUERY messages (OPCODE 0) with QDCOUNT greater than one, as required by RFC 9619.
- Require complete declared answer and authority records even when ARCOUNT is zero. Their wire
  boundaries are checked before matcher handoff.

#### Oversized-name rejection

If any decompressed QNAME exceeds the wire limit, reject the entire DNS message before matcher
or writer handoff. No question from it may enter matcher state or output.

`oversized_qname_message_count` increments exactly once per rejected message, regardless of
question count. The JSON metric `metrics.dns_messages_rejected_oversized_qname` uses the same
DNS-message unit.

### Monotonic timestamp contract

`--monotonic-capture` requires globally non-decreasing packet timestamps:

| Mode | Timestamp regression | Matcher eviction |
| --- | --- | --- |
| Enabled | `PacketParser` fails on the first regression | Use the batch-maximum timestamp as a global eviction watermark, keeping matcher memory bounded on long captures |
| Disabled (default) | Track regressions and report a post-run warning with the first offending sample | Check per-query timeouts at finalization; long captures with many pending queries use more memory |

The watermark contract is detailed in [RFC 0004](0004-forward-only-matcher.md#batched-timeout-eviction).

## Why not always use libpcap?

On a 10 GB classic PCAP, the pure-Rust reader is measurably faster because it avoids per-packet
FFI and gives DPP control over read buffering. The difference is most visible when high packet
rates make per-packet cost dominant.

`pcap-file` is pinned to `3.0.0-rc1` because the stable line lacks the required API. This is a
dependency risk: if the release candidate is abandoned, DPP will need to vendor or fork it.

## Why fail-fast on monotonic violations?

A timestamp regression can cause batched eviction to retire queries too early and produce
incorrect timeout counts. Failing on the first regression makes a violated assumption visible
instead of silently returning incorrect results.

## Consequences

- Add new capture formats through a new `PacketBackend` variant; keep the parser interface stable.
- Benchmark changes to the pure-Rust reader: it is the performance-critical path.
- Keep stdin within the offline-processing contract, using parser-owned stream-native backends
  for classic PCAP and PCAPNG.
- Retain `libpcap` fallback compatibility for non-classic regular files.
- Revisit the `pcap-file` release candidate when a suitable stable release is available.
