# Protocol correctness: final validation and performance

Updated 2026-09-05 for implementation commit `8881539` on
`feature/protocol-correctness-audit`.

The final implementation retains the protocol and matcher corrections and restores throughput
on the selected 18-million-packet capture. Default mode slightly exceeds the pre-audit version
in the final comparison; monotonic mode is at approximately the same level. The workspace suite
passes **254 tests**, and full CSV output is byte-identical to the correctness-fixed version in
both modes and with both DNS decoders. Peak RSS is higher, approximately 288–301 MiB in these runs.

## Current performance

Each comparison below used ten position-balanced pairs on one macOS ARM64 host. Speed ratios
are the median of paired reference-time / final-time ratios; values above 1 indicate improvement.
The two reference comparisons are separate measurement series, so their absolute timings and RSS
must not be combined as if they were one run.

Against the pre-audit version, `3bb45397baff03a6c7043d2e6cff1508f0161b39`:

| Configuration | Pre-audit median (s) | Final median (s) | Paired speed ratio | Median peak RSS, pre-audit / final (MiB) |
|---|---:|---:|---:|---:|
| Default | 0.9807 | 0.9677 | 1.0134 | 217.7 / 298.4 |
| Monotonic | 0.9580 | 0.9627 | 0.9962 | 221.3 / 287.9 |

Default throughput is about 1.3% higher in this series. The roughly 0.4% monotonic difference is
within the observed run-to-run variation: paired speed ratios ranged from 0.9687 to 1.0394.
These results establish local recovery on this capture, not a throughput or portability guarantee.

Against the correctness-fixed version before optimization, `2ef34a4`:

| Configuration | Fixed median (s) | Final median (s) | Paired speed ratio | Median peak RSS, fixed / final (MiB) |
|---|---:|---:|---:|---:|
| Default | 1.0273 | 0.9758 | 1.0484 | 209.8 / 301.4 |
| Monotonic | 0.9980 | 0.9723 | 1.0290 | 219.0 / 288.4 |

The optimizations improve throughput by about 4.8% and 2.9% respectively in this confirmation
series. Higher occupied pipeline backlog and allocator retention are hypotheses for the RSS
increase; their contributions were not isolated. Queue bounds and payload ownership are unchanged.

## Final implementation

- Routing metadata is **42 bytes on the measured host**. A checked `u16` offset is relative to
  the minimum 42-byte Ethernet/IPv4/UDP prefix. This still represents DNS starts above 65535:
  a maximum IPv6 frame ends at byte 65589 and must leave at least 12 DNS bytes. IP/UDP boundaries,
  QR direction, QCLASS/OPCODE identity and compression validation remain enforced.
- Flow routing collects the existing tuple's `Hash` writes into a 64-byte stack buffer and
  invokes SeaHash once over the bytes. Integer encoding, seeds and the complete digest are
  unchanged, preserving shard assignment and output order. If the input exceeds the buffer
  capacity, its contents are replayed into the original streaming hasher. No additional persistent
  flow state is kept.
- Each pending canonical query owns one optional retry-history pointer. Default mode allocates
  history when a pending retry arrives; later retries can grow its vector. Replacing a canonical
  query with an earlier attempt regroups that identity's unresolved attempts in `O(n log n)`.
  Monotonic mode allocates no retry history. Memory on duplicate-heavy captures therefore depends
  on unresolved attempts; this capture's low duplicate rate does not bound that workload.
- PCAPNG stdin retains parser-owned framing, one section-local interface table and exact signed
  timestamp conversion, including binary/decimal resolution and offsets. Conversion includes
  `u128` division per packet; the reusable block buffer grows with received bytes. Regular-file
  PCAPNG still uses libpcap, and classic PCAP retains its pure-Rust streaming path.
- Known exported DNS type/status labels remain borrowed strings; numeric fallback allocates for
  unknown values. CSV and Parquet share the same canonical formatting contract.

`build.rs` was reviewed and left unchanged. It requests executable stack size and supplies build
metadata. Optimization levels, LTO and codegen units belong to `Cargo.toml`; no compiler or linker
settings were changed during performance recovery.

## Validation

`cargo test --workspace --offline --locked` passes 254 tests. Coverage includes 30 capture-reader
tests, 13 DNS parser regressions, a 720-permutation matcher check, both pipeline execution models,
and CSV/Parquet preservation of unknown codes. Four differential hashing tests compare complete
64-bit digests for address families, ports, 4096 deterministic flows, integer encodings, buffer
boundaries, streaming fallback and repeated `finish` calls.

`cargo fmt --all -- --check` and the CI Clippy command pass:

```sh
cargo clippy --all-targets --no-deps --offline --locked -- \
  -D warnings \
  -A clippy::too_many_arguments \
  -A clippy::type_complexity \
  -A clippy::large_enum_variant
```

Every final comparison preserved packet/query/response/duplicate/match/timeout counters and
average matched RTT. The selected capture contains 18,006,441 packets, 9,013,611 queries,
13,610 duplicates, 8,992,830 responses and matched pairs, and 7,171 timeouts.

Full CSV output was compared against `2ef34a4` with each combination of monotonic mode and
`--dns-wire-fast-path`: 854,848,168 bytes per output, with identical SHA-256 within each pair.
Both decoders produce the same output for a given mode. Default and monotonic modes have different
row ordering by their existing timeout-emission contracts.

| Mode | SHA-256, both reference and final |
|---|---|
| Default | `02db37f51a60a84000b457c47339fb87bd725071c4e08899f3e8b90b430f9fc9` |
| Monotonic | `08f435bc3aa241615937e3c08b4c089570d5e3dbe9fb245a46c8e9bd3d680bc0` |

## Measurement method

The explicitly selected input was `synthetic/server1-like.pcap`. All compared binaries were built
with Rust 1.97.1 using `cargo build --profile perf`, default jemalloc and no additional RUSTFLAGS.
This profile inherits release's `opt-level=3`, LTO and one codegen unit, and disables overflow
checks for trusted benchmark input; the production release profile keeps overflow checks enabled.

The host exposed 16 CPUs, giving 14 matcher workers in staged mode. Affinity was disabled, CSV
output went to `/dev/null`, and bounded output settings were identical. Runs alternated reference /
final and final / reference order, with an excluded warmup pair per mode and no subsequent outlier
removal. Timings include process startup and shutdown. The capture was read from the filesystem
cache, so these results do not measure cold-storage performance. Peak RSS was collected per child
with `wait4`. See [README.md](README.md) for the benchmark scaffold and explicit-input contract.

## Earlier measurements and discarded experiments

Before optimization, the correctness fixes showed about 5.6% lower default throughput and 4.8%
lower monotonic throughput in the initial comparison. Those figures describe the intermediate
`2ef34a4` implementation, not the current version. Compact relative offsets and buffered flow
hashing were subsequently retained on measurement evidence.

Short four-pair screens did not justify retaining query-helper inlining/cold regrouping, CSV
formatter inlining, a fused borrowed matcher lookup, or a new packed hash input. The final code
contains none of those experimental changes. CPU sampling identified packet routing and its
streaming hash calls as the limiting stage on this capture.

An earlier PCAPNG-reader check compared the pre-audit reader with the correctness-fixed reader
using the first 1,000,000 packets re-encoded as little-endian Enhanced Packet Blocks. Three pairs
measured 0.0780 / 0.0787 seconds, with identical processing counters. The roughly 80 ms runs were
too short to establish a timing change. This is reader-validation history, not a final PCAPNG
throughput benchmark.
