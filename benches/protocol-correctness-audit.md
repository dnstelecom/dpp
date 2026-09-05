# Protocol correctness audit measurements

The fixes were checked against baseline commit `3bb45397baff03a6c7043d2e6cff1508f0161b39`
on 2026-09-05. Both binaries were built with Rust 1.97.1 using `cargo build --profile perf`,
default jemalloc, and no additional RUSTFLAGS. Measurements used one macOS ARM64 host with
16 available CPUs (14 matcher workers in staged mode), affinity disabled, CSV output to
`/dev/null`, and the same bounded output settings. These are local regression measurements,
not throughput or portability guarantees.

The explicitly selected input was `synthetic/server1-like.pcap`: 18,006,441 packets,
9,013,611 DNS queries, 13,610 duplicates, 8,992,830 matched pairs and 7,171 timeouts.
All six packet/query/response/duplicate/match/timeout counters agreed between baseline and
candidate in every measured run. Both the default and monotonic configurations were measured.
Runs alternated baseline/candidate and candidate/baseline order, with ten pairs per configuration.
Times include process startup and shutdown. The input was read from the local filesystem cache;
these results do not measure cold-storage performance. Peak RSS was collected per child with
`wait4`, rather than a periodically sampled process monitor.

A separate stdin PCAPNG check used the first 1,000,000 packets from that capture, manually
re-encoded as little-endian Enhanced Packet Blocks with default microsecond resolution. Three
alternating pairs compared both stream readers. Each run lasted roughly 80ms, so small timing
changes in this check are inconclusive; its primary result is identical processing counters.

| Input / configuration | Pairs | Baseline median (s) | Candidate median (s) | Median paired speed ratio |
|---|---:|---:|---:|---:|
| Classic PCAP / default | 10 | 0.9731 | 1.0284 | 0.9442 |
| Classic PCAP / monotonic | 10 | 0.9609 | 1.0060 | 0.9524 |
| PCAPNG / stdin | 3 | 0.0780 | 0.0787 | 0.9858 |

A speed ratio below 1 means the candidate was slower. The representative classic-PCAP runs
show about 5.6% lower throughput in default mode and 4.8% in monotonic mode. The difference is
consistent across the paired series, but individual runs are short and these measurements do
not isolate the cost of each correctness fix. Peak RSS varied substantially with pipeline
scheduling; this fixture showed no RSS increase, but it cannot establish a memory improvement
or bound the duplicate-heavy case below. The roughly 1.4% PCAPNG timing difference is within
the uncertainty of the 80ms runs.


Memory and hot-path implications:

- Every pending canonical query now has one optional retry-history pointer. In default mode,
  a first pending retry allocates one history object; subsequent retries may grow its vector.
  Histories are owned by the canonical query and discarded with that query. Memory now scales
  with unresolved retry attempts on duplicate-heavy captures; the representative fixture's
  low duplicate fraction does not bound that worst case.
- Monotonic mode allocates no retry history. Regrouping is limited to an earlier query replacing
  a pending canonical, and costs `O(n log n)` for that identity's unresolved attempts.
- On this host, routed DNS metadata increased from 42 to 44 bytes, to support a valid DNS
  offset beyond 65535 after IPv6 extension headers. QR/class/opcode and compression checks
  also add hot-path work.
- Exact PCAPNG conversion adds one `u128` division per packet and owns a reusable block buffer.
  That path no longer allocates an entire declared block length before receiving its contents.
- Known DNS type/status labels remain borrowed strings. Numeric fallback allocates only for
  unknown values; CSV and Parquet use the same canonical formatting contract.

The full workspace suite passes 248 tests, including manually encoded PCAPNG boundaries,
11 DNS parser regressions, a 720-permutation matcher check, both pipeline execution models,
and CSV/Parquet preservation of unknown codes. `cargo fmt --all -- --check` and the CI Clippy
command also pass. See the benchmark scaffold in [README.md](README.md) for future measurements
on caller-selected production-like captures.

## Performance recovery follow-up

The first accepted optimization stores the DNS start relative to the minimum 42-byte
Ethernet/IPv4/UDP prefix. The full validated range still fits: even a maximum-length IPv6 frame
must leave at least 12 DNS bytes. Routing metadata returns from 44 to 42 bytes on this host,
including packets whose absolute DNS start exceeds 65535. Tests cover minimum headers, maximum
IPv4/IPv6 lengths, and the longest accepted IPv6 extension prefix.

Ten new position-balanced pairs against the correctness-fixed version (`2ef34a4`) used the same
capture and build settings above, with an excluded warmup pair per mode. Relative offsets alone
gave median times of 1.0274 / 0.9924 seconds (reference / candidate) in default mode and
1.0136 / 1.0009 seconds in monotonic mode. Median paired speed ratios were 1.0318 and 1.0133.
All processing counters and average matched RTT agreed. Faster routing can increase the occupied
pipeline backlog and measured RSS despite smaller metadata: median peak RSS was 189.9 / 284.9 MiB
in default mode and 198.7 / 272.2 MiB in monotonic mode. Scheduling is a hypothesis for this
increase, not an isolated causal measurement. This is a throughput optimization, not a claim of
lower process memory. Queue bounds and payload ownership are unchanged.

Short four-pair screens rejected query-helper inlining/cold regrouping, CSV formatter inlining,
and a fused borrowed matcher lookup: none showed a consistent end-to-end improvement in default
mode. A CPU sample located the limiting stage in packet routing and its streaming hash calls.
`build.rs` was also checked: it sets executable stack size and build metadata, and was unchanged
by the correctness fixes. Optimization levels, LTO and codegen units remain owned by `Cargo.toml`;
no compiler or linker settings were changed for this recovery work.

The final routing optimization collects the unchanged tuple `Hash` writes in a 64-byte stack
buffer, then calls the existing SeaHash buffer implementation once. Integer byte order, seeds,
the complete digest and the shard modulo remain unchanged. Overflow replays the prefix into the
original streaming hasher. Differential tests cover IPv4, IPv6, mixed families, ports, 4096
deterministic flows, integer encodings, capacity boundaries and repeated `finish` calls.

A separate experiment packed addresses and ports into a new network-order hash input. It passed
targeted correctness tests but was slower than the digest-preserving adapter in both four-pair
screens, so it was discarded. Matcher and CSV formatter experiments were also discarded.

With relative offsets and buffered hashing together, ten position-balanced pairs against the
pre-audit version (`3bb4539`) gave the following local results:

| Configuration | Pre-audit median (s) | Final median (s) | Median paired speed ratio |
|---|---:|---:|---:|
| Default | 0.9807 | 0.9677 | 1.0134 |
| Monotonic | 0.9580 | 0.9627 | 0.9962 |

A separate ten-pair confirmation against correctness-fixed `2ef34a4` measured 1.0273 / 0.9758
seconds (reference / final) in default mode and 0.9980 / 0.9723 seconds in monotonic mode.
Median paired speed ratios were 1.0484 and 1.0290. Median peak RSS was 209.8 / 301.4 MiB and
219.0 / 288.4 MiB respectively. Both series used an excluded warmup pair per mode and retained
all subsequent samples.

Default throughput is restored and slightly exceeds the old version in this series. The
monotonic difference is within the observed run-to-run variation (paired ratios 0.9687–1.0394).
These are macOS ARM64 results for this selected capture, not a guarantee for other workloads.
Median peak RSS in the same comparison was 217.7 / 298.4 MiB (pre-audit / final) in default mode
and 221.3 / 287.9 MiB in monotonic mode. The speed recovery therefore comes with higher observed
RSS on this host; the existing queue bounds and ownership model remain unchanged.

Full CSV output against the correctness-fixed version was byte-identical in both monotonic
settings and with both DNS decoders: 854,848,168 bytes per output. SHA-256 was
`02db37f51a60a84000b457c47339fb87bd725071c4e08899f3e8b90b430f9fc9` in default mode and
`08f435bc3aa241615937e3c08b4c089570d5e3dbe9fb245a46c8e9bd3d680bc0` in monotonic mode.
All packet/query/response/duplicate/match/timeout counters and average matched RTT agreed.
The final workspace suite passes 254 tests, including all earlier protocol regressions.
