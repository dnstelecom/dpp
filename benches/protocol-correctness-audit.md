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
