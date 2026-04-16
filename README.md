<p align="left">
  <a href="https://github.com/dnstelecom/dpp">
    <img src="assets/dpp_mascote.svg" alt="DNS Packet Processor mascot" width="180">
  </a>
</p>

# DNS Packet Processor (DPP) — Community Edition

<p align="left">
  <img alt="License: GPLv3" src="https://img.shields.io/badge/License-GPLv3-blue.svg">
  <a href="https://github.com/dnstelecom/dpp/releases/latest">
    <img alt="Latest release" src="https://img.shields.io/github/v/release/dnstelecom/dpp?display_name=tag">
  </a>
</p>

<p align="left">
  High-performance offline DNS extraction from PCAP to CSV or Parquet.
</p>

DPP is a Rust application for parsing, matching, and exporting DNS query/response traffic from offline PCAP files. It is designed for large captures, bounded parallel processing, and downstream analytics workflows.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Documentation](#documentation)
- [Prerequisites](#prerequisites)
- [Build](#build)
- [Usage](#usage)
- [Example run](#example-run)
- [A simple AWK analysis to measure DNS traffic latency](#a-simple-awk-analysis-to-measure-dns-traffic-latency)
- [Performance Optimization](#performance-optimization)
- [Limitations](#limitations)
- [Commercial Edition](#commercial-edition)
- [License](#license)

## Overview

DPP reads offline PCAP files, extracts DNS traffic, matches queries with responses, and writes structured output to CSV or Parquet. The pipeline emphasizes throughput, bounded backpressure, deterministic aggregation, and optional IP pseudonymization.

## Features

- Offline capture parsing through a pure-Rust classic-PCAP reader, stream-native stdin support for classic PCAP and PCAPNG, and `libpcap` fallback for non-classic file inputs.
- Multi-threaded processing with cheap packet routing, canonical flow-based shard ownership, and deterministic aggregation under parallel load.
- Adaptive runtime behavior: low-core hosts fall back to a simpler phase-parallel path.
- DNS query/response matching using source and destination IPs, ID, QNAME, QTYPE, and closely aligned timestamps.
- A single forward-only matching mode with retry deduplication inside the configurable match-timeout window (`1200ms` by default).
- Optional monotonic-capture mode for globally ordered captures, enabling batched timeout eviction with fail-fast validation on timestamp regressions.
- CSV and Parquet output, with optional Zstandard (`zstd`) compression for Parquet.
- Asynchronous output pipeline to reduce write-side overhead.
- Optional deterministic IP pseudonymization.
- Peak RSS memory tracking for performance analysis.
- Graceful `SIGINT`/`SIGTERM` handling that stops intake and drains in-flight work; any still-buffered output tail is discarded before final writer teardown to avoid a skewed partial ending.
- Graceful handling of malformed packets and I/O errors.

## Architecture

The table below is a high-level map of the system. For the canonical architecture reference,
ownership boundaries, and matcher invariants, see [docs/architecture.md](docs/architecture.md).

| Layer                       | Components                                                    | Responsibility                                                                         |
|-----------------------------|---------------------------------------------------------------|----------------------------------------------------------------------------------------|
| Configuration and contracts | `src/config.rs`, `src/cli.rs`, `src/record.rs`                | Runtime constants, CLI/environment contract, and exported `DnsRecord` schema           |
| Input parsing               | `PacketParser`                                                | Offline capture input with pure-Rust classic-PCAP parsing, stream-native stdin parsing, and `libpcap` fallback for non-classic file inputs |
| DNS processing              | `DnsProcessor`, `pipeline.rs`                                 | Packet routing, DNS decoding, matching, shard ownership, and deterministic aggregation |
| Runtime and orchestration   | `src/app.rs`, `src/runtime.rs`, `src/allocator.rs`            | App lifecycle, bootstrap, reporting, thread-pool setup, and allocator selection        |
| Output pipeline             | `src/output.rs`, `src/csv_writer.rs`, `src/parquet_writer.rs` | Async writer lifecycle and CSV/Parquet serialization                                   |
| Memory monitoring           | `src/monitor_memory.rs`                                       | Peak RSS tracking with explicit stop/join lifecycle                                    |
| References and benchmarks   | `docs/rfc/`, `benches/`                                       | Architecture decisions, benchmark workflow, and harnesses                              |

## Documentation

- Canonical architecture reference: [docs/architecture.md](docs/architecture.md)
- Architecture decision records: [docs/rfc/README.md](docs/rfc/README.md)
- Benchmark workflow: [benches/README.md](benches/README.md)
- Benchmark harness: [benches/benchmark.sh](benches/benchmark.sh)
- Contribution guide: [CONTRIBUTING.md](CONTRIBUTING.md)
- Allocator guide: [docs/allocator-guide.md](docs/allocator-guide.md)
- Allocator benchmarking protocol: [benches/allocator-benchmarking.md](benches/allocator-benchmarking.md)
- Encapsulation handling playbook: [docs/encapsulation-playbook.md](docs/encapsulation-playbook.md)
- Synthetic DNS PCAP generator: [docs/synthetic-pcap-generator.md](docs/synthetic-pcap-generator.md)

## Prerequisites

- [Rust](https://rustup.rs/)
- Cargo
- PCAP files for offline processing
- `libpcap` development headers for fallback support on non-classic formats

Ubuntu/Debian:

```bash
sudo apt-get install libpcap-dev
```

## Build

Standard release build:

```bash
cargo build --release
```

For best throughput on the target host:

```bash
RUSTFLAGS='-C target-cpu=native' cargo build --release
```

Performance benchmarking build:

```bash
cargo build --profile perf
```

The `perf` profile inherits from `release` but disables release overflow checks. Use it only for
trusted performance measurements on representative input. The default `release` profile remains the
safe production build.

## Usage

### Basic examples

```bash
# Export to CSV
dpp input.pcap output.csv

# Export to Parquet
dpp -f parquet input.pcap output.pq

# Export to Parquet with Zstd compression
dpp -f parquet --zstd input.pcap output.pq

# Enable deterministic IP pseudonymization
dpp --anonymize /tmp/anon.key input.pcap output.csv

# Quiet mode
dpp -s -f parquet input.pcap dns_output.pq

# Stream CSV records to stdout
dpp input.pcap - > output.csv

# Read an offline PCAP stream from stdin
cat input.pcap | dpp - output.csv

# Emit a machine-readable JSON summary object at the end of the run
dpp --report-format json input.pcap output.csv > dpp-summary.json
```

If `output_filename` is omitted, DPP chooses the default file name from the resolved output format:
`dns_output.csv` for `csv` and `dns_output.parquet` for `parquet` or `pq`. Use `-` only when you
want CSV records on stdout.

The final text/JSON report includes both packet-level drop accounting and signal-shutdown
record-loss accounting. `dropped_packets` is a packet-level derived aggregate over the detailed
drop-path counters `routed_non_dns`, `unsupported_encapsulation`, `dns_decode_error`,
`dns_name_error`, and `dropped_on_shutdown`. `decode_errors` is the derived sum of
`dns_decode_error` and `dns_name_error`. Signal-driven record losses are surfaced separately as
`skipped_finalization_records_on_shutdown`, `discarded_output_tail_records_on_shutdown`, and the
derived `shutdown_record_losses`. `dns_name_error` remains a derived aggregate over the exact DNS
name subreason counters `dns_name_truncated`, `dns_name_too_long`,
`dns_name_compression_pointer_truncated`, `dns_name_compression_pointer_out_of_bounds`,
`dns_name_compression_pointer_loop`, `dns_name_unsupported_label_encoding`, and
`dns_name_label_truncated`.

Policy notes:

- `routed_non_dns` counts packets that were ingested successfully but did not qualify for the
  UDP/53 DNS routing contract after successful Ethernet/IP/UDP routing.
- `unsupported_encapsulation` counts packets whose Ethernet framing is outside the supported plain
  IPv4/IPv6 path, plus malformed Ethernet/IP/UDP routing-stage packets.
- `dns_decode_error` counts packets that reached UDP/53 routing but failed a structural DNS decode
  check, including trivially short DNS payloads rejected before shard dispatch.
- `dns_name_error` is the aggregate over exact DNS name parse failures. The summary also exposes
  the detailed subreason counters listed above, and those buckets remain populated regardless of
  whether `--dns-wire-fast-path` is enabled.
- `dropped_on_shutdown` counts packets that were already read into a batch but intentionally not
  handed to the processing pipeline after a termination signal was observed.
- `skipped_finalization_records_on_shutdown` counts terminal records that would have been emitted
  from pending unmatched queries during end-of-run matcher finalization, but were intentionally
  skipped after a termination signal.
- `discarded_output_tail_records_on_shutdown` counts already-materialized `DnsRecord` values that
  remained buffered inside the async writer when abort teardown discarded the tail.
- `shutdown_record_losses` is the derived sum of the two signal-shutdown record-loss counters above
  and is not folded into packet counters.

### Create an anonymization key

`--anonymize` expects a text file. DPP reads the file contents as a passphrase and derives the
internal pseudonymization key from that value.

One practical way to create a key file on Linux or macOS is:

```bash
umask 077
openssl rand -hex 32 > /tmp/anon.key
```

Then use it like this:

```bash
dpp --anonymize /tmp/anon.key input.pcap output.csv
```

Notes:

- Keep the key file private. Anyone with the same file can reproduce the same pseudonymized output.
- The key file must contain valid UTF-8 text because DPP reads it as a text passphrase.
- Rotating the key changes the resulting pseudonymized IP addresses for the same input capture.
- DPP intentionally uses a fixed PBKDF2 salt for deterministic pseudonymization. The passphrase is
  still the operator-controlled secret; changing it rotates the derived pseudonyms.
- If `--anonymize` or `DPP_ANONYMIZE` is configured and the key file is missing, unreadable, or
  invalid, DPP exits with an error. It does not silently fall back to pass-through IP addresses.

### Arguments

| Argument          | Description                                                                                                                                                       |
|-------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `filename`        | Path to the input PCAP file. Use `-` to read a finite offline PCAP stream from `stdin`.                                                                         |
| `output_filename` | Optional output file path. If omitted, DPP writes to `dns_output.csv` for `csv` and to `dns_output.parquet` for `parquet` or `pq`. Use `-` for CSV stdout output. |

### Options

| Option                            | Description                                                                                                         |
|-----------------------------------|---------------------------------------------------------------------------------------------------------------------|
| `-s, --silent`                    | Suppress info-level log output                                                                                      |
| `-f, --format <csv\|parquet\|pq>` | Select output format; stdout output is supported only for `csv`                                                     |
| `--report-format <text\|json>`    | Select the final process report format; defaults to `text`; `json` cannot be combined with `output_filename = -`    |
| `--match-timeout-ms <MS>`         | Set the DNS query-response match timeout in milliseconds; allowed range is `1..=5000`, default is `1200`            |
| `--monotonic-capture`             | Assume globally monotonic packet timestamps, enable batched timeout eviction, and abort if a regression is detected |
| `-b, --bonded <N>`                | Set I/O channel capacity; `0` uses the safe default bounded capacity                                                |
| `-z, --zstd`                      | Enable Zstd compression for Parquet output                                                                          |
| `--v2`                            | Use Parquet Version 2                                                                                               |
| `-a, --affinity`                  | Enable core affinity                                                                                                |
| `--dns-wire-fast-path`            | Enable the optional question-only DNS wire fast path with `hickory` fallback                                        |
| `--anonymize <path>`              | Path to the pseudonymization key file                                                                               |
| `-h, --help`                      | Print help                                                                                                          |
| `-V, --version`                   | Print version                                                                                                       |

### Environment variables

| Variable                 | Description                                                                                                               |
|--------------------------|---------------------------------------------------------------------------------------------------------------------------|
| `DPP_FILENAME`           | Input PCAP path. Use `-` to read a finite offline PCAP stream from `stdin`                                              |
| `DPP_OUTPUT_FILENAME`    | Optional output file path; use `-` for CSV stdout output                                                                  |
| `DPP_FORMAT`             | Output format: `csv`, `parquet`, or `pq`                                                                                  |
| `DPP_REPORT_FORMAT`      | Final process report format: `text` or `json`; defaults to `text`; `json` cannot be combined with `DPP_OUTPUT_FILENAME=-` |
| `DPP_MATCH_TIMEOUT_MS`   | DNS query-response match timeout in milliseconds; allowed range is `1..=5000`, default is `1200`                          |
| `DPP_MONOTONIC_CAPTURE`  | Assume globally monotonic packet timestamps, enable batched timeout eviction, and abort if a regression is detected       |
| `DPP_BONDED`             | I/O channel capacity; `0` uses the default bounded capacity                                                               |
| `DPP_ZSTD`               | Enable Zstd compression for Parquet output                                                                                |
| `DPP_V2`                 | Enable Parquet Version 2                                                                                                  |
| `DPP_AFFINITY`           | Enable CPU affinity                                                                                                       |
| `DPP_DNS_WIRE_FAST_PATH` | Enable the optional DNS wire fast path                                                                                    |
| `DPP_ANONYMIZE`          | Path to the key file used for pseudonymization                                                                            |
| `DPP_SILENT`             | Suppress info-level log output                                                                                            |

If neither `output_filename` nor `DPP_OUTPUT_FILENAME` is set, DPP chooses the default output path
from the resolved format: `dns_output.csv` for `csv` and `dns_output.parquet` for `parquet` or
`pq`.

When `output_filename` is `-`, DPP writes CSV records to stdout, suppresses non-error log output, and does not emit
the final text report. `--format parquet`, `--report-format json`, and `DPP_REPORT_FORMAT=json` are rejected in this
mode.

When `filename` is `-`, DPP reads a finite offline PCAP stream from `stdin` until EOF and then completes the run
normally. This preserves the existing offline-processing contract: `stdin` is not treated as a live capture source.
Classic PCAP streams on `stdin` now use the same pure-Rust parser family as classic file input, and PCAPNG streams
also use a stream-native parser path. For regular files, non-classic formats still fall back to `libpcap`.
Unsupported non-PCAP/non-PCAPNG stream magic on `stdin` is rejected explicitly instead of being redirected through a
hidden temp-file or second ingest path.

Repeated pending queries that share the same match identity (`id`, `name`, client IP, client port,
and `query_type`) inside the configured match window (`1200ms` by default) are deduplicated to the earliest canonical
query. Deduplicated retries increment a separate counter and do not emit extra timeout or matched
records.

For QNAME matching, DPP preserves the observed presentation-form name bytes and does not lowercase
them before building matcher identity keys. This is a deliberate Community Edition trade-off, not
an RFC-level guarantee: RFC 4343 defines ASCII label comparison as case-insensitive, and a valid
response is allowed to differ from the query's 0x20 casing, including when name compression
reuses label bytes from another wire location. DPP still keeps byte-preserving matcher identity
because that better matches the real behavior we target on offline caching-resolver workloads. As
a result, a query and response that differ only by case may fail to match even on otherwise valid
DNS traffic.

Timeout records leave response fields empty:

- `response_timestamp = NULL` in Parquet and an empty field in CSV
- `response_code = NULL` in Parquet and an empty field in CSV

This means "no matching response was observed inside the configured timeout window". It does not
mean the upstream server actually returned `ServFail`. Downstream timeout detection should key off
the absent `response_timestamp`; `response_code` is absent because no DNS response exists.

With `--report-format json` or `DPP_REPORT_FORMAT=json`, DPP suppresses routine `info`/`warn`
reporting and emits one final JSON summary object to `stdout`. This keeps CSV or Parquet output in
its own file while making the end-of-run report easy to capture and parse.

If DPP receives `SIGINT` or `SIGTERM`, it stops accepting new packet batches, drains already
accepted work, skips synthetic timeout finalization for pending unmatched queries, discards any
still-buffered output tail, and then exits. This applies to CSV and Parquet outputs alike. The
final JSON summary reports this through the `warnings.graceful_signal_shutdown` field.

The final report now also includes basic matching-quality metrics:

- `metrics.timed_out_queries`
- `metrics.timed_out_query_ratio`
- `metrics.average_matched_rtt_ms`

If packet timestamps move backwards in capture order, DPP emits a red warning after processing.
Matching remains deterministic, but timestamp-based pairing quality may degrade on such input.
When that warning appears, normalize the capture first with Wireshark's `reordercap`, for example:
`reordercap input.pcap normalized.pcap`

## Synthetic Capture Generation

This repository also ships a standalone utility, `dns-pcap-generator`, for producing synthetic DNS
classic-PCAP files without needing a source capture at runtime.
The tool lives in the separate workspace crate `tools/dns-pcap-generator`; from the repository root,
use `-p dns-pcap-generator`, or run the same commands directly inside that directory without `-p`.

Example:

```bash
cargo run -p dns-pcap-generator --release --bin dns-pcap-generator -- \
  --profile-dir tools/dns-pcap-generator/profiles/server1-jul-2024 \
  synthetic/server1-like.pcap \
  --duration-seconds 300 \
  --qps 30000
```

The generator always runs from a fitted profile artifact directory:

```bash
cargo run -p dns-pcap-generator --release --bin dns-pcap-generator -- \
  --profile-dir tools/dns-pcap-generator/profiles/server1-jul-2024 \
  synthetic/server1-like-fitted.pcap \
  --transactions 500000
```

To regenerate the workspace positive-domain catalog from a local CSV:

```bash
cargo run -p dns-catalog-builder --release -- \
  real_dns_traffic.csv \
  tools/dns-pcap-generator/catalog_data.tsv \
  --top 10000
```

The checked-in `server1-jul-2024` profile is shaped after a representative July 2024 resolver
workload while keeping only sanitized, non-client-specific domains. Its
`fitted-generator.toml` lives under `tools/dns-pcap-generator/profiles/server1-jul-2024`, while
the profile's `catalog_path` points back to `tools/dns-pcap-generator/catalog_data.tsv` so the
sanitized catalog remains a single reviewable source of truth. The generator verifies the
referenced catalog digest before generation. See
[docs/synthetic-pcap-generator.md](docs/synthetic-pcap-generator.md) for the full contract and
current modeling assumptions.

For captures that are already globally monotonic by timestamp, `--monotonic-capture` or
`DPP_MONOTONIC_CAPTURE=1` enables batched timeout eviction inside the matcher. This can reduce
in-flight matcher RSS, but the run will abort on the first detected timestamp regression so the
optimization does not silently weaken matching semantics.

## Example run

The log below is illustrative. Exact throughput, memory usage, and match counters depend on the hardware, build profile, capture shape, and matcher revision.

```bash
# On Intel(R) Atom(TM) x7425E with power-save profile.
# No output file name is specified here, so CSV mode uses the default output path: dns_output.csv.
$ DPP_FILENAME=server1_jul_2024.pcap DPP_FORMAT=csv target/release/dpp --dns-wire-fast-path --monotonic-capture 
04:15:01.046  INFO DNS Packet Parser (DPP) community edition, version hash: dbed8b3
04:15:01.046  INFO Git Commit Author: k.mikhailov@dnstele.com
04:15:01.046  INFO Git Timestamp: 2026-03-26T06:06:59.000000000+02:00
04:15:01.046  INFO Build Timestamp: 2026-03-26T04:08:26.901327423Z
04:15:01.046  INFO Build Hostname: hel-atom1
04:15:01.046  INFO Allocator: tikv-jemallocator
04:15:01.046  INFO > This software is licensed under under GNU GPLv3.
04:15:01.046  INFO > Commercial licensing options: carrier-support@dnstele.com
04:15:01.046  INFO > Nameto Oy (c) 2026. All rights reserved.
04:15:01.062  INFO OS: Linux, ARCH: x86_64
04:15:01.062  INFO Available parallelism: 4, execution budget: auto (all available CPUs), Affinity: false
04:15:01.062  INFO Free memory (system reported): 2,857 MB
04:15:01.062  INFO Starting to process PCAP file: /mnt/mirror/src/dpp/server1_jul_2024.pcap
04:15:01.062  INFO Processing mode: forward sorting with response-query matching
04:15:01.062  INFO IO channel: BOUNDED with 131,072 elements (default)
04:15:01.076  INFO Format is: CSV
04:15:01.076  INFO Anonymization: False
04:15:01.076  INFO DNS wire fast path: enabled (question-only decoder with hickory fallback)
04:15:01.076  INFO DNS match timeout: 1200 ms
04:15:01.076  INFO Monotonic capture mode: enabled (batched timeout eviction active; timestamp regressions abort the run)
04:15:01.076  INFO PID: 501755
04:15:01.147  INFO Results will be written to: /mnt/mirror/src/dpp/dns_output.csv
04:15:01.150  INFO Execution budget: auto using 4 CPUs, phase-parallel pipeline selected for low-core host, Rayon worker budget: 4
04:15:16.718  INFO Total packets processed: 40,000,000
04:15:16.718  INFO Total DNS queries processed: 19,670,037
04:15:16.718  INFO Deduplicated duplicate queries: 23,947
04:15:16.718  INFO Total DNS responses processed: 19,662,289
04:15:16.718  INFO Total matched Query-Response pairs: 19,630,152
04:15:16.718  INFO Timed-out queries: 15,938 (0.08%)
04:15:16.718  INFO Average matched RTT: 1.304 ms
04:15:16.718  INFO Processing speed: 2,685,468 packets per second
04:15:16.718  INFO Final write post-processing completed in +0.778 seconds
04:15:16.718  INFO Max memory usage (RSS): 169,256 KiB
04:15:16.718  INFO Processing completed in: "00:00:15.672"

```

### What DPP produces in CSV output

DPP writes one row per canonical DNS query outcome.

```csv
request_timestamp,response_timestamp,source_ip,source_port,id,name,query_type,response_code
1774783431482391,1774783431503127,10.0.0.1,53000,4660,example.com,A,No Error
1774783447118904,,10.0.0.2,53001,48879,example.org,A,
```
What this tells you:

- the first query for example.com A was matched with a response about 20.736 ms later;
- the second query for example.org A had no matching response within the timeout window;
- empty response_timestamp and response_code mean timeout.

### A simple AWK analysis to measure DNS traffic latency
```bash
$ gawk -F',' '
NR > 1 {
    total++
    req = $1
    resp = $2

    if (req == "") { invalid++; next }
    if (resp == "") { timeout++; next }

    d_ms = (resp - req) / 1000.0
    if (d_ms < 0) { invalid++; next }

    ok++
    sum += d_ms
    a[ok] = d_ms
}
END {
    printf "total_rows:    %d\n", total
    printf "ok_rows:       %d\n", ok
    printf "timeout_rows:  %d\n", timeout
    printf "invalid_rows:  %d\n", invalid
    printf "timeout_ratio: %.4f%%\n", (total ? 100.0 * timeout / total : 0)

    if (ok == 0) exit 0

    asort(a)
    mean = sum / ok
    median = (ok % 2) ? a[(ok + 1) / 2] : (a[ok / 2] + a[ok / 2 + 1]) / 2

    printf "mean_ms:       %.6f\n", mean
    printf "median_ms:     %.6f\n", median
    printf "p50_ms:        %.6f\n", pct(a, ok, 50)
    printf "p95_ms:        %.6f\n", pct(a, ok, 95)
    printf "p99_ms:        %.6f\n", pct(a, ok, 99)
    printf "p99.9_ms:      %.6f\n", pct(a, ok, 99.9)
}
function pct(arr, n, p, rank, x) {
    x = (p / 100) * n
    rank = int(x)
    if (x > rank) rank++
    if (rank < 1) rank = 1
    if (rank > n) rank = n
    return arr[rank]
}
' dns_output.csv
total_rows:    19646090
ok_rows:       19630152
timeout_rows:  15938
bad_rows:      0
mean_ms:       1.303967
median_ms:     0.021000
p50_ms:        0.021000
p95_ms:        0.034000
p99_ms:        34.479000
p99.9_ms:      257.322000
```


## Performance Optimization

For best throughput on the target host:

```bash
RUSTFLAGS='-C target-cpu=native' cargo build --release
```

Additional notes:

- Use [benches/benchmark.sh](benches/benchmark.sh) with `DPP_BENCH_PCAP` or `--pcap` to measure throughput and shutdown tail on representative input.
- See [benches/README.md](benches/README.md) for the benchmark contract and data-handling notes.
- For apples-to-apples performance testing, prefer the dedicated `perf` build profile:
  `cargo build --profile perf` or `DPP_BENCH_PROFILE=perf bash benches/benchmark.sh ...`.
- DPP auto-sizes its execution budget from all available CPUs.
- Historical `--threads` and `DPP_THREADS` inputs are accepted only as deprecated compatibility no-ops and emit a warning if used.
- The parser fast path is opt-in through `--dns-wire-fast-path` or `DPP_DNS_WIRE_FAST_PATH=1`; without that flag DPP uses the legacy `hickory` question decoder.
- For captures normalized with `reordercap`, `--monotonic-capture` can reduce in-flight matcher state by enabling batched timeout eviction. If a timestamp regression is detected, DPP fails the run instead of silently weakening matching semantics.
- Global allocator choice is a build-time concern. See [docs/allocator-guide.md](docs/allocator-guide.md) for the supported allocator matrix and [benches/allocator-benchmarking.md](benches/allocator-benchmarking.md) for the comparison protocol.

## Limitations

- **UDP/53 only:** DPP currently processes DNS traffic over UDP port 53 only.
- **PCAPNG support level:** DPP supports PCAPNG on stream input and via `libpcap` on regular-file fallback paths, but the performance-critical pure-Rust fast path remains focused on classic PCAP.
- **Outer encapsulation layers:** The fast extraction path assumes Ethernet followed by IPv4 or IPv6. Captures containing VLAN, QinQ, MPLS, or similar outer encapsulation layers may require preprocessing first. See [docs/encapsulation-playbook.md](docs/encapsulation-playbook.md).
- **Unsorted exported data:** CSV and Parquet outputs are not guaranteed to be timestamp-sorted.
- **Variable RAM usage:** Memory usage depends on capture size, traffic shape, and output backpressure. Larger `--bonded` values increase peak memory usage under slow output sinks.
- **Monotonic-capture mode is explicit:** Batched timeout eviction is available only with `--monotonic-capture` because it depends on globally monotonic packet timestamps. If the capture is not monotonic, DPP aborts and recommends `reordercap`.
- **Scaling ceilings on skewed workloads:** DPP auto-sizes from all available CPUs, but flow-affinity ceilings can still limit scaling before linear speedup.
- **Duplicate query handling:** Duplicate in-flight DNS queries and responses are preserved and resolved through deterministic matcher tie-breakers derived from capture order. Duplicate-heavy workloads can still increase matcher memory usage, and Parquet output may vary byte-for-byte because writers remain asynchronous.
- **QNAME casing trade-off:** Matcher identity preserves observed QNAME casing instead of canonicalizing names to lowercase. RFC 4343 allows ASCII-label case-only differences between a query and a valid response, and name compression can contribute to that mismatch. Community Edition still matches on observed bytes because that better reflects the caching-resolver workloads it targets. As a result, names that differ only by case may not match even on protocol-compliant traffic.

## Commercial Edition

DPP Community Edition is focused on deterministic offline DNS processing from PCAP into portable export formats.

DPP Commercial Edition extends that foundation with broader capture support, enterprise integrations, compliance-oriented capabilities, and deployment options for production environments.

| Community Edition                                     | Commercial Edition                                                                              |
|-------------------------------------------------------|-------------------------------------------------------------------------------------------------|
| Offline PCAP processing                               | Native S3 integration for reading PCAP                                                          |
| CSV and single-file Parquet export                    | Partitioned Parquet datasets, not just single-file export                                       |
| Current encapsulation scope                           | Advanced encapsulation support: native support for VLAN, QinQ, MPLS, GRE, VXLAN, ERSPAN, Geneve |
| Local file outputs                                    | Direct enterprise sinks: ClickHouse, Kafka, S3, PostgreSQL outputs                              |
| Batch-oriented processing                             | Live/continuous ingestion                                                                       |
| Deterministic pseudonymization with file-based keying | Commercial anonymization/compliance features                                                    |
| Current DNS field and message coverage                | Extended DNS protocol coverage                                                                  |
| Standalone synthetic DNS PCAP generation              | Profile extraction, fitting, and validation pipeline for calibrated synthetic DNS traffic       |
| Checked-in runtime traffic profiles                   | Fitted profiles derived from reference captures, with validation reports and tuning artifacts   |
| Manual binary-oriented deployment                     | Containerized delivery for easier deployment in cloud-native environments                       |
| Built-in runtime reporting                            | Prometheus/OpenTelemetry metrics                                                                |
| CLI-oriented offline workflows                        | Programmatic DPP library API with observer hooks for canonical per-query telemetry              |
| GPL/community distribution                            | Flexible commercial licensing for both source code and pre-built binaries                       |
| Self-service benchmarking                             | Benchmark/tuning help                                                                           |
| Current parsing and processing stack                  | An alternative packet parsing and DNS processing stack aimed at broader protocol coverage       |

Commercial licensing and support: `carrier-support@dnstele.com`  
Nameto Oy also offers commercial support for organizations using the Community Edition, including deployment guidance, troubleshooting, benchmarking, and production-readiness assistance.

## License

Licensed under GNU GPLv3.

Commercial licensing: `carrier-support@dnstele.com`  
Copyright © 2026 Nameto Oy. All rights reserved.
