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

DPP is a Rust application for parsing, matching, and exporting DNS query/response traffic from
offline PCAP files. It is designed for large captures, bounded parallel processing, and downstream
analytics workflows.

## Contents

- [Overview and features](#overview)
- [Build](#build)
- [Usage](#usage)
- [Input and matching](#input-and-matching)
- [Output and reports](#output-and-reports)
- [Pseudonymization keys](#create-an-anonymization-key)
- [Synthetic capture generation](#synthetic-capture-generation)
- [Example run](#example-run)
- [Performance optimization](#performance-optimization)
- [Limitations](#limitations)
- [Architecture](#architecture)
- [Documentation](#documentation)
- [Commercial Edition](#commercial-edition)
- [License](#license)

## Overview

DPP reads offline captures, pairs DNS queries with responses, and exports transaction records.
It supports bounded parallel processing, deterministic aggregation, and optional IP
pseudonymization.

Start with the [usage examples](#usage). For implementation details and diagrams, read the
[architecture reference](docs/architecture.md).

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

## Prerequisites

- [Rust](https://rustup.rs/) 1.98.1 or newer; this repository is pinned by `rust-toolchain.toml`.
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

Examples below assume `dpp` is on `PATH`. After a local build, use `target/release/dpp` instead.

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

### Arguments

| Argument | Description |
| --- | --- |
| `filename` | Path to the input PCAP file. Use `-` to read a finite offline PCAP stream from `stdin`. |
| `output_filename` | Optional output path; use `-` for CSV stdout. If neither this argument nor `DPP_OUTPUT_FILENAME` is set, the format determines the [default path](#files-and-streams). |

### Options

| Option | Description |
| --- | --- |
| `-s, --silent` | Suppress info-level log output |
| `-f, --format <csv\|parquet\|pq>` | Select output format; stdout output is supported only for `csv` |
| `--report-format <text\|json>` | Select the final process report format; defaults to `text`; `json` cannot be combined with `output_filename = -` |
| `--match-timeout-ms <MS>` | Set the DNS query-response match timeout in milliseconds; allowed range is `1..=5000`, default is `1200` |
| `--monotonic-capture` | Assume globally monotonic packet timestamps, enable batched timeout eviction, and abort if a regression is detected |
| `-t, --threads <N>` | Cap the CPU execution budget at a positive `N`, never above available CPUs |
| `-b, --bonded <N>` | Set I/O channel capacity in records; internally rounded up to batched messages of up to `1024` records; `0` uses the safe default bounded capacity |
| `-z, --zstd` | Enable Zstd compression for Parquet output |
| `--v2` | Use Parquet Version 2 |
| `-a, --affinity` | Apply CPU affinity to processing threads |
| `--dns-wire-fast-path` | Enable the optional question-only DNS wire fast path with `hickory` fallback |
| `--max-dns-compression-jumps <N>` | Maximum compression-pointer jumps per DNS name; defaults to `32`; `0` disables the jump limit |
| `--allow-fragments` | Opt in to matching complete queries with first IPv4 response fragments when the DNS header and question are present; no reassembly |
| `--full-fragments` | Reassemble IPv4 fragments into complete UDP datagrams; also enables `--allow-fragments` for incomplete responses |
| `--anonymize <path>` | Path to the pseudonymization key file |
| `-h, --help` | Print help |
| `-V, --version` | Print version |

On macOS, DPP continues without affinity after one warning because the platform does not
provide supported per-core thread pinning through the affinity backend.

### Environment variables

| Variable | Description |
| --- | --- |
| `DPP_FILENAME` | Input PCAP path. Use `-` to read a finite offline PCAP stream from `stdin` |
| `DPP_OUTPUT_FILENAME` | Optional output file path; use `-` for CSV stdout output |
| `DPP_FORMAT` | Output format: `csv`, `parquet`, or `pq` |
| `DPP_REPORT_FORMAT` | Final process report format: `text` or `json`; defaults to `text`; `json` cannot be combined with `DPP_OUTPUT_FILENAME=-` |
| `DPP_MATCH_TIMEOUT_MS` | DNS query-response match timeout in milliseconds; allowed range is `1..=5000`, default is `1200` |
| `DPP_MONOTONIC_CAPTURE` | Assume globally monotonic packet timestamps, enable batched timeout eviction, and abort if a regression is detected |
| `DPP_THREADS` | Maximum CPU execution budget when `--threads` is not set; must be a positive integer |
| `DPP_BONDED` | I/O channel capacity in records; internally rounded up to batched messages of up to `1024` records; `0` uses the default bounded capacity |
| `DPP_ZSTD` | Enable Zstd compression for Parquet output |
| `DPP_V2` | Enable Parquet Version 2 |
| `DPP_AFFINITY` | Apply CPU affinity to processing threads |
| `DPP_DNS_WIRE_FAST_PATH` | Enable the optional DNS wire fast path |
| `DPP_MAX_DNS_COMPRESSION_JUMPS` | Maximum compression-pointer jumps per DNS name when `--max-dns-compression-jumps` is not set; defaults to `32`; `0` disables the jump limit |
| `DPP_ALLOW_FRAGMENTS` | Enable first-fragment IPv4 response matching without reassembly. |
| `DPP_FULL_FRAGMENTS` | Enable IPv4 reassembly and first-fragment response matching. |
| `DPP_ANONYMIZE` | Path to the key file used for pseudonymization |
| `DPP_SILENT` | Suppress info-level log output |

## Input and matching

### Files and streams

If neither `output_filename` nor `DPP_OUTPUT_FILENAME` is set, DPP chooses the default file name
from the resolved output format:
`dns_output.csv` for `csv` and `dns_output.parquet` for `parquet` or `pq`. Use `-` only when you
want CSV records on stdout.

DPP refuses to start when the input and output paths refer to the same
file, including hard-link aliases, so the input capture cannot be overwritten.
The same protection applies when the output path refers to the anonymization key file.

| Input or output | Contract |
| --- | --- |
| `filename = -` | Read classic PCAP or PCAPNG from stdin until EOF. This is finite offline input, not live capture. |
| `output_filename = -` | Write CSV records to stdout; suppress non-error logs and the final text report. |
| Stdout restrictions | Reject Parquet output and JSON reports, including `DPP_REPORT_FORMAT=json`. |

Classic PCAP files and stdin streams use the pure-Rust parser family. PCAPNG stdin uses a
stream-native reader; regular non-classic files use the `libpcap` fallback. Unsupported stdin
magic is rejected without a temporary file or second ingest path.

### Match identity and retries

Queries and responses are paired using the original client IP, client port, resolver IP, DNS ID,
QNAME, QTYPE, QCLASS, OPCODE, and VLAN context. DNS QR determines direction, including when both UDP ports are 53.
QCLASS, OPCODE, and VLAN context stay internal and add no output columns.

VLAN identity contains each tag's TPID and VLAN ID. Priority (PCP) and drop eligibility (DEI) do
not distinguish transactions on the same tagged segment.

Pending queries with the same identity inside the match window (`1200ms` by default) are
deduplicated to the earliest canonical query. Retries increment a separate counter and do not
produce extra matched or timeout records.

Default mode retains pending retry timestamps. An earlier timestamp in a later batch can split
pending groups without widening the match window. Finalized transactions are never reopened.
Monotonic mode does not need or allocate retry history.

**Case matters in Community Edition.** Matcher identity preserves observed presentation-form
QNAME bytes. RFC 4343 permits case-only differences in valid responses, including differences
caused by compression; those pairs may fail to match in DPP.

This is a deliberate trade-off for offline caching-resolver workloads, not an RFC guarantee.
See the [matcher contract](docs/architecture.md#matcher-contract) for the full identity and ordering
rules.

### Timestamp order

In default mode, backwards capture timestamps produce a red warning after processing. Matching
remains deterministic, but pairing quality may degrade. Normalize the capture with Wireshark's
`reordercap` when needed:

```bash
reordercap input.pcap normalized.pcap
```

For globally ordered captures, `--monotonic-capture` or `DPP_MONOTONIC_CAPTURE=1` enables batched
timeout eviction, which can reduce matcher RSS. The first timestamp regression aborts the run;
this optimization must not weaken matching semantics.

### DNS message validation

Ordinary QUERY messages with more than one question are rejected under RFC 9619. Responses with
truncated declared answer or authority records are also rejected before matching.

QNAME limits apply to the decompressed wire form:

| Limit | Meaning |
| --- | --- |
| 255 octets | Maximum wire QNAME, including label-length octets and terminating root. |
| 1003 bytes | Possible escaped presentation form of a valid wire name; these names stay distinct in matching and export. |

If any QNAME exceeds the wire limit, DPP rejects the **entire DNS message** before matching or
export. No questions from that message become query or response records.

The text report labels the counter `DNS messages rejected for oversized QNAME`; JSON uses
`metrics.dns_messages_rejected_oversized_qname`. Both count rejected messages, not questions.

### IPv4 fragment modes

| Mode | Input accepted |
| --- | --- |
| Default | Skip IPv4 fragments. |
| `--allow-fragments` / `DPP_ALLOW_FRAGMENTS=1` | Use an observed first response fragment with a complete DNS header and question; no reassembly. |
| `--full-fragments` / `DPP_FULL_FRAGMENTS=1` | Reassemble complete IPv4 UDP datagrams; also enable first-response-fragment fallback. |

For a response prefix, `response_code` is present only when there are no additional records or
all declared DNS records fit in the prefix. The metric `fragmented_response_prefix_count` (text:
`Accepted first IPv4 response fragments`) counts accepted prefixes, even without a matching query.

Full reassembly uses the final fragment's (`MF=0`) timestamp. Incomplete responses may fall back
to their first fragment on capacity eviction or EOF, or on match-timeout expiry in monotonic
mode. Fallback uses the first fragment's timestamp.

Fragmented queries need complete reassembly;
overlapping, inconsistent, or UDP-length-mismatched fragment sets are rejected.

Duplicate suppression uses bounded history and compares the fragment key and UDP payload bytes:

- A reused IPv4 ID with different content can form a new datagram, even with an identical first
  fragment.
- A fully identical new datagram, or an incomplete one whose observed fragments match a recent
  completion, may be suppressed because it is indistinguishable from a duplicate.
- A separate bounded history drops tails after a non-DNS first fragment. If a new DNS datagram
  reuses that ID and its tail arrives before its first fragment while the mark is active, the
  tail may also be dropped.

For buffer ownership, validation boundaries, and ordering, see
[IPv4 fragmentation](docs/architecture.md#ipv4-fragmentation).


## Output and reports

### What DPP produces in CSV output

DPP writes one row per canonical DNS query outcome.

```csv
request_timestamp,response_timestamp,source_ip,source_port,id,name,query_type,response_code
1774783431482391,1774783431503127,10.0.0.1,53000,4660,example.com,A,No Error
1774783447118904,,10.0.0.2,53001,48879,example.org,A,
```
In this example:

- `example.com A` matched a response about 20.736ms later.
- `example.org A` had no matching response within the timeout window; both response fields are
  empty.

### Response fields

| Output value | Meaning |
| --- | --- |
| Missing `response_timestamp` | No matching response observed inside the configured timeout window. This is the canonical timeout signal. |
| Missing `response_code` on a timeout | No DNS response exists; this does not mean the server returned `ServFail`. |
| Present timestamp, missing code | A first-fragment response prefix matched, but its complete response code was unavailable. |
| `EDNS_BADVERS` | Extended RCODE 16 from EDNS OPT. |
| `TSIG Failure` | Code 16 supplied by a TSIG RR error field. |
| `TYPE<number>`, such as `TYPE65400` | An unknown query type, retaining its wire number. |
| Decimal code, such as `64` | An unknown response code, retaining its distinct value. |

Missing response fields are empty in CSV and `NULL` in Parquet. Both formats preserve unknown
type/code values rather than collapsing them to an `Unknown` label.

### JSON summaries

`--report-format json` or `DPP_REPORT_FORMAT=json` suppresses routine `info`/`warn` reporting and
writes one final summary object to stdout. CSV or Parquet records remain in their own output file.

The summary includes these processing and matching-quality metrics:

- `metrics.dns_messages_rejected_oversized_qname`
- `metrics.timed_out_queries`
- `metrics.timed_out_query_ratio`
- `metrics.average_matched_rtt_ms`

### Interrupted and failed runs

On `SIGINT` or `SIGTERM`, DPP stops intake and drains accepted work. It skips synthetic timeout
finalization for pending unmatched queries, discards the still-buffered writer tail, and exits.
This policy applies to CSV and Parquet. JSON reports it as `warnings.graceful_signal_shutdown`.

Stdin shutdown does not require producer EOF. If interruption happens before a capture header
can be read, DPP creates neither an output writer nor a final report.

A capture read failure after processing starts drains complete accepted batches and flushes
conclusive records as valid partial output, then returns an error. Pending queries do not become
timeout records. If processing failure and a signal coincide, processing failure takes precedence
and buffered output is flushed.

See [shutdown behavior](docs/architecture.md#output-reporting-and-shutdown) for the lifecycle
contract and error precedence.

<a id="a-simple-awk-analysis-to-measure-dns-traffic-latency"></a>

### Analyze latency with AWK

This example uses GNU AWK to calculate timeout counts and RTT percentiles from the timestamp
columns.

<details>
<summary>Show the AWK command and example output</summary>

```bash
gawk -F',' '
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
```

Example output for the illustrative capture:

```text
total_rows:    19646090
ok_rows:       19630152
timeout_rows:  15938
invalid_rows:  0
timeout_ratio: 0.0811%
mean_ms:       1.303967
median_ms:     0.021000
p50_ms:        0.021000
p95_ms:        0.034000
p99_ms:        34.479000
p99.9_ms:      257.322000
```

</details>

## Create an anonymization key

`--anonymize` accepts a legacy text key file or a salted v2 key file. DPP derives the internal
pseudonymization keys from the file's passphrase and salt.

One practical way to create a key file on Linux or macOS is:

```bash
umask 077
openssl rand -hex 32 > /tmp/anon.key
```

Then use it like this:

```bash
dpp --anonymize /tmp/anon.key input.pcap output.csv
```

To create a salted v2 key file instead, use Python 3:

```bash
umask 077
python3 - <<'PY'
import os
from secrets import token_bytes, token_hex

contents = (
    b"\x89DPP-ANON-KEY-v2\n"
    + token_bytes(32).hex().encode("ascii") + b"\n"
    + token_hex(32).encode("ascii") + b"\n"
)
with os.fdopen(os.open("anon-v2.key", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as key:
    key.write(contents)
PY
dpp --anonymize anon-v2.key input.pcap output.csv
```

### Key formats and handling

- Keep the key file private. Anyone with the same file can reproduce the same pseudonymized output.
- A legacy key file contains a non-empty UTF-8 passphrase. A salted v2 file contains the exact
  binary header `\x89DPP-ANON-KEY-v2\n`, a line of exactly 64 hexadecimal digits representing
  a 32-byte salt, then a non-empty UTF-8 passphrase. Leading and trailing passphrase whitespace is
  ignored. Malformed salted files are rejected.

### Mapping and compatibility

- Rotating the key changes the resulting pseudonymized IP addresses for the same input capture.
- Matching and deduplication use the original client IP. Pseudonymization is applied only to the
  `source_ip` field of finalized output records. IPv4 pseudonymization is a keyed permutation, so
  distinct IPv4 client addresses remain distinct in the output; network prefixes are not preserved.
- Legacy key files retain the original fixed PBKDF2 salt and produce the same pseudonyms as before.
  The salted v2 format limits precomputation across files that use weak passphrases; a random
  passphrase remains essential. Reuse the entire v2 key file across runs and hosts to keep output
  stable. Changing either its salt or passphrase rotates both IPv4 and IPv6 pseudonyms.
- The IPv4 Feistel mapping replaces the previous truncated-AES mapping. Even with the same
  passphrase, exports produced before and after this change cannot be joined by pseudonymized IPv4
  `source_ip`. IPv6 pseudonyms remain unchanged.

### Key-loading errors

If `--anonymize` or `DPP_ANONYMIZE` is configured and the key file is missing, unreadable, or
invalid, DPP exits with an error. It does not silently fall back to pass-through IP addresses.

## Synthetic capture generation

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
workload while keeping only sanitized, non-client-specific domains.

Its `fitted-generator.toml` lives under `tools/dns-pcap-generator/profiles/server1-jul-2024`, while
the profile's `catalog_path` points back to `tools/dns-pcap-generator/catalog_data.tsv` so the
sanitized catalog remains a single reviewable source of truth.

The generator verifies the referenced catalog digest before generation. See
[docs/synthetic-pcap-generator.md](docs/synthetic-pcap-generator.md) for the full contract and
current modeling assumptions.

## Example run

The log below is illustrative. Exact throughput, memory usage, and match counters depend on the hardware, build profile, capture shape, and matcher revision.

<details>
<summary>Show the illustrative run log</summary>

```text
# On Intel(R) Atom(TM) x7425E with power-save profile.
# No output file name is specified here, so CSV mode uses the default output path: dns_output.csv.
$ DPP_FILENAME=server1_jul_2024.pcap DPP_FORMAT=csv target/release/dpp --dns-wire-fast-path --monotonic-capture
04:15:01.046  INFO DNS Packet Parser (DPP) community edition, version hash: dbed8b3
04:15:01.046  INFO Git Commit Author: k.mikhailov@dnstele.com
04:15:01.046  INFO Git Timestamp: 2026-03-26T06:06:59.000000000+02:00
04:15:01.046  INFO Build Timestamp: 2026-03-26T04:08:26.901327423Z
04:15:01.046  INFO Build Hostname: hel-atom1
04:15:01.046  INFO Allocator: tikv-jemallocator
04:15:01.046  INFO > This software is licensed under GNU GPLv3.
04:15:01.046  INFO > Commercial licensing options: carrier-support@dnstele.com
04:15:01.046  INFO > Nameto Oy (c) 2026. All rights reserved.
04:15:01.062  INFO OS: Linux, ARCH: x86_64
04:15:01.062  INFO Available parallelism: 4, execution budget: 4 CPUs (auto), affinity requested: false, effective: false
04:15:01.062  INFO Available memory (system reported): 2,857 MB
04:15:01.062  INFO Starting to process PCAP file: /mnt/mirror/src/dpp/server1_jul_2024.pcap
04:15:01.062  INFO Processing mode: forward sorting with response-query matching
04:15:01.062  INFO IO channel: BOUNDED with 128 batched messages / 131,072 records max (default)
04:15:01.076  INFO Format is: CSV
04:15:01.076  INFO Anonymization: False
04:15:01.076  INFO DNS wire fast path: enabled (question-only decoder with hickory fallback)
04:15:01.076  INFO DNS match timeout: 1200 ms
04:15:01.076  INFO Monotonic capture mode: enabled (batched timeout eviction active; timestamp regressions abort the run)
04:15:01.076  INFO PID: 501755
04:15:01.147  INFO Results will be written to: /mnt/mirror/src/dpp/dns_output.csv
04:15:01.150  INFO Execution budget: 4 CPUs, phase-parallel pipeline selected for low-core budget, Rayon worker budget: 4
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

</details>

## Performance optimization

Build for the target host and benchmark representative captures; throughput depends on hardware,
traffic shape, and output backpressure.

```bash
RUSTFLAGS='-C target-cpu=native' cargo build --release
```

| Control | Guidance |
| --- | --- |
| Benchmark harness | Use [benchmark.sh](benches/benchmark.sh) with `DPP_BENCH_PCAP` or `--pcap`; measure throughput and shutdown tail. |
| `perf` profile | For comparable trusted measurements, use `cargo build --profile perf` or `DPP_BENCH_PROFILE=perf bash benches/benchmark.sh ...`. See the [build caveat](#build). |
| CPU budget | Auto-size from available CPUs, or cap with `--threads` / `DPP_THREADS`. Pipeline selection remains automatic. |
| Question decoder | Opt in with `--dns-wire-fast-path` / `DPP_DNS_WIRE_FAST_PATH=1`; otherwise use the Hickory question decoder. |
| Monotonic capture | Enable batched eviction only for globally ordered captures; regressions abort the run. |
| Allocator | Choose at build time using the [allocator guide](docs/allocator-guide.md) and [comparison protocol](benches/allocator-benchmarking.md). |

Both decoder modes default to **32 compression-pointer jumps per name**. Set
`--max-dns-compression-jumps N` or `DPP_MAX_DNS_COMPRESSION_JUMPS=N` to change the resource limit;
`0` disables it. Cached suffixes count toward the full chain depth.

Bounds, backward-pointer, overlap, and name-length checks stay active regardless of the jump
limit. Validated suffixes are cached per message to avoid repeated walks. See the
[benchmark contract](benches/README.md) before making performance comparisons.


## Limitations

### Capture and protocol coverage

| Area | Limit |
| --- | --- |
| DNS transport | UDP port 53 only. |
| Linktype | Ethernet only. VLAN/QinQ TPIDs `0x8100`, `0x88a8`, and `0x9100` are decoded natively; other declared linktypes are rejected. |
| Outer encapsulation | MPLS and other unsupported encapsulations need [preprocessing](docs/encapsulation-playbook.md). |
| PCAPNG | Stream-native stdin support and `libpcap` regular-file fallback; the performance-focused pure-Rust fast path targets classic PCAP. Stdin blocks over 16MiB are rejected before reading the body. |
| IPv6 | Hop-by-Hop, Routing, Destination Options, Authentication, and atomic Fragment headers are traversed. IPv6 reassembly, ESP, and jumbograms are unsupported. |
| Partial IPv4 responses | First-fragment inference cannot establish whether later fragments arrived or validate the full UDP/DNS contents. The response code may be unavailable. |

Flow identity uses observed IP endpoints. Read [fragment modes](#ipv4-fragment-modes) before opting
into inference or reassembly.

### Ordering, memory, and scaling

- CSV and Parquet records are not guaranteed to be timestamp-sorted. Asynchronous Parquet layout
  may also differ byte-for-byte between runs.
- RAM depends on capture size, traffic shape, and backpressure. Larger `--bonded` values increase
  peak memory under slow sinks; capacity rounds up to messages of at most `1024` records.
- Full reassembly holds ready packets while fragment sets remain unresolved. The retained backlog
  is bounded between batches to 65,536 packets or 64MiB; overflow triggers capacity fallback.
  The current input batch and fallback packets may temporarily exceed those bounds.
- Flow affinity and skewed traffic can limit scaling before linear speedup, even with more CPUs.
- Pending duplicate queries are deduplicated within the match window; duplicate responses remain
  distinguishable until matched or discarded. Duplicate-heavy workloads can increase matcher RAM.

### Interpreting results

Case-only QNAME differences may prevent a match; see [match identity](#match-identity-and-retries).
Timestamp regressions can reduce pairing quality, and monotonic mode treats them as errors.
Capture failures can leave valid partial output; see [interrupted and failed runs](#interrupted-and-failed-runs).


## Architecture

The table below is a high-level map of the system. For the canonical architecture reference,
ownership boundaries, and matcher invariants, see [docs/architecture.md](docs/architecture.md).

| Layer | Components | Responsibility |
| --- | --- | --- |
| Configuration and contracts | `src/config.rs`, `src/cli.rs`, `src/record.rs` | Runtime constants, CLI/environment contract, and exported `DnsRecord` schema |
| Input parsing | `PacketParser` | Offline capture input with pure-Rust classic-PCAP parsing, stream-native stdin parsing, and `libpcap` fallback for non-classic file inputs |
| DNS processing | `DnsProcessor`, `pipeline.rs` | Packet routing, DNS decoding, matching, shard ownership, and deterministic aggregation |
| Runtime and orchestration | `src/app.rs`, `src/runtime.rs`, `src/allocator.rs` | App lifecycle, bootstrap, reporting, thread-pool setup, and allocator selection |
| Output pipeline | `src/output.rs`, `src/csv_writer.rs`, `src/parquet_writer.rs` | Async writer lifecycle and CSV/Parquet serialization |
| Memory monitoring | `src/monitor_memory.rs` | Peak RSS tracking with explicit stop/join lifecycle |
| References and benchmarks | `docs/rfc/`, `benches/` | Architecture decisions, benchmark workflow, and harnesses |

## Documentation

| Task | Reference |
| --- | --- |
| Understand components and processing | [Architecture and diagrams](docs/architecture.md) |
| Read accepted design decisions | [RFC index](docs/rfc/README.md) |
| Contribute a change | [Contribution guide](CONTRIBUTING.md) |
| Run repeatable benchmarks | [Benchmark workflow](benches/README.md) and [harness](benches/benchmark.sh) |
| Select and compare allocators | [Allocator guide](docs/allocator-guide.md) and [benchmark protocol](benches/allocator-benchmarking.md) |
| Prepare unsupported encapsulations | [Encapsulation playbook](docs/encapsulation-playbook.md) |
| Generate test captures | [Synthetic DNS PCAP generator](docs/synthetic-pcap-generator.md) |


## Commercial Edition

DPP Community Edition is focused on deterministic offline DNS processing from PCAP into portable export formats.

DPP Commercial Edition extends that foundation with broader capture support, enterprise integrations, compliance-oriented capabilities, and deployment options for production environments.

| Community Edition | Commercial Edition |
| --- | --- |
| Offline PCAP processing | Native S3 integration for reading PCAP |
| CSV and single-file Parquet export | Partitioned Parquet datasets, not just single-file export |
| Native Ethernet, VLAN and QinQ decoding | Advanced encapsulation support: MPLS, GRE, VXLAN, ERSPAN, Geneve |
| Local file outputs | Direct enterprise sinks: ClickHouse, Kafka, S3, PostgreSQL outputs |
| Batch-oriented processing | Live/continuous ingestion |
| Deterministic pseudonymization with file-based keying | Commercial anonymization/compliance features |
| Current DNS field and message coverage | Extended DNS protocol coverage |
| Standalone synthetic DNS PCAP generation | Profile extraction, fitting, and validation pipeline for calibrated synthetic DNS traffic |
| Checked-in runtime traffic profiles | Fitted profiles derived from reference captures, with validation reports and tuning artifacts |
| Manual binary-oriented deployment | Containerized delivery for easier deployment in cloud-native environments |
| Built-in runtime reporting | Prometheus/OpenTelemetry metrics |
| CLI-oriented offline workflows | Programmatic DPP library API with observer hooks for canonical per-query telemetry |
| GPL/community distribution | Flexible commercial licensing for both source code and pre-built binaries |
| Self-service benchmarking | Benchmark/tuning help |
| Current parsing and processing stack | An alternative packet parsing and DNS processing stack aimed at broader protocol coverage |

Commercial licensing and support: `carrier-support@dnstele.com`
Nameto Oy also offers commercial support for organizations using the Community Edition, including deployment guidance, troubleshooting, benchmarking, and production-readiness assistance.

## License

Licensed under GNU GPLv3.

Commercial licensing: `carrier-support@dnstele.com`
Copyright © 2026 Nameto Oy. All rights reserved.
