# Synthetic DNS PCAP Generator

`dns-pcap-generator` is a standalone utility in `tools/dns-pcap-generator`. It generates classic
PCAP with synthetic DNS traffic from a fitted profile artifact directory; no input capture is
needed at runtime.

The checked-in `server1-jul-2024` profile resembles the broad DNS mix in a representative July 2024
resolver capture. It uses a large positive-domain catalog sourced from filtered real client DNS
traffic, excluding obviously client-specific names and bank domains.

Traffic includes duplicate query retries, unanswered queries, mixed response codes, and multiple
clients talking to one or more resolvers. Output is deterministic for a fixed `--seed`.

- [Build and generate a capture](#build-and-generate-a-capture)
- [Understand the traffic model](#understand-the-traffic-model)
- [Use fitted profile artifacts](#use-fitted-profile-artifacts)
- [Maintain the domain catalog](#maintain-the-domain-catalog)
- [Sanitization boundary](#sanitization-boundary)

## Build and generate a capture

Requires Rust 1.98.1 or newer; this repository is pinned by `rust-toolchain.toml`.

Build the standalone binary:

```bash
cargo build -p dns-pcap-generator --release --bin dns-pcap-generator
```

### Generate by duration

Generate a five-minute capture with an explicit rate, client pool, resolver pool, and seed:

```bash
./target/release/dns-pcap-generator \
  --profile-dir tools/dns-pcap-generator/profiles/server1-jul-2024 \
  synthetic/server1-like.pcap \
  --duration-seconds 300 \
  --qps 1200 \
  --clients 2048 \
  --resolvers 3 \
  --seed 42
```

### Generate a fixed transaction count

Use `--transactions` for an exact number of logical transactions instead of duration-based traffic:

```bash
./target/release/dns-pcap-generator \
  --profile-dir tools/dns-pcap-generator/profiles/server1-jul-2024 \
  synthetic/fixed-count.pcap \
  --transactions 500000 \
  --clients 1024 \
  --resolvers 2
```

### Use the fitted defaults

Omitted `--qps`, `--clients`, and `--resolvers` values inherit the fitted profile defaults:

```bash
./target/release/dns-pcap-generator \
  --profile-dir tools/dns-pcap-generator/profiles/server1-jul-2024 \
  synthetic/fitted-profile.pcap \
  --transactions 500000
```

The profile also sets calibrated duplicate and timeout rates and duplicate retry multiplicity.
Those settings cannot be overridden at runtime, keeping post-DPP behavior anchored to the fitted
profile.

## Understand the traffic model

### Packet format and address pools

Queries go from the synthetic client pool to the synthetic resolver pool.

| Property | Model |
| --- | --- |
| Output | Classic little-endian PCAP. |
| Packet layers | Ethernet → IPv4 → UDP → DNS. |
| Synthetic clients | `100.64.0.0/10`. |
| Synthetic resolvers | `172.20.0.0/16`. |
| Client limit | `--clients` is validated against the pool's capacity of 4,161,536 distinct synthetic client IPs. |

### Timing and retries

Inter-arrival times follow an exponential distribution around `--qps`. Scheduling uses nanosecond
precision with fractional carry, while classic PCAP stores microsecond timestamps. At high QPS,
multiple packets can therefore share a timestamp without imposing a one-microsecond minimum gap on
the generated rate.

Duplicate retries use the profile's fitted delay for each retry step. Delays are not necessarily
increasing: the first unanswered steps have long backoff, while later fitted or hypothesized steps
can be much shorter. A response follows the last retry.

Matched response latency is calibrated from the local `server1_jul_2024.csv` distribution. Most
replies arrive in a few dozen microseconds, with a rare long tail and heavier `ServFail` delays.

The generator streams output and keeps only future scheduled packets in memory, which scales much
better than materializing the whole capture before sorting.

### DNS answers

| Successful query | Response contents |
| --- | --- |
| `A`, `AAAA`, `HTTPS`, `SVCB` | Syntactically valid DNS answers. |
| `NS` for the root domain (`.`) | A valid root-server target selected from `a.root-servers.net` through `m.root-servers.net`. |
| `TXT`, `SRV`, `CNAME`, `MX` | May return `NOERROR` with zero answers: an intentional NODATA-style simplification. |

## Use fitted profile artifacts

The generator loads `fitted-generator.toml` from `--profile-dir`, verifies the referenced catalog's
digest, and uses the artifact directory as its runtime source of truth.

The checked-in `server1-jul-2024` profile contains `fitted-generator.toml`. Its `catalog_path` points
to the workspace-level `tools/dns-pcap-generator/catalog_data.tsv`, keeping one reviewable copy of
the sanitized catalog instead of duplicating it inside the profile directory.

### Validation and errors

Runtime failures use typed CLI errors, with stable top-level messages and source chains for invalid
arguments and I/O failures. In particular:

- Catalog rows with zero weights or DNS names longer than 255 wire bytes are rejected.
- Fitted profiles are rejected if `duplicate_max` is below every configured retry count.
- Generation returns an error if a packet timestamp exceeds the classic PCAP 32-bit seconds range.

## Maintain the domain catalog

Regenerate the checked-in workspace catalog TSV from a local CSV:

```bash
cargo run -p dns-catalog-builder --release -- \
  from_real_traffic.csv \
  tools/dns-pcap-generator/catalog_data.tsv \
  --top 10000
```

The catalog builder writes and syncs a separate temporary file beside the destination before
replacing the output:

- Concurrent builds targeting the same path cannot truncate each other's temporary files. The last
  successful replacement supplies the complete catalog.
- Ordinary I/O errors preserve the previous output and trigger best-effort removal of that build's
  temporary file.
- A process crash or filesystem cleanup error can leave a temporary file behind.

When changing the traffic shape, keep the fitted profile, catalog, and tests in sync so the
sanitization boundary remains explicit.

## Sanitization boundary

The checked-in positive-domain catalog is curated and validated to exclude:

| Category | Exclusions |
| --- | --- |
| Client and device routing | `android.clients.*`; push-courier / Apple-device routing names. |
| Resolver discovery | `_dns.resolver.arpa`. |
| Local names | `.local`, `.lan`, `.home.arpa`. |
| Sensitive domain category | Banking domains. |
| Identifier-like labels | Long unique numeric or hex identifiers. |

**Hypothesis:** The current client-specific detector is a conservative heuristic, not a formally
complete classifier. It is designed to block obvious device/user-specific names without requiring
the original capture at runtime.
