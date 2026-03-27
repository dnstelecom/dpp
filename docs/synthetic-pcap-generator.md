# Synthetic DNS PCAP Generator

`dns-pcap-generator` is a standalone utility that emits classic PCAP with synthetic DNS traffic.
It does not need an input capture at runtime.
It lives in the separate workspace crate `tools/dns-pcap-generator`.
It runs from a fitted profile artifact directory.

## Goal

The checked-in `server1-jul-2024` profile is shaped to resemble the broad DNS mix seen in a
representative July 2024 resolver capture, while deliberately excluding obviously client-specific
names and bank domains.

The generator also models:

- duplicate query retries
- unanswered queries
- mixed response codes
- multiple clients talking to one or more resolvers
- deterministic output for a fixed `--seed`
- a large checked-in positive-domain catalog sourced from filtered real client DNS traffic

## Usage

Build the standalone binary:

```bash
cargo build -p dns-pcap-generator --release --bin dns-pcap-generator
```

Generate a five-minute synthetic capture:

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

Generate an exact number of logical transactions instead of duration-based traffic:

```bash
./target/release/dns-pcap-generator \
  --profile-dir tools/dns-pcap-generator/profiles/server1-jul-2024 \
  synthetic/fixed-count.pcap \
  --transactions 500000 \
  --clients 1024 \
  --resolvers 2
```

Generate from the checked-in fitted profile defaults without overriding `qps`, `clients`, or
`resolvers`:

```bash
./target/release/dns-pcap-generator \
  --profile-dir tools/dns-pcap-generator/profiles/server1-jul-2024 \
  synthetic/fitted-profile.pcap \
  --transactions 500000
```

Regenerate the embedded catalog TSV from a local CSV:

```bash
cargo run -p dns-catalog-builder --release -- \
  from_real_traffic.csv \
  tools/dns-pcap-generator/catalog_data.tsv \
  --top 10000
```

The generator loads `fitted-generator.toml` from `--profile-dir`, verifies the referenced
`catalog_data.tsv` digest, and then uses the artifact directory as the runtime source of truth.
The checked-in `server1-jul-2024` profile points its `catalog_path` at the workspace-level
`tools/dns-pcap-generator/catalog_data.tsv`, so the catalog remains a single reviewable source of
truth instead of being duplicated inside the profile directory. Runtime failures are reported
through typed CLI errors, so invalid arguments and I/O failures surface with stable top-level
messages and source chains.

## Model

- The output is classic little-endian PCAP with Ethernet + IPv4 + UDP + DNS packets.
- Queries go from a synthetic client pool in `100.64.0.0/10` to a synthetic resolver pool in
  `172.20.0.0/16`.
- `--clients` is validated against the distinct address capacity of that client pool, which is
  4,161,536 synthetic client IPs.
- Inter-arrival times are sampled from an exponential distribution around the configured `--qps`.
- Duplicate retries use increasing retry delays so slow or unanswered lookups produce realistic
  retry spacing; unanswered transactions keep long retransmit backoff, while answered retries stay
  short enough not to distort matched RTT.
- Matched response latency is calibrated from the local `server1_jul_2024.csv` distribution:
  most replies land in a few dozen microseconds, with a rare long tail and heavier `ServFail`
  delays.
- Successful `A`, `AAAA`, `HTTPS`, and `SVCB` responses include syntactically valid DNS answers.
- Successful `NS` queries for the root domain (`.`) are allowed and return a valid root-server
  target selected from the current `a.root-servers.net` through `m.root-servers.net` set.
- `TXT`, `SRV`, `CNAME`, and `MX` questions may return `NOERROR` with zero answers; that is an
  intentional NODATA-style simplification.
- The checked-in runtime profile carries calibrated duplicate/timeout rates and duplicate retry
  multiplicity. Those knobs are not user-overridable at runtime, which keeps post-DPP behavior
  anchored to the fitted profile.
- The positive-domain catalog stays in `tools/dns-pcap-generator/catalog_data.tsv`, and the
  checked-in profile references it via `catalog_path`. This avoids a second source of truth for
  the sanitized catalog.
- Omitted `--qps`, `--clients`, and `--resolvers` values inherit the fitted profile defaults.

## Sanitization Boundary

The checked-in positive-domain catalog is curated and validated to exclude:

- `android.clients.*`
- push-courier / Apple-device routing names
- `_dns.resolver.arpa`
- `.local`, `.lan`, `.home.arpa`
- Banking domains
- labels that look like long unique numeric or hex identifiers

Hypothesis:
The current “client-specific” detector is a conservative heuristic, not a formally complete
classifier. It is designed to block obvious device/user-specific names without requiring access to
the original capture at runtime.

## Operational Notes

- The generator streams output and keeps only future scheduled packets in memory, so it scales much
  better than materializing the whole capture before sorting.
- The checked-in `server1-jul-2024` profile includes `fitted-generator.toml` and intentionally
  reuses the workspace catalog TSV instead of carrying a second copy of the catalog. If the traffic
  shape needs to change, keep the fitted profile and the catalog/tests in sync so the sanitization
  boundary remains explicit.
