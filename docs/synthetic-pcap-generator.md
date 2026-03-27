# Synthetic DNS PCAP Generator

`dns-pcap-generator` is a standalone utility that emits classic PCAP with synthetic DNS traffic.
It does not need an input capture at runtime.

## Goal

The default built-in profile, `server1-jul-2024-sanitized`, is shaped to resemble the broad DNS
mix seen in a representative July 2024 resolver capture, while deliberately excluding obviously
client-specific names, bank domains.

The generator also models:

- duplicate query retries
- unanswered queries
- mixed response codes
- multiple clients talking to one or more resolvers
- deterministic output for a fixed `--seed`
- a large embedded positive-domain catalog sourced from the filtered real client DNS traffic

## Usage

Build the standalone binary:

```bash
cargo build --release --bin dns-pcap-generator
```

Generate a five-minute synthetic capture:

```bash
./target/release/dns-pcap-generator synthetic/server1-like.pcap \
  --duration-seconds 300 \
  --qps 1200 \
  --clients 2048 \
  --resolvers 3 \
  --duplicate-rate 0.08 \
  --timeout-rate 0.03 \
  --seed 42
```

Generate an exact number of logical transactions instead of duration-based traffic:

```bash
./target/release/dns-pcap-generator synthetic/fixed-count.pcap \
  --transactions 500000 \
  --clients 1024 \
  --resolvers 2
```

## Model

- The output is classic little-endian PCAP with Ethernet + IPv4 + UDP + DNS packets.
- Queries go from a synthetic client pool in `100.64.0.0/10` to a synthetic resolver pool in
  `172.20.0.0/16`.
- Inter-arrival times are sampled from an exponential distribution around the configured `--qps`.
- Duplicate retries use increasing retry delays so slow or unanswered lookups produce realistic
  retry spacing.
- Successful `A`, `AAAA`, `HTTPS`, and `SVCB` responses include syntactically valid DNS answers.
- Successful `NS` queries for the root domain (`.`) are allowed and return a valid root-server
  target.
- `TXT`, `SRV`, `CNAME`, and `MX` questions may return `NOERROR` with zero answers; that is an
  intentional NODATA-style simplification.
- The positive-domain catalog is stored as a plain embedded TSV asset, so the domain corpus stays
  easy to review even though the profile now carries a large catalog.

## Sanitization Boundary

The built-in positive-domain catalog is curated and validated to exclude:

- `android.clients.*`
- push-courier / Apple-device routing names
- `_dns.resolver.arpa`
- `.local`, `.lan`, `.home.arpa`
- Russian ecosystem domains such as `yandex`, `vk`, `userapi`, `mycdn`, `mail.ru`, `my.com`
- any domain containing `ru`
- labels that look like long unique numeric or hex identifiers

Hypothesis:
The current “client-specific” detector is a conservative heuristic, not a formally complete
classifier. It is designed to block obvious device/user-specific names without requiring access to
the original capture at runtime.

## Operational Notes

- The generator streams output and keeps only future scheduled packets in memory, so it scales much
  better than materializing the whole capture before sorting.
- The profile is intentionally self-contained. If the traffic shape needs to change, regenerate the
  embedded catalog from csv file with real traffic, with the same filters and keep the profile/tests in
  sync so the sanitization boundary remains explicit.
