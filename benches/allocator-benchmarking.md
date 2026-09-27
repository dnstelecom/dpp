# Allocator Benchmarking

This document records the canonical protocol for comparing DPP global allocator builds.

## Goal

Compare both throughput and peak RSS on the same representative capture.

Allocator changes are meaningful only when compared under the same binary flags, CPU availability,
input capture, and output format.

## Supported Build Variants

Exactly one allocator feature must be enabled at build time.

| Build | Feature | Platform restriction |
| --- | --- | --- |
| Default | `allocator-jemalloc` | — |
| Alternative | `allocator-system` | — |
| Alternative | `allocator-mimalloc` | — |
| Alternative | `allocator-tcmalloc` | Linux `x86_64` and Linux `aarch64` only. |

### Notes

`allocator-tcmalloc` starts a background maintenance thread during process bootstrap.
`cargo check --all-features` is intentionally excluded because allocator features are mutually
exclusive.

## Build Matrix

Requires Rust 1.98.1 or newer; the repository is pinned by
[`rust-toolchain.toml`](../rust-toolchain.toml).

Build each variant into a separate binary path.

```bash
RUSTFLAGS='-C target-cpu=native' cargo build --release
cp target/release/dpp target/release/dpp-jemalloc

RUSTFLAGS='-C target-cpu=native' cargo build --release --no-default-features --features allocator-system
cp target/release/dpp target/release/dpp-system

RUSTFLAGS='-C target-cpu=native' cargo build --release --no-default-features --features allocator-mimalloc
cp target/release/dpp target/release/dpp-mimalloc

# Linux x86_64 or Linux aarch64 only
RUSTFLAGS='-C target-cpu=native' cargo build --release --no-default-features --features allocator-tcmalloc
cp target/release/dpp target/release/dpp-tcmalloc
```

Hypothesis: `target-cpu=native` is the right setting for apples-to-apples allocator comparisons on a
fixed host. If the goal is portable release benchmarking, keep `RUSTFLAGS` identical across all
allocator builds and document the chosen baseline.

## Benchmark Protocol

1. Build each allocator variant separately.
2. Run the [canonical benchmark harness](README.md) with the same capture, format set and bonded value.
3. Record throughput, shutdown tail, and peak RSS from logs.
4. Compare outputs for determinism before accepting any allocator change.

The following example compares jemalloc and mimalloc using the saved binaries:

```bash
bash benches/benchmark.sh \
  --pcap /path/to/capture.pcap \
  --bin /path/to/target/release/dpp-jemalloc \
  --formats csv,parquet \
  --bonded 0 \
  --runs 3 \
  --no-build

bash benches/benchmark.sh \
  --pcap /path/to/capture.pcap \
  --bin /path/to/target/release/dpp-mimalloc \
  --formats csv,parquet \
  --bonded 0 \
  --runs 3 \
  --no-build
```

## Acceptance Criteria

- No correctness regression.
- No byte-for-byte CSV drift for the same representative run.
- Clear benchmark evidence that the allocator change is worth the operational tradeoff.
