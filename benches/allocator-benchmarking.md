# Allocator Benchmarking

This document records the canonical protocol for comparing DPP global allocator builds.

## Goal

Allocator experiments must answer two questions on the same representative capture:

- does throughput improve or regress;
- does peak RSS improve or regress.

Allocator changes are meaningful only when compared under the same binary flags, CPU availability,
input capture, and output format.

## Supported Build Variants

Exactly one allocator feature must be enabled at build time.

- default build: `allocator-jemalloc`
- alternative builds:
  - `allocator-system`
  - `allocator-mimalloc`
  - `allocator-tcmalloc` on Linux `x86_64` and Linux `aarch64` only

## Build Matrix

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
2. Run the canonical benchmark harness with the same capture, format set, and bonded value.
3. Record throughput, shutdown tail, and peak RSS from logs.
4. Compare outputs for determinism before accepting any allocator change.

Example:

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

## Notes

- `allocator-tcmalloc` starts a background maintenance thread during process bootstrap.
- `cargo check --all-features` is intentionally not part of this protocol because allocator features
  are mutually exclusive.
