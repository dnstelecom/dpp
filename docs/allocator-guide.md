# Allocator Guide

This document explains how DPP selects its global allocator and how to build alternative allocator
variants.

## Scope

Allocator choice in DPP is a build-time concern.

- It applies to the whole process.
- It is selected through Cargo features.
- It is not exposed as a runtime flag or environment override.

The default build uses `tikv-jemallocator`.

## Supported Allocators

Exactly one allocator feature must be enabled.

- `allocator-jemalloc`
  Default build. Uses `tikv-jemallocator`.
- `allocator-mimalloc`
  Alternative build. Uses `mimalloc`.
- `allocator-system`
  Alternative build. Uses `std::alloc::System`.
- `allocator-tcmalloc`
  Alternative build for Linux `x86_64` and Linux `aarch64` only. Uses `tcmalloc-better`.

Invalid feature combinations fail the build explicitly.

## Build Commands

Default allocator build:

```bash
cargo build --release
```

Alternative allocator builds:

```bash
cargo build --release --no-default-features --features allocator-system
cargo build --release --no-default-features --features allocator-mimalloc

# Linux x86_64 and Linux aarch64 only
cargo build --release --no-default-features --features allocator-tcmalloc
```

If you want host-specific code generation during allocator comparisons, keep the same `RUSTFLAGS`
for every build variant. Example:

```bash
RUSTFLAGS='-C target-cpu=native' cargo build --release
RUSTFLAGS='-C target-cpu=native' cargo build --release --no-default-features --features allocator-mimalloc
```

Hypothesis: `target-cpu=native` is the right setting for same-host allocator comparisons. If you are
building portable release binaries, keep the same portable compiler settings across all variants.

## Runtime Visibility

DPP logs the active allocator during startup. Example log line:

```text
Allocator: tikv-jemallocator
```

This makes allocator-specific benchmark logs and operational reports easier to interpret.

## Benchmarking

Allocator changes must be evaluated on the same representative capture, format, and CPU budget.

Use the canonical benchmark protocol here:

- [benches/allocator-benchmarking.md](../benches/allocator-benchmarking.md)

That protocol covers:

- how to build one binary per allocator;
- how to run the benchmark harness fairly;
- what metrics to compare;
- what correctness bar must be met before accepting a change.

## Design Reference

The accepted architecture contract for allocator selection lives here:

- [docs/rfc/0003-allocator-selection.md](rfc/0003-allocator-selection.md)

Use this guide for day-to-day builds and comparisons. Use the RFC when reviewing ownership
boundaries or changing the contract.
