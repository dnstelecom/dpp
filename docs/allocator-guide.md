# Allocator Guide

DPP selects one global allocator at build time through Cargo features. The choice applies to the
whole process; there is no runtime flag or environment override. The default is `tikv-jemallocator`.

## Choose an allocator

Exactly one allocator feature must be enabled. Invalid feature combinations fail the build
explicitly.

| Cargo feature | Allocator | Availability |
| --- | --- | --- |
| `allocator-jemalloc` | `tikv-jemallocator` | Default build. |
| `allocator-mimalloc` | `mimalloc` | Alternative build. |
| `allocator-system` | `std::alloc::System` | Alternative build. |
| `allocator-tcmalloc` | `tcmalloc-better` | Linux `x86_64` and Linux `aarch64` only. |

## Build a variant

Requires Rust 1.98.1 or newer; this repository is pinned by `rust-toolchain.toml`.

Default allocator:

```bash
cargo build --release
```

Alternative allocators:

```bash
cargo build --release --no-default-features --features allocator-system
cargo build --release --no-default-features --features allocator-mimalloc

# Linux x86_64 and Linux aarch64 only
cargo build --release --no-default-features --features allocator-tcmalloc
```

## Confirm the active allocator

DPP logs the active allocator during startup, making benchmark logs and operational reports easier
to interpret. For example:

```text
Allocator: tikv-jemallocator
```

## Compare allocators

Use the same representative capture, output format, and CPU budget for every variant. Follow the
[allocator benchmark protocol](../benches/allocator-benchmarking.md) for building separate binaries,
running the harness, comparing metrics, and meeting the correctness bar before accepting a change.

Keep the same `RUSTFLAGS` across variants. For host-specific code generation:

```bash
RUSTFLAGS='-C target-cpu=native' cargo build --release
RUSTFLAGS='-C target-cpu=native' cargo build --release --no-default-features --features allocator-mimalloc
```

**Hypothesis:** `target-cpu=native` is the right setting for same-host allocator comparisons. For
portable release binaries, keep the same portable compiler settings across all variants.

## Design reference

Use this guide for day-to-day builds and comparisons. The accepted contract for allocator selection
is [RFC 0003](rfc/0003-allocator-selection.md); consult it when reviewing ownership boundaries or
changing the contract.
