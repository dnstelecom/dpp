# RFC 0003 — Compile-time allocator selection

**Status:** Accepted · **Date:** 2025-03-21

## Problem

DPP is allocation-heavy: the parser, matcher, and writers all allocate on hot paths. The global
allocator affects throughput, RSS, and cross-thread frees. The allocator was previously hardcoded
in `src/main.rs` through a direct `jemallocator` dependency, making its policy implicit and
harder to benchmark independently of the entrypoint.

Allocator choice is fundamentally a build-time decision: it affects the entire binary, must be
settled before `main()` runs, and must not drift between CLI flags, env vars, and code.

## Decision

Allocator selection is owned by [`src/allocator.rs`](../../src/allocator.rs) and configured exclusively through
mutually exclusive Cargo features:

| Feature | Allocator | Role or restriction |
| --- | --- | --- |
| `allocator-jemalloc` | `tikv-jemallocator` | Default choice for throughput and RSS |
| `allocator-mimalloc` | `mimalloc` | Alternative with different fragmentation characteristics |
| `allocator-system` | `std::alloc::System` | Benchmark baseline |
| `allocator-tcmalloc` | `tcmalloc-better` | Linux x86_64 / aarch64 only; fails to compile elsewhere |

Exactly one feature must be enabled. Invalid combinations fail the build with a clear error.

`src/main.rs` delegates to `src/allocator.rs` and doesn't touch allocator policy.

## Why not a runtime flag?

The global allocator is selected before `main()` runs. Cargo features make that choice explicit
and reproducible: change the feature, rebuild, and measure the resulting binary.

## Trade-offs

- Allocator changes require a rebuild.
- `allocator-tcmalloc` intentionally fails on unsupported targets instead of silently falling back.
- `cargo check --all-features` cannot pass because the features are mutually exclusive. Each
  allocator configuration must be checked separately; there is no silent feature priority.

## Validation

When changing allocator configuration:

1. Run `cargo test` with the default feature.
2. Run `cargo check` for each supported alternative.
3. Measure throughput and RSS using the [allocator benchmark protocol](../../benches/allocator-benchmarking.md).
   An allocator change needs measured results, not an assumed speedup.
