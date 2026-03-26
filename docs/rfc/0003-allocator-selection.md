# RFC 0003 — Compile-Time Allocator Selection

Status: Accepted  
Date: 2025-03-21

## Problem

DPP is allocation-heavy: the parser, matcher, and writers all allocate on hot paths. The global
allocator has a measurable impact on throughput, RSS, and cross-thread free behavior. For a while,
the allocator was hardcoded in `src/main.rs` via a direct `jemallocator` dependency — which meant
allocator policy was implicit, hard to benchmark, and tangled with the process entrypoint.

Allocator choice is fundamentally a build-time decision: it affects the entire binary, must be
settled before `main()` runs, and must not drift between CLI flags, env vars, and code.

## Decision

Allocator selection is owned by **`src/allocator.rs`** and configured exclusively through
mutually exclusive Cargo features:

| Feature              | Allocator            | Notes                                                                |
|----------------------|----------------------|----------------------------------------------------------------------|
| `allocator-jemalloc` | `tikv-jemallocator`  | Default. Good all-round choice for throughput and RSS.               |
| `allocator-mimalloc` | `mimalloc`           | Alternative with different fragmentation characteristics.            |
| `allocator-system`   | `std::alloc::System` | Useful as a baseline for benchmarking.                               |
| `allocator-tcmalloc` | `tcmalloc-better`    | Linux x86_64 / aarch64 only. Fails to compile elsewhere — by design. |

Exactly one feature must be enabled. Invalid combinations fail the build with a clear error.

`src/main.rs` delegates to `src/allocator.rs` and doesn't touch allocator policy.

## Why not a runtime flag?

Because swapping the global allocator at runtime isn't a thing in Rust (and for good reason).
Making it a Cargo feature keeps the decision explicit, auditable, and benchmarkable. You rebuild,
you re-measure — there's no illusion that you can just flip a switch.

## Trade-offs

- Allocator changes require a rebuild. That's the point.
- `allocator-tcmalloc` intentionally fails on unsupported targets instead of silently falling back.
  Surprises in production are worse than a compile error.
- `cargo check --all-features` doesn't work because the features are mutually exclusive. This is
  a known ergonomic cost, but the alternative (runtime dispatch or silent feature priority) is worse.

## Validation

When changing allocator configuration:

- `cargo test` with the default feature;
- `cargo check` for each supported alternative;
- throughput + RSS benchmarks via `benches/` — don't assume a new allocator is faster without
  measuring.
