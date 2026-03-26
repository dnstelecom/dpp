# RFC Index

This directory holds architecture decision records for DPP. Each RFC captures a specific
design decision — the problem it solves, the chosen approach, and the trade-offs involved.

## Ground rules

- If a decision affects ownership boundaries, SSOT, lifecycle contracts, or benchmark policy,
  it belongs here.
- `docs/architecture.md` is the high-level architecture reference. RFCs record the *reasoning*
  behind that architecture.
- New RFCs use a sequential numeric prefix and a short descriptive slug.

## Current RFCs

| RFC                                        | Title                                           | Scope                                                    |
|--------------------------------------------|-------------------------------------------------|----------------------------------------------------------|
| [0001](0001-architecture-boundaries.md)    | Ownership Boundaries and Benchmark Contract     | Module ownership, SSOT discipline, benchmark scaffolding |
| [0002](0002-cli-and-runtime-boundaries.md) | CLI and Runtime Bootstrap Boundaries            | CLI parsing, env precedence, runtime bootstrap split     |
| [0003](0003-allocator-selection.md)        | Compile-Time Allocator Selection                | Build-time allocator features, validation contract       |
| [0004](0004-forward-only-matcher.md)       | Forward-Only Matcher and Determinism Contract   | Shard-local matching, retry dedup, batched eviction      |
| [0005](0005-dual-path-pcap-parsing.md)     | Dual-Path PCAP Parsing and Monotonic Timestamps | Pure-Rust vs libpcap backends, monotonic contract        |
| [0006](0006-adaptive-pipeline.md)          | Adaptive Pipeline: Staged vs Phase-Parallel     | Automatic execution model selection by CPU budget        |
