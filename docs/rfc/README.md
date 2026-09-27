# RFC index

Each RFC records an architecture decision: the problem, chosen approach, trade-offs, and
conditions for revisiting it. Start with [DPP Architecture](../architecture.md) for the system
overview; use these records to understand why it works that way.

## Ground rules

- Record decisions that affect ownership boundaries, a single source of truth (SSOT), lifecycle
  contracts, or benchmark policy.
- Keep the high-level architecture in [architecture.md](../architecture.md) and decision
  rationale here.
- Give new RFCs the next sequential numeric prefix and a short descriptive slug.

## Current RFCs

All RFCs below have **Accepted** status. For experiment records, this means the decision to
retain the existing design was accepted; the tested replacements were rejected.

| RFC | Decision | Read it for |
| --- | --- | --- |
| [0001](0001-architecture-boundaries.md) | Ownership boundaries and benchmark contract | Module ownership, SSOT, and benchmark inputs |
| [0002](0002-cli-and-runtime-boundaries.md) | CLI and runtime bootstrap boundaries | Argument resolution, environment precedence, and host setup |
| [0003](0003-allocator-selection.md) | Compile-time allocator selection | Cargo features, platform limits, and validation |
| [0004](0004-forward-only-matcher.md) | Forward-only matching and determinism | Flow routing, transaction identity, retries, ordering, and eviction |
| [0005](0005-dual-path-pcap-parsing.md) | Capture parsing and monotonic timestamps | Reader selection, protocol boundaries, and timestamp validation |
| [0006](0006-adaptive-pipeline.md) | Adaptive pipeline execution | Staged and phase-parallel models, selected by CPU budget |
| [0007](0007-packet-storage-allocation.md) | Retain per-packet payload ownership | Rejected storage/decoder allocation experiments and reconsideration criteria |
| [0008](0008-matcher-state-expiry.md) | Retain current matcher expiry behavior | Rejected expiry indexes and safe reconsideration criteria |
