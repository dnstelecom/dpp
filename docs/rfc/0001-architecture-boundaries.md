# RFC 0001 — Ownership Boundaries and Benchmark Contract

Status: Accepted  
Date: 2025-01-14

## Why this matters

DPP is a multi-threaded pipeline with distinct stages: packet parsing, flow-based routing,
DNS query/response matching, and serialization to CSV or Parquet. Without explicit ownership
boundaries, responsibility bleeds across modules — configuration gets duplicated, lifecycle
contracts become implicit, and shutdown turns into a guessing game.

On top of that, the project needs a repeatable benchmark that doesn't depend on local paths
or private PCAP captures sitting on someone's laptop.

## Decision

Each module owns exactly one responsibility:

| Module                            | What it owns                                                                                 |
|-----------------------------------|----------------------------------------------------------------------------------------------|
| `src/config.rs`                   | Single source of truth for runtime policy: batch sizes, timeouts, execution-model thresholds |
| `src/output.rs`                   | Writer lifecycle and output-channel control messages                                         |
| `src/monitor_memory.rs`           | Optional RSS monitoring with explicit stop/join — must not outlive the process               |
| `src/app.rs`                      | Run orchestration, reporting, shutdown coordination                                          |
| `src/main.rs`                     | Thin entrypoint: wires `cli` + `runtime` + `app`, returns exit code                          |
| `src/dns_processor/anonymizer.rs` | Key loading, PBKDF2 derivation, deterministic IP pseudonymization                            |

Benchmark scaffolding lives under `benches/` and takes all inputs from the caller.

## Rationale

- **SSOT** — every policy is defined in one place. Changing the match timeout means editing
  `config.rs`, not grepping the whole tree.
- **Explicit lifecycle** — shutdown doesn't depend on drop ordering. `monitor_memory` has
  `stop()` + `join()`, the output channel closes via a control message, not by dropping the sender.
- **Reproducible benchmarks** — the script has no idea where PCAP files live until you tell it.
  This keeps private data out of the repository by construction.

## Consequences

- Any refactor that moves an ownership boundary must update this RFC.
- Benchmark results are comparative data, not a substitute for correctness tests.
- New canonical directories get documented here or in a follow-up RFC.

## Benchmark contract

`benches/benchmark.sh` must:

- accept a PCAP path from the caller — no hardcoded local paths;
- support both CSV and Parquet output;
- record wall-clock runtime and the writer shutdown tail;
- allow bonded-channel sweeps and CPU-budget comparisons;
- leave generated metrics in the benchmark output directory.
