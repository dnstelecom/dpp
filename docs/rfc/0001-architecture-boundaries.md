# RFC 0001 — Ownership boundaries and benchmark contract

**Status:** Accepted · **Date:** 2025-01-14

## Why this matters

DPP has distinct stages for packet parsing, flow routing, DNS query/response matching, and
CSV or Parquet serialization. Explicit ownership boundaries keep configuration in one place
and make lifecycle and shutdown responsibilities clear.

The project also needs repeatable benchmarks that do not depend on hardcoded local paths or
private captures.

## Decision

Each module owns exactly one responsibility:

| Module | Ownership |
| --- | --- |
| [`config.rs`](../../src/config.rs) | Single source of truth for runtime policy: batch sizes, timeouts, and execution-model thresholds |
| [`output.rs`](../../src/output.rs) | Writer lifecycle and output-channel control messages |
| [`monitor_memory.rs`](../../src/monitor_memory.rs) | Optional RSS monitoring with explicit stop/join; must not outlive the process |
| [`app.rs`](../../src/app.rs) | Run orchestration, reporting, and shutdown coordination |
| [`main.rs`](../../src/main.rs) | Thin entrypoint: compose `cli`, `runtime`, and `app`; return the exit code |
| [`dns_processor/anonymizer.rs`](../../src/dns_processor/anonymizer.rs) | Key loading, PBKDF2 derivation, and deterministic IP pseudonymization |

Benchmark scaffolding lives under [`benches/`](../../benches/README.md) and takes all inputs
from the caller.

## Rationale

- **Single source of truth (SSOT):** runtime policy changes, such as match-timeout defaults,
  belong in `config.rs`.
- **Explicit lifecycle:** `monitor_memory` uses `stop()` and `join()`; the output channel closes
  through a control message. Shutdown does not depend on drop ordering or dropping the sender.
- **Reproducible benchmarks:** callers supply capture paths, keeping private input data out of
  the repository.

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
