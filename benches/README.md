# Benchmark Scaffolding

This directory is the canonical location for repeatable performance measurements.

Use [benchmark.sh](benchmark.sh) for end-to-end measurements, or choose a focused guide below.

## Files

| File or directory | Purpose |
| --- | --- |
| [benchmark.sh](benchmark.sh) | End-to-end benchmark harness for the `dpp` binary. |
| [allocator-benchmarking.md](allocator-benchmarking.md) | Canonical build-and-measure protocol for global allocator comparisons. |
| [protocol-correctness-audit.md](protocol-correctness-audit.md) | Final validation, restored throughput and measured memory costs of the 2026-09-05 protocol and matcher fixes; earlier experiments are identified separately. |
| [dns-compression.md](dns-compression.md) | Compression limits, message-local suffix caching, repeated measurements, RR-loop inlining and reproduction instructions. |
| [dns-compression-benchmark.py](dns-compression-benchmark.py) and [dns-compression/](dns-compression/) | Synthetic end-to-end and isolated scanner benchmarks for short names, shared suffixes and deep pointer chains. |

## Safety Contract

- The benchmark input PCAP must be provided explicitly with `--pcap` or `DPP_BENCH_PCAP`.
- The script does not upload data or fetch remote inputs.
- Results are written under the selected output directory, which defaults to `target/benchmarks/...`.
- Benchmark outputs can contain derived data from the input capture. Avoid committing or sharing
  them unless that is intended for the dataset.
- The script exits non-zero if any benchmarked run fails.

## Setup

For trusted benchmark runs, prefer the dedicated `perf` Cargo profile. It inherits from `release`
but disables overflow checks so benchmark numbers reflect the faster arithmetic path without
changing the default production build.

DPP auto-sizes execution from all available CPUs. The harness does not support a runtime
thread-count sweep. To compare smaller CPU budgets, limit CPU availability externally with your
platform tooling and run the harness once per environment.

## Example

```bash
bash benches/benchmark.sh \
  --pcap /path/to/capture.pcap \
  --profile perf \
  --formats csv,parquet \
  --bonded 0,131072 \
  --runs 3
```

Metrics are written to `metrics.csv` inside the chosen benchmark output directory. Run-level
provenance is written to `metadata.txt` in the same directory.

## What It Measures

| Category | Recorded fields |
| --- | --- |
| Run configuration | Build profile, output format, execution budget label, bonded channel capacity, run number and whether `--silent` was used. |
| Provenance | Current git SHA, benchmarked binary path, `rustc` version and verbose compiler metadata in `metadata.txt`. |
| Measurements | Total wall-clock time; processing speed and final writer shutdown tail parsed from application logs. |
| Result and artifacts | Exit code, log file path, output file path and whether the row has full metrics or wall-clock-only metrics. |

For `--silent` runs, the script records wall-clock time and exit status. Log-derived throughput
and shutdown-tail fields are intentionally left blank.
