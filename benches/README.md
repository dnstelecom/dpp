# Benchmark Scaffolding

This directory is the canonical location for repeatable performance measurements.

## Files

- `benchmark.sh`: end-to-end benchmark harness for the `dpp` binary.
- `allocator-benchmarking.md`: canonical build-and-measure protocol for global allocator
  comparisons.

## Safety Contract

- The benchmark input PCAP must be provided explicitly with `--pcap` or `DPP_BENCH_PCAP`.
- The script does not upload data or fetch remote inputs.
- Results are written under the selected output directory, which defaults to `target/benchmarks/...`.
- Benchmark outputs can contain derived data from the input capture, so avoid committing or sharing them unless that is intended for the dataset.
- The script exits non-zero if any benchmarked run fails.

## What It Measures

`benchmark.sh` records:

- build profile
- output format
- execution budget label
- bonded channel capacity
- run number
- whether the run used `--silent`
- whether the row contains full metrics or wall-clock-only metrics
- current git SHA and benchmarked binary path
- total wall-clock time
- processing speed parsed from application logs
- final writer shutdown tail parsed from application logs
- exit code
- log file path
- output file path

For `--silent` runs, the script records wall-clock and exit status, but log-derived throughput and
shutdown-tail fields are intentionally left blank.

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

Note: DPP now auto-sizes execution from all available CPUs. The harness no longer supports a
runtime thread-count sweep; if you need to compare smaller CPU budgets, limit CPU availability
externally with your platform tooling and run the harness once per environment.

For trusted benchmark runs, prefer the dedicated `perf` Cargo profile. It inherits from `release`
but disables overflow checks so benchmark numbers reflect the faster arithmetic path without
changing the default production build.
