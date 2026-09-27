# DNS compression validation and performance

## Behavior and validation

`--max-dns-compression-jumps` defaults to 32. The environment equivalent is
`DPP_MAX_DNS_COMPRESSION_JUMPS`; an explicit CLI value takes precedence. Zero disables
the jump-count policy, while backward-pointer, bounds and nonoverlap checks remain
mandatory. The policy covers questions, scanned RR owners and TSIG algorithm names,
including partial responses and the optional wire fast path's Hickory fallback.

The decoder belongs to one immutable DNS message. Cached suffixes retain their
encoded segment end, expanded length, pointer depth and first label. Reuse checks
the segment end against the new referring name and charges the entire cached
depth against the configured limit. Entries are published only after a complete
successful walk. No cache survives the message or crosses worker ownership.

Short RR-owner walks use a direct scanner: at most eight pointers and 64 literal
bytes per referenced segment. Crossing either threshold switches to the cached
scanner from the original name offset. These thresholds select an implementation,
not a different acceptance policy. Uncompressed questions in the optional fast
path retain a single-pass formatter. Compressed questions are validated before
Hickory receives their expanded wire form, avoiding recursive replay of long
pointer chains.

The tests cover exact jump boundaries, zero/unlimited, warmed-cache depth and
overlap checks, literal versus compressed OPT roots, TSIG, partial fragments,
malformed and oversized questions, per-message isolation, and bounded traversal
work. The strictly backward, nonoverlapping walker accepts a synthetic raw name
with 8,193 pointer transitions when unlimited; normal DNS record framing further
limits how many such segments fit into a message. The deep benchmark is a valid
64,419-byte DNS response with 4,600 RRs and a maximum depth of 1,170.

## Measurement method

The end-to-end baseline is commit `7807751`, immediately before configurable
limits and suffix caching. The measured implementation is `400acc5`. Both binaries
use Rust 1.97.1, the `perf` profile and default jemalloc features, on macOS/aarch64.
`perf` disables overflow checks; these measurements
must not be interpreted as measurements of the production `release` profile.

`dns-compression-benchmark.py` generates deterministic synthetic PCAPs and `.dns`
messages locally. Each configuration gets an excluded warm-up pair followed by
10 measured pairs, alternating which binary runs first. Builds and other test
processes are stopped during measurement. All `DPP_*` environment overrides are
removed for each child process.

The harness validates packet, query, response, match and timeout counters on every
run, then compares CSV contents. Parallel output is sorted before comparison.
It records binary SHA-256, fixture dimensions, per-run processing time, wall time,
RSS and checksums. The main statistic is the median of the paired
candidate/baseline processing-time ratios; below 1 is faster. The interquartile
range (IQR) describes dispersion, **not** a confidence interval. A single favorable
run is not evidence of an improvement.

The isolated scanner benchmark uses a fresh message-local decoder per iteration
and a historical uncached walker with the **same** configurable limit. This
separates scanner/cache cost from the end-to-end changes in question parsing and
mandatory validation. The full-application uncached control makes the same
comparison for RR-name skipping while keeping the new question parser (including
its suffix cache) and policy.

## Reproduction

Build the baseline and candidate with the same compiler, target and allocator:

```bash
bench_dir=$(mktemp -d /tmp/dpp-compression.XXXXXX)
mkdir "$bench_dir/baseline"
git archive 7807751 | tar -x -C "$bench_dir/baseline"
cargo build --manifest-path "$bench_dir/baseline/Cargo.toml" \
  --target-dir "$bench_dir/baseline-target" --profile perf --locked --offline
cp "$bench_dir/baseline-target/perf/dpp" "$bench_dir/dpp-before"
cargo build --target-dir "$bench_dir/candidate-target" --profile perf --locked --offline
cp "$bench_dir/candidate-target/perf/dpp" "$bench_dir/dpp-after"

python3 benches/dns-compression-benchmark.py \
  --baseline "$bench_dir/dpp-before" --candidate "$bench_dir/dpp-after" \
  --outdir "$bench_dir/short" --runs 10 --transactions 1000000 \
  --cases empty,one,two,eight,literal-eight,three-label-eight,chain8-eight \
  --limits 32 --decoders both

python3 benches/dns-compression-benchmark.py \
  --baseline "$bench_dir/dpp-before" --candidate "$bench_dir/dpp-after" \
  --outdir "$bench_dir/unlimited" --runs 10 --transactions 200000 \
  --cases one,three-label-eight,long-name-eight,chain2-eight --limits 0 --decoders both

python3 benches/dns-compression-benchmark.py \
  --baseline "$bench_dir/dpp-before" --candidate "$bench_dir/dpp-after" \
  --outdir "$bench_dir/dense" --runs 10 --transactions 200000 \
  --cases distinct-128,suffix-128,chain32-128,flat-4600,deep-4600 \
  --limits 32,0 --decoders both

python3 benches/dns-compression-benchmark.py \
  --baseline "$bench_dir/dpp-before" --candidate "$bench_dir/dpp-after" \
  --outdir "$bench_dir/staged" --runs 10 --transactions 200000 \
  --cases one,chain32-128,deep-4600 --threads 5 --limits 32,0 --decoders both
```

Dense fixtures scale the transaction count by 20 for 128 RRs and by 1,000 for
4,600 RRs. The harness omits configurations whose depth exceeds the requested
nonzero limit, so the deep case runs only with zero. Add `--threads 5` to exercise
the staged pipeline, and use a new output directory for each experiment.

Build and run the isolated scanner using dependency paths reported by Cargo for
the current compiler, rather than picking arbitrary old `.rlib` files:

```bash
python3 benches/dns-compression/build-scan.py --output "$bench_dir/dns-compression-scan"
"$bench_dir/dns-compression-scan" "$bench_dir/short" 10 100 > "$bench_dir/scan-short.csv"
"$bench_dir/dns-compression-scan" "$bench_dir/unlimited" 10 100 > "$bench_dir/scan-unlimited.csv"
"$bench_dir/dns-compression-scan" "$bench_dir/dense" 10 100 > "$bench_dir/scan-dense.csv"
```

To reproduce the end-to-end control with uncached RR-name skipping, export the
candidate commit and apply the benchmark-only patch in that separate directory:

```bash
mkdir "$bench_dir/control"
git archive HEAD | tar -x -C "$bench_dir/control"
git -C "$bench_dir/control" apply "$PWD/benches/dns-compression/uncached-control.patch"
cargo build --manifest-path "$bench_dir/control/Cargo.toml" \
  --target-dir "$bench_dir/control-target" --profile perf --locked --offline
python3 benches/dns-compression-benchmark.py \
  --baseline "$bench_dir/control-target/perf/dpp" --candidate "$bench_dir/dpp-after" \
  --baseline-limit 32 --limits 32 --decoders fast \
  --cases one,two,eight,literal-eight,three-label-eight \
  --outdir "$bench_dir/control-results" --runs 10 --transactions 1000000
```

Use an explicit `--baseline-limit 0` when comparing unlimited configurations with
this control. Leave `--baseline-limit` unset for the historical binary, which
predates the option. The patch is a measurement control, not a production mode.

The scripts use synthetic data only and do not upload anything. Keep raw output
under the selected benchmark directory rather than committing generated PCAPs.
Keep build directories separate: exporting several revisions into one shared
Cargo target directory can leave the top-level executable from the last copy even
when a later build of another copy reports `Fresh`.

Final correctness checks on `400acc5` passed: 353 workspace tests, formatting,
`git diff --check`, and Clippy with the existing `too_many_arguments`,
`type_complexity` and `large_enum_variant` allowances. CLI smoke checks cover
default rejection at 33 jumps, explicit 33, zero, environment configuration and
CLI precedence, in both decoder modes. Before the final inlining and plain-QNAME
optimizations, a separate randomized comparison of the cached and uncached
validators covered six million calls over 20,000 messages, with cold and warm
caches and limits 0 through 11. The final changes also received an independent
review of cursor handling, error classification and limit equivalence.

## Results

### Short messages against `7807751`

Ten alternating pairs per configuration, 1,000,000 query/response transactions,
one processing thread, candidate limit 32. Each cell is median paired ratio
followed by its IQR; below 1 is faster.

| Response owners | Default decoder | Optional fast decoder |
| --- | ---: | ---: |
| None | 0.917 [0.908–0.927] | 1.000 [0.995–1.006] |
| One compressed owner | 0.908 [0.899–0.915] | 1.004 [0.994–1.020] |
| Two compressed owners | 0.941 [0.925–0.944] | 1.024 [1.015–1.033] |
| Eight compressed owners | 0.939 [0.934–0.953] | 1.036 [1.030–1.046] |
| Eight literal owners | 0.941 [0.938–0.955] | 1.043 [1.039–1.053] |
| Eight owners sharing `www.example.com` | 0.923 [0.916–0.930] | 1.014 [0.994–1.022] |
| Eight owners, chain depth up to eight | 0.941 [0.939–0.945] | 1.014 [1.003–1.020] |

The default decoder uses approximately 6–9% less processing time in this set.
The optional fast decoder has a **remaining end-to-end regression** on several
small synthetic cases, up to 4.3% for eight literal owners. For that case the
median times are 0.267963 s before and 0.278825 s after, per million transactions.
This is not dismissed as noise: its paired IQR is wholly above 1. The complete
change includes configurable validation, different question parsing and cache
context; the control below isolates the adaptive RR scanner more narrowly.

### Same-policy RR-scanner control

Ten alternating pairs, 1,000,000 transactions per case, optional fast question
decoder, one processing thread, both binaries explicitly limited to 32 jumps:

| Response owners | Uncached control median (s) | Candidate median (s) | Median paired ratio | Ratio IQR |
| --- | ---: | ---: | ---: | ---: |
| One compressed owner | 0.233462 | 0.234452 | 1.001 | 0.997–1.020 |
| Two compressed owners | 0.242091 | 0.242340 | 0.996 | 0.989–1.013 |
| Eight compressed owners | 0.283838 | 0.286409 | 1.006 | 0.992–1.017 |
| Eight literal owners | 0.277441 | 0.279397 | 1.007 | 0.988–1.028 |
| Eight owners sharing `www.example.com` | 0.338048 | 0.337085 | 0.998 | 0.992–1.006 |

These runs do not show a consistent short-message penalty from the adaptive RR
scanner: each IQR includes 1. This is narrower than a claim that the complete
change is free, or that performance is identical on every machine and workload.
Ratios are medians of pairs and need not equal the ratio of the two time medians.

### Unlimited and dense messages

Ten pairs per configuration. Unlimited short cases use 200,000 transactions;
dense cases use 10,000 transactions for 128 RRs and 200 for 4,600 RRs.

| Case | Limit | Default decoder ratio [IQR] | Optional fast decoder ratio [IQR] |
| --- | ---: | ---: | ---: |
| One owner | 0 | 0.925 [0.915–0.947] | 1.022 [1.004–1.031] |
| Eight owners sharing `www.example.com` | 0 | 0.920 [0.907–0.943] | 1.002 [0.990–1.009] |
| Eight owners sharing a 211-byte name | 0 | 0.992 [0.984–1.000] | 0.981 [0.958–0.984] |
| Eight owners, chain depth two | 0 | 0.943 [0.933–0.967] | 1.010 [0.992–1.024] |
| 128 distinct literal owners | 32 | 0.995 [0.984–1.035] | 1.025 [0.969–1.035] |
| 128 distinct literal owners | 0 | 1.029 [1.011–1.076] | 1.000 [0.978–1.026] |
| 128 owners with a shared suffix | 32 | 1.000 [0.970–1.016] | 0.995 [0.976–1.049] |
| 128 owners with a shared suffix | 0 | 1.004 [0.979–1.019] | 0.979 [0.955–1.011] |
| 128 owners, chain depth 32 | 32 | 0.707 [0.698–0.717] | 0.713 [0.690–0.728] |
| 128 owners, chain depth 32 | 0 | 0.714 [0.690–0.723] | 0.702 [0.697–0.726] |
| 4,600 owners pointing directly to the question | 32 | 1.028 [0.993–1.119] | 1.004 [0.973–1.049] |
| 4,600 owners pointing directly to the question | 0 | 1.009 [0.973–1.038] | 1.012 [0.987–1.063] |
| 4,600 owners, chain depth 1,170 | 0 | 0.036 [0.035–0.037] | 0.037 [0.037–0.038] |

The depth-32 workload needs about 30% less processing time. The deep unlimited
workload improves from median 1.443625 s to 0.052278 s with the default decoder,
and from 1.440767 s to 0.053734 s with the fast decoder (about 27 times faster).
The distinct-owner unlimited/default configuration also has an observed +2.9%
paired median with IQR above 1. Other flat dense configurations mostly overlap 1.
Their 30–40 ms end-to-end duration limits sensitivity to scanner costs; the
isolated measurements below provide a second, narrower view.

### Five-thread staged pipeline

Ten pairs, 200,000 short transactions, 10,000 depth-32 transactions and 200 deep
transactions, using the same binary pair:

| Case | Limit | Default decoder ratio [IQR] | Optional fast decoder ratio [IQR] |
| --- | ---: | ---: | ---: |
| One owner | 32 | 0.961 [0.947–0.985] | 0.977 [0.948–1.000] |
| One owner | 0 | 0.942 [0.924–0.968] | 1.021 [0.995–1.059] |
| 128 owners, chain depth 32 | 32 | 0.840 [0.808–0.858] | 0.834 [0.824–0.856] |
| 128 owners, chain depth 32 | 0 | 0.811 [0.796–0.845] | 0.792 [0.781–0.800] |
| 4,600 owners, chain depth 1,170 | 0 | 0.066 [0.065–0.068] | 0.065 [0.064–0.067] |

The deep default-decoder medians are 0.561074 s before and 0.036981 s after,
approximately a 15-fold improvement. Every pair has identical normalized CSV
contents and expected transaction counters.

RSS is retained in the raw data but is not used to claim peak-memory savings.
The application samples RSS every 100 ms, longer than many candidate runs; a
shorter run can miss a memory peak that the slower baseline happens to sample.

### Isolated name scanning with equal limits

Ten alternating pairs per case/limit, one excluded warm-up pair, 100 ms per
sample. Times include skipping the question and all RR owners of one DNS message,
with a fresh decoder each time; they exclude question formatting, matching and
CSV output. The baseline walker receives the same limit as the candidate.

| Case | Median ns/message before → after (limit 32) | Ratio at 32 [IQR] | Ratio at 0 [IQR] |
| --- | ---: | ---: | ---: |
| No RR owners | 2.75 → 3.17 | 1.150 [1.133–1.158] | 0.974 [0.966–0.983] |
| One owner | 5.63 → 5.24 | 0.927 [0.920–0.971] | 0.792 [0.785–0.807] |
| Two owners | 8.84 → 7.73 | 0.873 [0.864–0.899] | 0.750 [0.741–0.764] |
| Eight owners | 33.07 → 27.88 | 0.837 [0.835–0.856] | 0.832 [0.823–0.840] |
| Eight literal owners | 22.02 → 16.09 | 0.733 [0.727–0.742] | 0.686 [0.680–0.691] |
| Eight owners sharing `www.example.com` | 50.95 → 52.42 | 1.029 [1.018–1.046] | 1.022 [1.020–1.038] |
| Eight owners sharing a 211-byte name | 145.81 → 79.04 | 0.539 [0.533–0.556] | 0.544 [0.530–0.549] |
| Eight owners, chain depth two | 45.66 → 40.08 | 0.879 [0.872–0.890] | 0.866 [0.848–0.875] |
| Eight owners, chain depth eight | 82.91 → 73.44 | 0.881 [0.868–0.899] | 0.920 [0.913–0.930] |
| 128 distinct literal owners | 599.77 → 493.21 | 0.825 [0.814–0.833] | 0.820 [0.797–0.827] |
| 128 owners with a shared suffix | 741.39 → 686.99 | 0.921 [0.916–0.936] | 0.858 [0.840–0.869] |
| 128 owners, chain depth 32 | 5,987.28 → 2,712.57 | 0.452 [0.451–0.458] | 0.460 [0.455–0.465] |
| 4,600 flat owners | 22,992.61 → 17,816.45 | 0.777 [0.772–0.784] | 0.779 [0.768–0.790] |
| 4,600 owners, chain depth 1,170 | Rejected by policy | — | 0.0154 [0.0151–0.0156] |

The unlimited deep-case medians are 6.966778 ms and 107.433 microseconds per
message, approximately a 65-fold scanner improvement. Most shallow cases also
improve. Two small costs remain measurable: approximately 0.4 ns per empty
response at limit 32, and 1.5 ns per response with eight three-label owners.
The latter is about 2–3% of isolated scanning. Therefore the result is **not**
"zero overhead in every case," even though the same-policy end-to-end control
cannot consistently distinguish these costs from its variation.

### Recorded artifacts

Run-level CSV, summaries and metadata from this machine are under
`/tmp/dpp-compression-final-400-{short,unlimited,dense,staged}` and
`/tmp/dpp-compression-causal-control` (the additional two-owner control is separate).
The isolated results are `/tmp/dpp-compression-final-micro.csv` and
`/tmp/dpp-compression-final-micro-summary.json`; the combined machine-readable
summary is `/tmp/dpp-compression-final-summary.json`.
These temporary files are not required to reproduce the measurements.

| Binary | SHA-256 |
| --- | --- |
| Historical `7807751` | `8199ab733f9ff1f0c839fa04cbc556d0af410bdde434175f5572c06437628e59` |
| Final `400acc5` | `76c8ea5e7f3d2dfaa8e0190ec54893dbe70ddc5f54ae34ab097fb68431da60ce` |
| Same-source candidate used for the causal control, before refreshing build metadata | `f3cf38d9931b436a9130bcc36feac698be4bd925891c6554f40090ec176a74d7` |
| Uncached RR-scanner control | `cbc0c0f0b0dad398a2d4d541546aabc403f2eb5a7c094f0921c2ad59a301fbed` |

Measurements use macOS 15.8/aarch64 and Python 3.14.6. Absolute timings and small
relative differences are machine- and workload-dependent; these synthetic runs
do not establish universal performance equivalence.
