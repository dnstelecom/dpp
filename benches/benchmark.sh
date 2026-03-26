#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/.." && pwd)"

pcap_path="${DPP_BENCH_PCAP:-}"
profile="${DPP_BENCH_PROFILE:-release}"
bin_path="${DPP_BENCH_BIN:-$repo_root/target/$profile/dpp}"
out_root="${DPP_BENCH_OUTDIR:-$repo_root/target/benchmarks/$(date +%Y%m%dT%H%M%S)}"
formats_csv="${DPP_BENCH_FORMATS:-csv,parquet}"
bonded_csv="${DPP_BENCH_BONDED:-0}"
runs="${DPP_BENCH_RUNS:-3}"
silent="${DPP_BENCH_SILENT:-0}"
build="${DPP_BENCH_BUILD:-1}"
dry_run=0
git_sha="$(git -C "$repo_root" rev-parse --short HEAD 2>/dev/null || printf 'unknown')"
failure_count=0

usage() {
  cat <<'EOF'
Usage: benchmark.sh [options]

Options:
  --pcap PATH       Input PCAP file (required)
  --bin PATH        Path to the release binary
  --profile NAME    Cargo build profile, default: release
  --outdir PATH     Directory for metrics and run logs
  --formats LIST    Comma-separated formats, default: csv,parquet
  --bonded LIST     Comma-separated bonded values, default: 0
  --runs N          Runs per configuration, default: 3
  --dry-run         Print planned commands without executing them
  --no-build        Skip cargo build for the selected profile
  --silent          Add --silent to the benchmarked runs (wall-clock-only metrics)
  -h, --help        Show this help

Environment overrides:
  DPP_BENCH_PCAP, DPP_BENCH_BIN, DPP_BENCH_PROFILE, DPP_BENCH_OUTDIR, DPP_BENCH_FORMATS,
  DPP_BENCH_BONDED, DPP_BENCH_RUNS, DPP_BENCH_SILENT,
  DPP_BENCH_BUILD
EOF
}

die() {
  printf 'benchmark.sh: %s\n' "$*" >&2
  exit 1
}

csv_escape() {
  local value="${1:-}"
  value="${value//$'\r'/ }"
  value="${value//$'\n'/ }"
  case "$value" in
    [=\+\-@]*)
      value="'$value"
      ;;
  esac
  value="${value//\"/\"\"}"
  printf '"%s"' "$value"
}

write_csv_row() {
  local first=1
  local field
  for field in "$@"; do
    if [[ "$first" == "1" ]]; then
      first=0
    else
      printf ',' >> "$metrics_file"
    fi
    csv_escape "$field" >> "$metrics_file"
  done
  printf '\n' >> "$metrics_file"
}

validate_format() {
  case "$1" in
    csv|parquet) ;;
    *)
      die "unsupported format: $1"
      ;;
  esac
}

validate_positive_integer() {
  [[ "$1" =~ ^[1-9][0-9]*$ ]] || die "$2 must be a positive integer: $1"
}

validate_non_negative_integer() {
  [[ "$1" =~ ^[0-9]+$ ]] || die "$2 must be a non-negative integer: $1"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --pcap)
      pcap_path="${2:-}"
      shift 2
      ;;
    --bin)
      bin_path="${2:-}"
      shift 2
      ;;
    --profile)
      profile="${2:-}"
      shift 2
      ;;
    --outdir)
      out_root="${2:-}"
      shift 2
      ;;
    --formats)
      formats_csv="${2:-}"
      shift 2
      ;;
    --threads)
      die "runtime thread-count overrides are deprecated; limit CPU availability externally instead"
      ;;
    --bonded)
      bonded_csv="${2:-}"
      shift 2
      ;;
    --runs)
      runs="${2:-}"
      shift 2
      ;;
    --dry-run)
      dry_run=1
      shift
      ;;
    --no-build)
      build=0
      shift
      ;;
    --silent)
      silent=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

[[ -n "$pcap_path" ]] || die "pass --pcap or set DPP_BENCH_PCAP explicitly"
[[ -f "$pcap_path" ]] || die "pcap not found: $pcap_path"
[[ "$profile" =~ ^[A-Za-z0-9_-]+$ ]] || die "profile contains unsupported characters: $profile"
validate_positive_integer "$runs" "runs"
[[ "$silent" == "0" || "$silent" == "1" ]] || die "silent must be 0 or 1: $silent"
[[ "$build" == "0" || "$build" == "1" ]] || die "build must be 0 or 1: $build"

formats_csv="${formats_csv//[[:space:]]/}"
bonded_csv="${bonded_csv//[[:space:]]/}"

default_bin_path="$repo_root/target/$profile/dpp"
if [[ -z "${DPP_BENCH_BIN:-}" ]]; then
  bin_path="$default_bin_path"
fi

mkdir -p "$out_root"
metrics_file="$out_root/metrics.csv"
metadata_file="$out_root/metadata.txt"
printf 'profile,format,threads,bonded,run,silent,metric_mode,git_sha,bin_path,wall_seconds,processing_speed_pps,final_write_seconds,exit_code,log_file,output_file\n' > "$metrics_file"
cat > "$metadata_file" <<EOF
git_sha=$git_sha
pcap_path=$pcap_path
profile=$profile
bin_path=$bin_path
formats=$formats_csv
threads=auto
bonded=$bonded_csv
runs=$runs
silent=$silent
EOF

if [[ "$build" == "1" ]]; then
  if [[ "$dry_run" == "1" ]]; then
    printf '[dry-run] cargo build --profile %q\n' "$profile"
  else
    (cd "$repo_root" && cargo build --profile "$profile")
  fi
fi

if [[ "$dry_run" != "1" && ! -x "$bin_path" ]]; then
  die "binary not executable: $bin_path"
fi

IFS=',' read -r -a formats <<< "$formats_csv"
IFS=',' read -r -a bonded_values <<< "$bonded_csv"

for format in "${formats[@]}"; do
  [[ -n "$format" ]] || continue
  validate_format "$format"
done

for bonded_value in "${bonded_values[@]}"; do
  [[ -n "$bonded_value" ]] || continue
  validate_non_negative_integer "$bonded_value" "bonded"
done

run_cmd() {
  local format="$1"
  local threads_value="auto"
  local bonded_value="$2"
  local run_id="$3"

  local run_dir="$out_root/${format}/t${threads_value}/b${bonded_value}"
  local output_ext="$format"
  local output_file="$run_dir/run-${run_id}.${output_ext}"
  local log_file="$run_dir/run-${run_id}.log"

  mkdir -p "$run_dir"

  local cmd=("$bin_path" "$pcap_path" "$output_file" --format "$format" --bonded "$bonded_value")
  if [[ "$silent" == "1" ]]; then
    cmd+=(--silent)
  fi

  if [[ "$dry_run" == "1" ]]; then
    printf '[dry-run]'
    printf ' %q' "${cmd[@]}"
    printf ' > %q 2>&1\n' "$log_file"
    return 0
  fi

  local start_ns end_ns wall_seconds exit_code processing_speed final_write metric_mode
  start_ns="$(date +%s%N)"
  set +e
  "${cmd[@]}" > "$log_file" 2>&1
  exit_code=$?
  set -e
  end_ns="$(date +%s%N)"
  wall_seconds="$(awk -v start="$start_ns" -v end="$end_ns" 'BEGIN { printf "%.6f", (end - start) / 1000000000 }')"

  if [[ "$silent" == "1" ]]; then
    processing_speed=""
    final_write=""
    metric_mode="wall_only"
  else
    processing_speed="$(sed -nE 's/.*Processing speed: ([0-9,]+) packets per second.*/\1/p' "$log_file" | tail -n1 | tr -d ',')"
    final_write="$(sed -nE 's/.*Final write post-processing completed in \+([0-9.]+) seconds.*/\1/p' "$log_file" | tail -n1)"
    metric_mode="full"
  fi

  write_csv_row \
    "$profile" \
    "$format" \
    "$threads_value" \
    "$bonded_value" \
    "$run_id" \
    "$silent" \
    "$metric_mode" \
    "$git_sha" \
    "$bin_path" \
    "$wall_seconds" \
    "${processing_speed:-}" \
    "${final_write:-}" \
    "$exit_code" \
    "$log_file" \
    "$output_file"

  if [[ "$exit_code" != "0" ]]; then
    failure_count=$((failure_count + 1))
  fi
}

for format in "${formats[@]}"; do
  [[ -n "$format" ]] || continue
  for bonded_value in "${bonded_values[@]}"; do
    [[ -n "$bonded_value" ]] || continue
    for ((run_id = 1; run_id <= runs; run_id++)); do
      run_cmd "$format" "$bonded_value" "$run_id"
    done
  done
done

printf 'benchmark metrics: %s\n' "$metrics_file"
printf 'benchmark metadata: %s\n' "$metadata_file"

if [[ "$failure_count" != "0" ]]; then
  die "benchmark sweep completed with $failure_count failed run(s)"
fi
