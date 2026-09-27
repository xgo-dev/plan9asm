#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
go_version=$(go env GOVERSION)
if [[ ! "$go_version" =~ ^go1[.]27([.]|$) ]]; then
  echo "compile benchmark requires Go 1.27, got $go_version" >&2
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "jq not found in PATH" >&2
  exit 1
fi

# Resolved relative to the checked-out repository.
# shellcheck disable=SC1091
source "$repo_root/scripts/llvm22.sh"
if ! llc_cmd=$(find_llvm22_llc); then
  exit 1
fi

targets_csv=${PLAN9ASM_BENCHMARK_TARGETS:-linux/386,linux/amd64,linux/arm,linux/arm64,js/wasm}
IFS=',' read -r -a targets <<<"$targets_csv"
if (( ${#targets[@]} == 0 )); then
  echo "PLAN9ASM_BENCHMARK_TARGETS must contain at least one GOOS/GOARCH target" >&2
  exit 2
fi
for target in "${targets[@]}"; do
  if ! [[ "$target" =~ ^[a-z0-9]+/(386|amd64|arm|arm64|wasm)$ ]]; then
    echo "invalid benchmark target $target" >&2
    exit 2
  fi
done

max_target_seconds=${PLAN9ASM_BENCHMARK_MAX_TARGET_SECONDS:-300}
max_total_seconds=${PLAN9ASM_BENCHMARK_MAX_TOTAL_SECONDS:-900}
if ! [[ "$max_target_seconds" =~ ^[1-9][0-9]*$ && "$max_total_seconds" =~ ^[1-9][0-9]*$ ]]; then
  echo "benchmark time budgets must be positive integer seconds" >&2
  exit 2
fi

report_dir=${PLAN9ASM_BENCHMARK_REPORT_DIR:-"$repo_root/_out/compile-benchmark"}
mkdir -p "$report_dir"
find "$report_dir" -maxdepth 1 -type f \( -name '*.json' -o -name '*.md' \) -delete

tmp_root=$(mktemp -d)
trap 'rm -rf "$tmp_root"' EXIT
translator="$tmp_root/plan9asmll"

group_start() {
  if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
    printf '::group::%s\n' "$1"
  else
    printf '==> %s\n' "$1"
  fi
}

group_end() {
  if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
    printf '::endgroup::\n'
  fi
}

group_start "build plan9asmll benchmark driver"
build_start=$SECONDS
if go build -C "$repo_root/cmd/plan9asmll" -o "$translator" .; then
  build_status=0
else
  build_status=$?
fi
build_seconds=$((SECONDS - build_start))
group_end
printf 'benchmark driver build: %ds\n' "$build_seconds"
if (( build_status != 0 )); then
  exit "$build_status"
fi

total_wall_seconds=0
budget_failed=0
metric_files=()
for target in "${targets[@]}"; do
  goos=${target%/*}
  goarch=${target#*/}
  target_id="$goos-$goarch"
  report_path="$report_dir/$target_id.json"
  metric_path="$tmp_root/$target_id-metric.json"

  group_start "compile benchmark $target"
  target_start=$SECONDS
  if "$translator" \
    -goos="$goos" \
    -goarch="$goarch" \
    -patterns=std \
    -compile \
    -llc="$llc_cmd" \
    -strict-load \
    -keep-going=false \
    -repo-root="$repo_root" \
    -out="$tmp_root/llvm/$target_id" \
    -report="$report_path"; then
    target_status=0
  else
    target_status=$?
  fi
  wall_seconds=$((SECONDS - target_start))
  group_end
  if (( target_status != 0 )); then
    echo "compile benchmark $target failed after ${wall_seconds}s" >&2
    exit "$target_status"
  fi

  failed=$(jq -r '.failed' "$report_path")
  total_asm=$(jq -r '.total_asm' "$report_path")
  success=$(jq -r '.success' "$report_path")
  not_applicable=$(jq -r '.not_applicable' "$report_path")
  tool_duration=$(jq -r '.duration' "$report_path")
  if [[ "$failed" != "0" || "$not_applicable" != "0" || "$success" != "$total_asm" || ! "$total_asm" =~ ^[1-9][0-9]*$ ]]; then
    echo "compile benchmark $target requires every assembly file to compile: total=$total_asm success=$success not_applicable=$not_applicable failed=$failed" >&2
    exit 1
  fi
  total_wall_seconds=$((total_wall_seconds + wall_seconds))
  if (( wall_seconds > max_target_seconds )); then
    echo "compile benchmark $target exceeded ${max_target_seconds}s budget: ${wall_seconds}s" >&2
    budget_failed=1
  fi
  printf 'compile benchmark %s: wall=%ds tool=%s asm=%s success=%s not_applicable=%s\n' \
    "$target" "$wall_seconds" "$tool_duration" "$total_asm" "$success" "$not_applicable"

  jq -n \
    --arg target "$target" \
    --arg tool_duration "$tool_duration" \
    --argjson wall_seconds "$wall_seconds" \
    --argjson total_asm "$total_asm" \
    --argjson success "$success" \
    --argjson not_applicable "$not_applicable" \
    '{target:$target,wall_seconds:$wall_seconds,tool_duration:$tool_duration,total_asm:$total_asm,success:$success,not_applicable:$not_applicable}' \
    >"$metric_path"
  metric_files+=("$metric_path")

  # The benchmark report is outside tmp_root; compiled IR and objects from
  # completed targets are not needed by the remaining targets.
  rm -r "$tmp_root/llvm/$target_id"
done

jq -s \
  --arg go_version "$go_version" \
  --arg llc "$llc_cmd" \
  --argjson build_seconds "$build_seconds" \
  --argjson total_wall_seconds "$total_wall_seconds" \
  --argjson max_target_seconds "$max_target_seconds" \
  --argjson max_total_seconds "$max_total_seconds" \
  '{schema_version:1,go_version:$go_version,llc:$llc,build_seconds:$build_seconds,total_wall_seconds:$total_wall_seconds,max_target_seconds:$max_target_seconds,max_total_seconds:$max_total_seconds,targets:.}' \
  "${metric_files[@]}" >"$report_dir/summary.json"

summary_path="$report_dir/summary.md"
{
  printf '### Compile benchmark\n\n'
  printf '| Target | Wall | Tool duration | Asm files | Success | N/A |\n'
  printf '| --- | ---: | ---: | ---: | ---: | ---: |\n'
  jq -r '.targets[] | "| \(.target) | \(.wall_seconds)s | \(.tool_duration) | \(.total_asm) | \(.success) | \(.not_applicable) |"' "$report_dir/summary.json"
  printf '\nBuild: %ss; target total: %ss; budgets: %ss per target / %ss total.\n' \
    "$build_seconds" "$total_wall_seconds" "$max_target_seconds" "$max_total_seconds"
} >"$summary_path"
cat "$summary_path"
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  cat "$summary_path" >>"$GITHUB_STEP_SUMMARY"
fi

if (( total_wall_seconds > max_total_seconds )); then
  echo "compile benchmark exceeded ${max_total_seconds}s total budget: ${total_wall_seconds}s" >&2
  budget_failed=1
fi
if (( budget_failed != 0 )); then
  exit 1
fi
