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
seen_targets=,
for target in "${targets[@]}"; do
  if ! [[ "$target" =~ ^[a-z0-9]+/(386|amd64|arm|arm64|wasm)$ ]]; then
    echo "invalid benchmark target $target" >&2
    exit 2
  fi
  if [[ "$seen_targets" == *",$target,"* ]]; then
    echo "duplicate benchmark target $target" >&2
    exit 2
  fi
  seen_targets+="$target,"
done

max_target_seconds=${PLAN9ASM_BENCHMARK_MAX_TARGET_SECONDS:-300}
max_total_seconds=${PLAN9ASM_BENCHMARK_MAX_TOTAL_SECONDS:-900}
if ! [[ "$max_target_seconds" =~ ^[1-9][0-9]*$ && "$max_total_seconds" =~ ^[1-9][0-9]*$ ]]; then
  echo "benchmark time budgets must be positive integer seconds" >&2
  exit 2
fi

report_dir=${PLAN9ASM_BENCHMARK_REPORT_DIR:-"$repo_root/_out/compile-benchmark"}
if [[ -d "$report_dir" ]] && [[ -n "$(find "$report_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  echo "benchmark reports already exist; select a fresh PLAN9ASM_BENCHMARK_REPORT_DIR" >&2
  exit 2
fi
mkdir -p "$report_dir"

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
compile_failed=0
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
    -keep-going=true \
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
  fi

  report_valid=false
  statistics=null
  if [[ -f "$report_path" ]] && jq -e --arg goos "$goos" --arg goarch "$goarch" '
    def count: type == "number" and . >= 0 and . == floor;
    type == "object" and .goos == $goos and .goarch == $goarch and
    ([.total_asm, .success, .failed, .not_applicable] | all(count)) and
    .total_asm > 0 and .success + .failed + .not_applicable <= .total_asm and
    (.asm_files | type == "array") and (.asm_files | length) == .total_asm and
    (.asm_files | all(type == "string" and length > 0)) and
    (.asm_files | unique | length) == .total_asm and
    ((.fails // []) | type == "array") and ((.fails // []) | length) == .failed and
    (.duration | type == "string")
  ' "$report_path" > /dev/null 2> "$report_dir/$target_id-validation.stderr"; then
    report_valid=true
    statistics=$(jq -c '{total_asm, success, failed, not_applicable, duration}' "$report_path")
  else
    echo "compile benchmark $target has no valid target-bound report; counts remain unknown" >&2
  fi

  status=failed
  if (( target_status == 0 )) && [[ "$report_valid" == true ]] &&
    jq -e '.failed == 0 and .not_applicable == 0 and .success == .total_asm' "$report_path" > /dev/null; then
    status=passed
  else
    compile_failed=1
    echo "compile benchmark $target requires a successful command and every assembly file compiled" >&2
  fi

  total_wall_seconds=$((total_wall_seconds + wall_seconds))
  if (( wall_seconds > max_target_seconds )); then
    echo "compile benchmark $target exceeded ${max_target_seconds}s budget: ${wall_seconds}s" >&2
    budget_failed=1
    status=failed
  fi
  printf 'compile benchmark %s: status=%s command_exit=%s wall=%ds statistics=%s\n' \
    "$target" "$status" "$target_status" "$wall_seconds" "$statistics"

  jq -n \
    --arg target "$target" \
    --arg status "$status" \
    --argjson command_exit "$target_status" \
    --argjson report_valid "$report_valid" \
    --argjson wall_seconds "$wall_seconds" \
    --argjson statistics "$statistics" '
      {target:$target, status:$status, command_exit:$command_exit,
       report_valid:$report_valid, wall_seconds:$wall_seconds,
       tool_duration:$statistics.duration, total_asm:$statistics.total_asm,
       success:$statistics.success, failed:$statistics.failed,
       not_applicable:$statistics.not_applicable,
       unattempted:(if $statistics == null then null else
         $statistics.total_asm - $statistics.success - $statistics.failed - $statistics.not_applicable
       end)}
    ' \
    >"$metric_path"
  metric_files+=("$metric_path")

  # The benchmark report is outside tmp_root; compiled IR and objects from
  # completed targets are not needed by the remaining targets.
  if [[ -d "$tmp_root/llvm/$target_id" ]]; then
    rm -r "$tmp_root/llvm/$target_id"
  fi
done

jq -s \
  --arg go_version "$go_version" \
  --arg llc "$llc_cmd" \
  --argjson build_seconds "$build_seconds" \
  --argjson total_wall_seconds "$total_wall_seconds" \
  --argjson max_target_seconds "$max_target_seconds" \
  --argjson max_total_seconds "$max_total_seconds" \
  '{schema_version:2,go_version:$go_version,llc:$llc,build_seconds:$build_seconds,total_wall_seconds:$total_wall_seconds,max_target_seconds:$max_target_seconds,max_total_seconds:$max_total_seconds,all_passed:(all(.status == "passed") and $total_wall_seconds <= $max_total_seconds),targets:.}' \
  "${metric_files[@]}" >"$report_dir/summary.json"

summary_path="$report_dir/summary.md"
{
  printf '### Compile benchmark\n\n'
  printf '| Target | Status | Exit | Wall | Tool duration | Asm files | Success | N/A | Failed | Unattempted |\n'
  printf '| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n'
  jq -r '.targets[] | "| \(.target) | \(.status) | \(.command_exit) | \(.wall_seconds)s | \(.tool_duration) | \(.total_asm) | \(.success) | \(.not_applicable) | \(.failed) | \(.unattempted) |"' "$report_dir/summary.json"
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
if (( budget_failed != 0 || compile_failed != 0 )); then
  exit 1
fi
