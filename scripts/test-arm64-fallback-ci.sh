#!/usr/bin/env bash
set -euo pipefail

# Reuse the registered strict selected-CI protocol. Owner zero executes the one
# complete rich-CLI root; owner one is explicitly empty, not another execution.
root=TestFallbackARM64WideFrameCompilesWithLLVM22
mode=${1:?execute or complete required}
if [[ ${PLAN9ASM_CROSS_EXEC:-} != 1 ]]; then
  echo 'ARM64 fallback CI requires PLAN9ASM_CROSS_EXEC=1' >&2
  exit 1
fi

run_owner_or_reader() {
  local output=$1
  shift
  go run ./cmd/plan9asmtest -dir cmd/plan9asmll -out "$output" \
    -ci-selector "^${root}$" -ci-isolate-root "$root" \
    -shards 2 -timeout 5m "$@"
}

case "$mode" in
  execute)
    base=_out/cross-runtime-owner/arm64-fallback-cross
    mkdir "$base"
    mkdir "$base/owners"
    result=0
    for owner in 0 1; do
      run_owner_or_reader "$base/owners/cross-runtime-owner-$owner" -ci-owner "$owner" || result=1
    done
    output="$base/complete"
    ;;
  complete)
    base=_out/cross-runtime-partitions/cross-runtime-owner-15/arm64-fallback-cross
    output=_out/cross-runtime-aggregate/arm64-fallback-cross-completion
    result=0
    ;;
  *)
    echo 'expected execute or complete' >&2
    exit 2
    ;;
esac

run_owner_or_reader "$output" -verify-ci-partitions "$base/owners" || result=1
node .github/scripts/audit-arm64-fallback.cjs \
  "$base/owners/cross-runtime-owner-0/root-0000.stdout" \
  > "$output-required-tests.json" || result=1
exit "$result"
