#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo_root"

# Resolved relative to the checked-out repository.
# shellcheck disable=SC1091
source "$repo_root/scripts/llvm22.sh"
if ! llc_cmd=$(find_llvm22_llc); then
  exit 1
fi
if [[ "${RUNNER_OS:-}" == "Windows" ]] && command -v python >/dev/null 2>&1; then
  python_cmd=python
elif command -v python3 >/dev/null 2>&1; then
  python_cmd=python3
elif command -v python >/dev/null 2>&1; then
  python_cmd=python
else
  echo "Python 3 not found in PATH" >&2
  exit 1
fi

tmp_root=$(mktemp -d)
trap 'rm -rf "$tmp_root"' EXIT

# Build host tools once before applying any target-specific architecture
# setting. Besides avoiding repeated builds, this prevents GOAMD64=v4 (for
# example) from producing a scanner binary that cannot run on the CI host.
# Invoking the package tool through `go run -C cmd/plan9asm` would also make old
# Go lanes auto-select the nested module's newer toolchain, and the corpus would
# silently come from the wrong GOROOT.
plan9asmscan_cmd="$tmp_root/plan9asmscan"
if [[ "${RUNNER_OS:-}" == "Windows" ]]; then
  plan9asmscan_cmd+=".exe"
fi
go build -o "$plan9asmscan_cmd" ./cmd/plan9asmscan

if [[ -n "${PLAN9ASM_CMD:-}" ]]; then
  plan9asm_cmd=$PLAN9ASM_CMD
  if [[ ! -x "$plan9asm_cmd" ]]; then
    echo "PLAN9ASM_CMD is not executable: $plan9asm_cmd" >&2
    exit 1
  fi
else
  plan9asm_cmd="$tmp_root/plan9asm"
  if [[ "${RUNNER_OS:-}" == "Windows" ]]; then
    plan9asm_cmd+=".exe"
  fi
  go build -C cmd/plan9asm -o "$plan9asm_cmd" .
fi

# Linux is the authoritative architecture-level matrix. Keep every value that
# the supported Go toolchain understands: an unversioned request such as
# linux/arm expands to all of its rows below. Other operating systems retain a
# single integration target because their Plan 9 instruction surface is the
# same and the Linux matrix already covers the architecture settings.
all_targets=(
  "linux 386 i386-unknown-linux-gnu GO386 sse2"
  "linux 386 i386-unknown-linux-gnu GO386 softfloat"
  "linux amd64 x86_64-unknown-linux-gnu GOAMD64 v1"
  "linux amd64 x86_64-unknown-linux-gnu GOAMD64 v2"
  "linux amd64 x86_64-unknown-linux-gnu GOAMD64 v3"
  "linux amd64 x86_64-unknown-linux-gnu GOAMD64 v4"
  "linux arm armv5te-unknown-linux-gnueabi GOARM 5"
  "linux arm armv5te-unknown-linux-gnueabihf GOARM 5,hardfloat"
  "linux arm armv6-unknown-linux-gnueabihf GOARM 6"
  "linux arm armv6-unknown-linux-gnueabi GOARM 6,softfloat"
  "linux arm armv7-unknown-linux-gnueabihf GOARM 7"
  "linux arm armv7-unknown-linux-gnueabi GOARM 7,softfloat"
)
for arm64_version in v8.{0..9} v9.{0..5} v8.0,lse v8.0,crypto v8.0,lse,crypto; do
  all_targets+=("linux arm64 aarch64-unknown-linux-gnu GOARM64 $arm64_version")
done
all_targets+=(
  "darwin amd64 x86_64-apple-macosx - -"
  "darwin arm64 arm64-apple-macosx - -"
  "js wasm wasm32-unknown-unknown - -"
  "js wasm wasm32-unknown-unknown GOWASM satconv"
  "js wasm wasm32-unknown-unknown GOWASM signext"
  "js wasm wasm32-unknown-unknown GOWASM satconv,signext"
  "wasip1 wasm wasm32-unknown-wasi - -"
  "wasip1 wasm wasm32-unknown-wasi GOWASM satconv"
  "wasip1 wasm wasm32-unknown-wasi GOWASM signext"
  "wasip1 wasm wasm32-unknown-wasi GOWASM satconv,signext"
)

# Include Windows by default. Linux CI cross-compiles the COFF corpora, while
# the latest Windows host lane remains an auxiliary native-host integration.
if [[ "${PLAN9ASM_CORPUS_INCLUDE_WINDOWS:-1}" != "0" ]]; then
  all_targets+=(
    "windows 386 i686-pc-windows-msvc - -"
    "windows amd64 x86_64-pc-windows-msvc - -"
    "windows arm64 aarch64-pc-windows-msvc - -"
  )
fi

targets=()
if [[ -z "${PLAN9ASM_CORPUS_TARGETS:-}" ]]; then
  targets=("${all_targets[@]}")
else
  IFS=',' read -r -a requested_targets <<< "$PLAN9ASM_CORPUS_TARGETS"
  for requested in "${requested_targets[@]}"; do
    requested=${requested//[[:space:]]/}
    matched=0
    for target in "${all_targets[@]}"; do
      read -r goos goarch _ setting_name setting_value <<< "$target"
      target_name="$goos/$goarch"
      if [[ "$setting_name" != "-" ]]; then
        setting_label=${setting_value//,/+}
        if [[ "$goarch" == "arm" ]]; then
          setting_label="v${setting_label//,/-}"
          setting_label=${setting_label//+/-}
        fi
        target_name+="/$setting_label"
      fi
      if [[ "$requested" == "$goos/$goarch" || "$requested" == "$target_name" ]]; then
        targets+=("$target")
        matched=1
        if [[ "$requested" == "$target_name" && "$requested" != "$goos/$goarch" ]]; then
          break
        fi
      fi
    done
    if [[ "$matched" -eq 0 ]]; then
      echo "unsupported PLAN9ASM_CORPUS_TARGETS entry: $requested" >&2
      exit 1
    fi
  done
fi

for target in "${targets[@]}"; do
  read -r goos goarch triple setting_name setting_value <<< "$target"
  target_name="$goos-$goarch"
  target_label="$goos/$goarch"
  target_env=("GO386=" "GOAMD64=" "GOARM=" "GOARM64=" "GOWASM=")
  if [[ "$setting_name" != "-" ]]; then
    setting_label=${setting_value//,/+}
    if [[ "$goarch" == "arm" ]]; then
      setting_label="v${setting_label//+/-}"
    fi

    # GOARM float suffixes appeared in Go 1.22 and GOARM64 in Go 1.23.
    # Skip values an older supported toolchain cannot represent; v8.0 is the
    # implicit ARM64 baseline there and must still be checked.
    actual=$(env "GOARCH=$goarch" "$setting_name=$setting_value" go env "$setting_name" 2>/dev/null || true)
    if [[ "$actual" == "$setting_value" ]]; then
      target_env+=("$setting_name=$setting_value")
    elif [[ "$setting_name" != "GOARM64" || "$setting_value" != "v8.0" || -n "$actual" ]]; then
      echo "==> skip $target_label/$setting_label (unsupported by $(go version))"
      continue
    fi
    target_name+="-$setting_label"
    target_label+="/$setting_label"
  fi

  echo "==> scan $target_label"
  json="$tmp_root/$target_name.json"
  env "${target_env[@]}" "$plan9asmscan_cmd" -goos="$goos" -goarch="$goarch" -repo-root . -format json -out "$json"
  "$python_cmd" - "$json" "$target_label" <<'PY'
import json
import sys

path, target = sys.argv[1], sys.argv[2]
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)

unsupported = data.get("unsupported", [])
unsupported_forms = data.get("unsupported_by_form", [])
parse_errs = data.get("parse_errs") or []
print(f"scan {target}: packages={data['std_pkgs_with_sfile']} files={data['asm_files']} unsupported={len(unsupported)} unsupported_forms={len(unsupported_forms)} parse_errs={len(parse_errs)}")
if unsupported:
    top = ", ".join(f"{item['op']}({item['count']})" for item in unsupported[:12])
    raise SystemExit(f"{target}: unsupported ops remain: {top}")
if unsupported_forms:
    top = ", ".join(
        f"{item['form']} ({item['errors'][0] if item.get('errors') else item['examples'][0] if item.get('examples') else 'no diagnostic'})"
        for item in unsupported_forms[:12]
    )
    raise SystemExit(f"{target}: unsupported operand forms remain: {top}")
if parse_errs:
    top = ", ".join(f"{item['File']}: {item['Err']}" for item in parse_errs[:8])
    raise SystemExit(f"{target}: parse errors remain: {top}")
PY

  echo "==> transpile+compile $target_label"
  out_dir="$tmp_root/$target_name-ll"
  meta="$tmp_root/$target_name-meta.json"
  transpile_log="$tmp_root/$target_name-transpile.log"
  if ! env "${target_env[@]}" GOTOOLCHAIN=local "$plan9asm_cmd" transpile \
    -goos="$goos" -goarch="$goarch" -dir "$out_dir" -meta "$meta" std \
    >"$transpile_log" 2>&1; then
    cat "$transpile_log" >&2
    exit 1
  fi
  rm "$transpile_log"

  ll_count=$(find "$out_dir" -name '*.ll' | wc -l | tr -d ' ')
  if [ "$ll_count" -eq 0 ]; then
    echo "$goos/$goarch: no .ll files generated" >&2
    exit 1
  fi
  echo "compiled corpus $target_label: ll_files=$ll_count"

  while IFS= read -r ll; do
    "$llc_cmd" -mtriple="$triple" -filetype=obj "$ll" -o "$tmp_root/verify-object.o"
  done < <(find "$out_dir" -name '*.ll' | sort)

  # The corpus only checks object compilation. Keep one reusable object and
  # release each target's IR and scan output before starting the next target.
  rm "$tmp_root/verify-object.o" "$json" "$meta"
  rm -r "$out_dir"
done
