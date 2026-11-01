#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
family_file="$repo_root/testdata/coverage/arm64-go-assembler-families.txt"
baseline="$repo_root/testdata/coverage/arm64-xarch-plan9-baseline.json"
cd "$repo_root"

if command -v python3 >/dev/null 2>&1; then
  python_cmd=python3
elif command -v python >/dev/null 2>&1; then
  python_cmd=python
else
  echo "Python 3 not found in PATH" >&2
  exit 1
fi

tmp_root=$(mktemp -d)
trap 'rm -rf "$tmp_root"' EXIT
module_json="$tmp_root/xarch.json"
# This official Go decoder corpus is independent of external-library manifests.
# An explicit module@version can be downloaded outside a main module without
# modifying the translator's go.mod/go.sum or recreating a compatibility ledger.
GOWORK=off go -C "$tmp_root" mod download -json golang.org/x/arch@v0.31.0 >"$module_json"
xarch_root=$("$python_cmd" - "$module_json" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["Dir"])
PY
)
source_cases="$xarch_root/arm64/arm64asm/testdata/plan9cases.txt"

mkdir -p "$repo_root/_out"
oracle_parent=$(mktemp -d "$repo_root/_out/arm64-plan9-XXXXXX")
full_report="$oracle_parent/full.json"
go run "$repo_root/cmd/plan9asmscan" \
  -corpus=arm64-plan9 \
  -input="$source_cases" \
  -goos=linux \
  -goarch=arm64 \
  -repo-root="$repo_root" \
  -format=json \
  -out="$full_report"

"$python_cmd" - "$baseline" "$full_report" <<'PY'
import json
import sys

expected = json.load(open(sys.argv[1], encoding="utf-8"))
actual = json.load(open(sys.argv[2], encoding="utf-8"))
fields = ("asm_files", "unique_ops", "unique_forms", "supported_forms", "context_forms", "unsupported_forms", "parse_err_count", "coverage_fingerprint")
changed = [field for field in fields if actual.get(field) != expected.get(field)]
if changed:
    details = ", ".join(f"{field}: expected {expected.get(field)!r}, got {actual.get(field)!r}" for field in changed)
    raise SystemExit(f"x/arch ARM64 Plan 9 corpus changed ({details}); inspect the form report before updating the baseline")
print(f"x/arch ARM64 Plan 9 decoder corpus: ops={actual['unique_ops']} forms={actual['unique_forms']} supported={actual['supported_forms']} context={actual['context_forms']} unsupported={actual['unsupported_forms']} parse_errors={actual['parse_err_count']}")
PY

go_path=$(command -v go)
goroot=$("$go_path" env GOROOT)
# The explicitly selected physical driver/SDK remain one observed role.
readarray_inputs=$("$python_cmd" - "$go_path" "$goroot" "$source_cases" "$family_file" <<'PY'
import pathlib
import sys
for value in sys.argv[1:]:
    print(pathlib.Path(value).resolve(strict=True))
PY
)
go_path=$(printf '%s\n' "$readarray_inputs" | sed -n '1p')
goroot=$(printf '%s\n' "$readarray_inputs" | sed -n '2p')
source_cases=$(printf '%s\n' "$readarray_inputs" | sed -n '3p')
family_file=$(printf '%s\n' "$readarray_inputs" | sed -n '4p')
"$go_path" run "$repo_root/cmd/plan9asmgooracle" \
  -cases="$source_cases" -families="$family_file" \
  -go="$go_path" -goroot="$goroot" -out="$oracle_parent/go-oracle"
accepted_cases="$oracle_parent/go-oracle/accepted.txt"

accepted_report="$oracle_parent/accepted.json"
go run "$repo_root/cmd/plan9asmscan" \
  -corpus=arm64-plan9 \
  -input="$accepted_cases" \
  -goos=linux \
  -goarch=arm64 \
  -repo-root="$repo_root" \
  -format=json \
  -out="$accepted_report"

"$python_cmd" - "$accepted_report" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
if report["parse_err_count"] or report["unsupported_forms"]:
    examples = [item["form"] for item in report.get("unsupported_by_form", [])[:12]]
    raise SystemExit(f"native-Go-accepted x/arch forms are not lowerable: parse_errors={report['parse_err_count']} unsupported={report['unsupported_forms']} examples={examples}")
print(f"native-Go-accepted x/arch family corpus: ops={report['unique_ops']} forms={report['unique_forms']} supported={report['supported_forms']} context={report['context_forms']}")
PY
