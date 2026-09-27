#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo_root"

if [[ -n "${GOROOT:-}" ]]; then
  go_root=$GOROOT
else
  go_root=$(go env GOROOT)
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

required_arches=(386 amd64 arm arm64 wasm)
for goarch in "${required_arches[@]}"; do
  echo "==> official Go assembler coverage $goarch"
  goos=linux
  if [[ "$goarch" == "wasm" ]]; then
    goos=js
  fi
  go run ./cmd/plan9asmscan \
    -corpus=go-asm \
    -goroot="$go_root" \
    -goos="$goos" \
    -goarch="$goarch" \
    -repo-root=. \
    -format=json \
    -out="$tmp_root/$goarch.json"
done

"$python_cmd" - testdata/coverage/go-asm-baseline.json testdata/coverage/arm64-go-assembler-families.txt "$tmp_root" <<'PY'
import json
import pathlib
import re
import sys

baseline_path = pathlib.Path(sys.argv[1])
family_path = pathlib.Path(sys.argv[2])
report_dir = pathlib.Path(sys.argv[3])
baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
if baseline.get("schema_version") != 2:
    raise SystemExit("coverage baseline schema must be 2")

required_arches = {"386", "amd64", "arm", "arm64", "wasm"}
report_paths = sorted(report_dir.glob("*.json"))
reported_arches = {path.stem for path in report_paths}
if reported_arches != required_arches:
    raise SystemExit(
        "official Go assembler coverage must run every supported architecture: "
        f"expected {sorted(required_arches)}, got {sorted(reported_arches)}"
    )

expected_versions = {f"go1.{minor}" for minor in range(20, 28)}
actual_versions = set(baseline.get("versions", {}))
if actual_versions != expected_versions:
    raise SystemExit(
        "coverage baseline versions differ: "
        f"expected {sorted(expected_versions)}, got {sorted(actual_versions)}"
    )
latest_version = max(expected_versions, key=lambda item: int(item.split(".")[1]))

fields = (
    "official_opcodes",
    "unique_ops",
    "unique_forms",
    "supported_forms",
    "context_forms",
    "unsupported_forms",
    "parse_err_count",
    "runtime_verified_forms",
    "compile_only_forms",
    "encoder_opcodes",
    "encoder_forms",
    "encoder_opcodes_observed_in_corpus",
    "coverage_fingerprint",
    "encoder_fingerprint",
)

for report_path in report_paths:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    match = re.match(r"^(go\d+\.\d+)", report["go_version"])
    if not match:
        raise SystemExit(f"cannot normalize Go version {report['go_version']!r}")
    version = match.group(1)
    arch = report["goarch"]
    if arch != report_path.stem:
        raise SystemExit(
            f"coverage report {report_path.name} identifies itself as {arch!r}"
        )
    classified_forms = (
        report["supported_forms"]
        + report["context_forms"]
        + report["unsupported_forms"]
    )
    if classified_forms != report["unique_forms"]:
        raise SystemExit(
            f"{version}/{arch}: form classification skipped entries: "
            f"supported+context+unsupported={classified_forms}, "
            f"unique={report['unique_forms']}"
        )
    if report["parse_err_count"]:
        raise SystemExit(
            f"{version}/{arch}: official assembler corpus has "
            f"{report['parse_err_count']} unclassified parse errors"
        )
    expected = baseline.get("versions", {}).get(version, {}).get(arch)
    if expected is None:
        raise SystemExit(
            f"missing coverage baseline for {version}/{arch}; "
            "inspect the full JSON report and update the baseline intentionally"
        )
    changed = [
        field for field in fields
        if report.get(field) != expected.get(field)
    ]
    print(
        f"{version}/{arch}: official={report['official_opcodes']} "
        f"ops={report['unique_ops']} forms={report['unique_forms']} "
        f"supported={report['supported_forms']} "
        f"context={report['context_forms']} "
        f"unsupported={report['unsupported_forms']} "
        f"runtime_verified={report['runtime_verified_forms']} "
        f"compile_only={report.get('compile_only_forms', 0)} "
        f"encoder_ops={report['encoder_opcodes']} "
        f"encoder_forms={report['encoder_forms']} "
        f"parse_errors={report['parse_err_count']}"
    )
    if changed:
        details = ", ".join(
            f"{field}: expected {expected.get(field)!r}, got {report.get(field)!r}"
            for field in changed
        )
        raise SystemExit(
            f"{version}/{arch}: instruction coverage changed ({details}); "
            "review the form-level report before updating the baseline"
        )

    if arch == "arm64":
        required = {
            line.strip()
            for line in family_path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
        catalog = {item["opcode"]: item for item in report["opcode_catalog"]}
        available = required.intersection(catalog)
        unavailable = sorted(required.difference(available))
        missing_encoder = sorted(op for op in available if not catalog[op].get("encoder_forms"))
        missing_corpus = sorted(op for op in available if not catalog[op].get("observed_in_corpus"))
        unsupported = sorted(op for op in available if catalog[op].get("unsupported_forms"))
        missing_latest = unavailable if version == latest_version else []
        if missing_latest or missing_encoder or missing_corpus or unsupported:
            raise SystemExit(
                f"{version}/arm64: incomplete required Go assembler families: "
                f"missing_from_latest={missing_latest}, missing_encoder={missing_encoder}, "
                f"missing_corpus={missing_corpus}, unsupported={unsupported}"
            )
        print(
            f"{version}/arm64: all {len(available)} toolchain-available required opcodes "
            f"are encoder-defined, observed, and lowerable"
            + (f"; {len(unavailable)} future opcodes are absent from this Go release" if unavailable else "")
        )
PY
