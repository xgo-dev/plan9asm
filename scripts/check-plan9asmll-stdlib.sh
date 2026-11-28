#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
go build -C "$root/cmd/plan9asmll" -o "$tmp/plan9asmll" .
args=(-patterns std -targets linux/386,linux/amd64,linux/arm,linux/arm64,js/wasm -out "$tmp/objects" -repo-root "$root" -strict-load)
CGO_ENABLED=0 "$tmp/plan9asmll" "${args[@]}" -list-only >"$tmp/tasks.json"
CGO_ENABLED=0 "$tmp/plan9asmll" "${args[@]}" -compile -keep-obj
python3 - "$tmp/tasks.json" <<'PY'
import json
import sys
from pathlib import Path

with open(sys.argv[1], encoding="utf-8") as manifest:
    targets = json.load(manifest)
for target in targets:
    tasks = target["tasks"]
    outputs = {Path(task["out_ll"]).with_suffix(".o") for task in tasks}
    if not tasks or len(outputs) != len(tasks):
        sys.exit(f'{target["target"]}: empty or duplicate assembly outputs')
    for obj in outputs:
        if not obj.is_file() or obj.stat().st_size == 0:
            sys.exit(f"missing or empty object: {obj}")
    print(f'{target["target"]}: {len(outputs)} nonempty objects')
PY
