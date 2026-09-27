#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
reports_dir=${1:-"$repo_root/_out/discovered-library-corpus"}
shard_count=${2:-32}
output_dir="$repo_root/testdata/discovery/assembly-ledger"

if (( $# > 2 )) || ! [[ "$shard_count" =~ ^[1-9][0-9]*$ ]]; then
  echo "usage: $0 [reports-directory] [shard-count]" >&2
  exit 2
fi

mkdir -p "$repo_root/_out"

# Reports must match this clean checkout before any persisted evidence changes.
go run -C "$repo_root" ./cmd/plan9asmcorpus \
  -manifest "$repo_root/testdata/corpus/reported-libraries.json" \
  -repo-root "$repo_root" \
  -discovery-ledger "$repo_root/testdata/discovery/ledger" \
  -discovery-shard-count "$shard_count" \
  -discovery-progress "$reports_dir" \
  -write-assembly-ledger "$output_dir" \
  > "$repo_root/_out/assembly-ledger-progress.json"

# This compares semantic source content, excluding only the evidence directory.
go run -C "$repo_root" ./cmd/plan9asmcorpus \
  -manifest "$repo_root/testdata/corpus/reported-libraries.json" \
  -repo-root "$repo_root" \
  -discovery-ledger "$repo_root/testdata/discovery/ledger" \
  -assembly-ledger-status "$output_dir" \
  > "$repo_root/_out/assembly-ledger-validated.json"

echo "Validated assembly ledger written to $output_dir; verified=true requires every shard and zero failures."
