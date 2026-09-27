#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
reports_dir=${1:-"$repo_root/_out/discovered-library-corpus"}
shard_count=${2:-32}
if (( $# > 2 )) || ! [[ "$shard_count" =~ ^[1-9][0-9]*$ ]]; then
  echo "usage: $0 [reports-directory] [shard-count]" >&2
  exit 2
fi

# A status query does not run candidates or mark missing evidence successful.
# Keep this checkout and its scan ledger frozen, just as for corpus verification.
mkdir -p "$reports_dir"
pending_dir=$(mktemp -d "$reports_dir/.status-XXXXXX")
trap 'rm -rf "$pending_dir"' EXIT

go run -C "$repo_root" ./cmd/plan9asmdiscover \
  -status \
  -out-dir "$repo_root/testdata/discovery/ledger" \
  > "$pending_dir/scan-status.json"
go run -C "$repo_root" ./cmd/plan9asmcorpus \
  -manifest "$repo_root/testdata/corpus/reported-libraries.json" \
  -repo-root "$repo_root" \
  -discovery-ledger "$repo_root/testdata/discovery/ledger" \
  -discovery-shard-count "$shard_count" \
  -discovery-progress "$reports_dir" \
  > "$pending_dir/assembly-progress.json"

mv "$pending_dir/scan-status.json" "$reports_dir/scan-status.json"
mv "$pending_dir/assembly-progress.json" "$reports_dir/assembly-progress.json"
echo "Validated scan status and assembly progress written to $reports_dir; use verify-discovered-library-corpus.sh for the passing gate."
