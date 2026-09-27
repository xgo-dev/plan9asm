#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
reports_dir=${1:-"$repo_root/_out/discovered-library-corpus"}
if (( $# > 1 )); then
  echo "usage: $0 [reports-directory]" >&2
  exit 2
fi

go run -C "$repo_root" ./cmd/plan9asmdiscover \
  -status \
  -out-dir "$repo_root/testdata/discovery/ledger"
go run -C "$repo_root" ./cmd/plan9asmcorpus \
  -manifest "$repo_root/testdata/corpus/reported-libraries.json" \
  -discovery-ledger "$repo_root/testdata/discovery/ledger" \
  -verify-discovery-reports "$reports_dir"
