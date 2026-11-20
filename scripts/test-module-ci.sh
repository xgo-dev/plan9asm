#!/usr/bin/env bash
set -euo pipefail

# One actual inventory: sixteen root parts (32 for race), profile/rest once.
# Every root owner retains two shards. Nested CLIs and Windows run separately.
flavor=${1:?test, race or coverage required}
phase=${2:?execute or complete required}
flags=()
root_partitions=16
shards=32
case "$flavor" in
  test) timeout=45m ;;
  race) timeout=60m; flags=(-race); root_partitions=32; shards=64 ;;
  coverage) timeout=45m; flags=(-coverprofile=coverage-root.out) ;;
  *) echo "unknown module suite role" >&2; exit 1 ;;
esac
if [[ -n "${GOFLAGS:-}" ]]; then
  echo "module suite requires explicit empty GOFLAGS" >&2
  exit 1
fi
export GOFLAGS= GOENV=off GOWORK=off GOTOOLCHAIN=local GOMAXPROCS=2
mkdir -p _out
args=(-module -out="_out/module-$flavor" -shards=$shards -workers=2
  "-timeout=$timeout" "-module-root-partitions=$root_partitions")
case "$phase" in
  execute)
    if [[ $# != 4 || ! $3 =~ ^[012]$ ]]; then
      echo "execute requires one owner and its root part (or -1)" >&2
      exit 1
    fi
    if [[ $3 == 0 ]]; then
      if ! [[ $4 =~ ^([0-9]|[1-9][0-9])$ ]] || (( $4 >= root_partitions )); then
        echo "root owner requires part 0..$((root_partitions - 1))" >&2
        exit 1
      fi
    elif [[ $4 != -1 ]]; then
      echo "profile/rest require part -1" >&2
      exit 1
    fi
    args+=("-module-owner=$3" "-module-root-partition=$4")
    ;;
  complete)
    if [[ $# != 2 ]]; then
      echo "complete does not execute an owner" >&2
      exit 1
    fi
    args=(-module -out="_out/module-$flavor-verified" -shards=$shards -workers=2
      "-timeout=$timeout" "-module-root-partitions=$root_partitions"
      "-verify-module=_out/module-$flavor-owners")
    ;;
  *) echo "unknown module suite phase" >&2; exit 1 ;;
esac
go run ./cmd/plan9asmtest "${args[@]}" -- "${flags[@]}"
