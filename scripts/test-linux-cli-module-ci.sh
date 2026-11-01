#!/usr/bin/env bash
set -euo pipefail

module=${1:?plan9asm or plan9asmll required}
flavor=${2:?test or coverage required}
phase=${3:?execute or complete required}
case "$module" in
  plan9asm|plan9asmll) ;;
  *) echo 'unknown Linux CLI module' >&2; exit 1 ;;
esac
case "$flavor" in
  test) flags=() ;;
  coverage) flags=("-coverprofile=coverage-$module.out") ;;
  *) echo 'unknown Linux CLI suite' >&2; exit 1 ;;
esac
stem="linux-cli-$module-$flavor"
case "$phase" in
  execute)
    if [[ $# != 5 || ! $4 =~ ^[012]$ ]]; then
      echo 'execute requires one owner and its root part (or -1)' >&2
      exit 1
    fi
    if [[ $4 == 0 ]]; then
      if ! [[ $5 =~ ^[0-3]$ ]]; then
        echo 'root owner requires part 0..3' >&2
        exit 1
      fi
      output="_out/$stem-root-$5"
    else
      if [[ $5 != -1 ]]; then
        echo 'profile/rest require part -1' >&2
        exit 1
      fi
      output="_out/$stem-owner-$4"
    fi
    args=("-module-owner=$4" "-module-root-partition=$5" "-out=$output")
    ;;
  complete)
    if [[ $# != 3 ]]; then
      echo 'complete does not execute an owner' >&2
      exit 1
    fi
    args=("-verify-module=_out/linux-cli-$module-$flavor-owners"
      "-out=_out/$stem-verified")
    ;;
  *) echo 'unknown Linux CLI suite phase' >&2; exit 1 ;;
esac
if [[ -n ${GOFLAGS:-} ]]; then
  echo 'Linux CLI module suite requires explicit empty GOFLAGS' >&2
  exit 1
fi
export GOFLAGS= GOENV=off GOWORK=off GOTOOLCHAIN=local GOMAXPROCS=2
mkdir -p _out
go run ./cmd/plan9asmtest -module "-dir=cmd/$module" "${args[@]}" \
  -shards=8 -workers=2 -timeout=30m -module-root-partitions=4 -- "${flags[@]}"
if [[ $phase == complete && $flavor == coverage ]]; then
  test -s "cmd/$module/coverage-$module.out"
fi
