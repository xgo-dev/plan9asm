#!/usr/bin/env bash
set -euo pipefail

module=${1:?root, plan9asm or plan9asmll required}
phase=${2:?execute or complete required}
case "$module" in
  root) directory=.; parts=16; shards=64 ;;
  plan9asm|plan9asmll) directory="cmd/$module"; parts=4; shards=8 ;;
  *) echo 'unknown Windows module' >&2; exit 1 ;;
esac
case "$phase" in
  execute)
    if [[ $# != 4 || ! $3 =~ ^[012]$ ]]; then
      echo 'execute requires one owner and its root part (or -1)' >&2
      exit 1
    fi
    if [[ $3 == 0 ]]; then
      if ! [[ $4 =~ ^([0-9]|[1-9][0-9])$ ]] || (( $4 >= parts )); then
        echo 'invalid Windows root partition' >&2
        exit 1
      fi
    elif [[ $4 != -1 ]]; then
      echo 'non-root owners require part -1' >&2
      exit 1
    fi
    args=("-module-owner=$3" "-module-root-partition=$4"
      "-out=_out/windows-module-$module")
    ;;
  complete)
    if [[ $# != 2 ]]; then
      echo 'complete does not execute an owner' >&2
      exit 1
    fi
    args=("-verify-module=_out/windows-module-$module-owners"
      "-out=_out/windows-module-$module-verified")
    ;;
  *) echo 'unknown Windows module phase' >&2; exit 1 ;;
esac

# The LLVM setup action selects byollvm. Both the inherited and explicit Go
# build context must match; never clear it and select different helper sources.
if [[ ${GOFLAGS:-} != -tags=byollvm ]]; then
  echo 'Windows LLVM module suite requires the declared byollvm context' >&2
  exit 1
fi
export GOENV=off GOWORK=off GOTOOLCHAIN=local GOMAXPROCS=2
if [[ $(go env GOHOSTOS) != windows ]]; then
  echo 'Windows module driver requires an actual Windows Go toolchain' >&2
  exit 1
fi

# Hosted images can differ in unrelated Git/WSL/search entries. Select the
# tools before freezing PATH; never teach the aggregate to ignore that input.
# Keep Git's stable cmd/usr directories, not its changing mingw64/ucrt64 bank.
posix_directory() {
  local directory=${1%$'\r'}
  if [[ -z $directory || $directory == *$'\n'* ]]; then
    echo 'Windows module tool directory must be one nonempty path' >&2
    return 1
  fi
  cygpath -u "$directory"
}

go_bin=$(posix_directory "$(go env GOROOT)")/bin
llvm_config=${LLVM_CONFIG:-llvm-config}
llvm_version=$("$llvm_config" --version)
llvm_version=${llvm_version%$'\r'}
if [[ $llvm_version != 22.* || $llvm_version == *$'\n'* ]]; then
  echo 'Windows module suite requires the selected LLVM 22' >&2
  exit 1
fi
llvm_bin=$(posix_directory "$("$llvm_config" --bindir)")
node_bin=$(posix_directory "$(node -p "require('path').dirname(process.execPath)")")
python_bin=$(posix_directory "$(python -c 'import os, sys; print(os.path.dirname(sys.executable))')")
jq_path=$(command -v jq)
system_root=$(posix_directory "${SYSTEMROOT:-${SystemRoot:?Windows system root required}}")
native_root=$(cygpath -m "$PWD")
mkdir -p _out
export PATH="$go_bin:$llvm_bin:$node_bin:$python_bin:${jq_path%/*}:/cmd:/usr/bin:$system_root/System32:$system_root"
hash -r

go run ./cmd/plan9asmtest -module "-dir=$directory" "${args[@]}" \
  "-shards=$shards" -workers=2 -timeout=30m "-module-root-partitions=$parts" -- \
  -tags=byollvm "-coverprofile=$native_root/coverage-windows-$module.out"
if [[ $phase == complete ]]; then
  test -s "coverage-windows-$module.out"
fi
