#!/usr/bin/env bash

find_llvm22_tool() {
  local tool=$1
  local llvm_config_version llvm_bin_dir candidate version
  local -a candidates=()

  if [[ -n "${LLVM_CONFIG:-}" ]]; then
    if ! llvm_config_version=$("$LLVM_CONFIG" --version 2>/dev/null); then
      echo "LLVM_CONFIG failed: $LLVM_CONFIG" >&2
      return 1
    fi
    if [[ ! "$llvm_config_version" =~ ^22([.]|$) ]]; then
      echo "LLVM_CONFIG must select LLVM 22, got $llvm_config_version" >&2
      return 1
    fi
    if ! llvm_bin_dir=$("$LLVM_CONFIG" --bindir 2>/dev/null); then
      echo "LLVM_CONFIG --bindir failed: $LLVM_CONFIG" >&2
      return 1
    fi
    candidates+=("$llvm_bin_dir/$tool")
  else
    candidate=$(command -v "${tool}-22" || true)
    [[ -z "$candidate" ]] || candidates+=("$candidate")
    candidate=$(command -v "$tool" || true)
    [[ -z "$candidate" ]] || candidates+=("$candidate")
  fi

  for candidate in "${candidates[@]}"; do
    [[ -x "$candidate" ]] || continue
    version=$("$candidate" --version 2>/dev/null || true)
    if grep -Eq '(^|[[:space:]])LLVM version 22([.]|$)' <<<"$version"; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  echo "LLVM 22 $tool not found; install ${tool}-22 or set LLVM_CONFIG to LLVM 22" >&2
  return 1
}

find_llvm22_llc() {
  find_llvm22_tool llc
}
