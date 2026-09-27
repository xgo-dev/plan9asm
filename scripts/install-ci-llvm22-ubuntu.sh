#!/usr/bin/env bash
set -euo pipefail

# Every Linux CI lane uses the same LLVM 22 toolchain. Avoid repeatedly
# downloading it when a self-hosted runner already has all required packages.
packages=(
  llvm-22-dev clang-22 libclang-22-dev lld-22
  libunwind-22-dev libc++-22-dev
  "$@"
)
installed=true
for package in "${packages[@]}"; do
  if ! dpkg -s "$package" >/dev/null 2>&1; then
    installed=false
    break
  fi
done

if [[ "$installed" != true ]]; then
  suite=$(lsb_release -cs)
  key=/etc/apt/trusted.gpg.d/llvm-snapshot.asc
  curl -4fsSL --connect-timeout 15 --max-time 60 --retry 2 \
    https://apt.llvm.org/llvm-snapshot.gpg.key | sudo tee "$key" >/dev/null
  echo "deb https://apt.llvm.org/$suite/ llvm-toolchain-$suite-22 main" |
    sudo tee /etc/apt/sources.list.d/llvm.list >/dev/null

  apt_options=(-o Acquire::Retries=2 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30)
  update() {
    sudo timeout -k 10s 2m apt-get "${apt_options[@]}" update
  }
  install() {
    sudo timeout -k 10s 4m env DEBIAN_FRONTEND=noninteractive \
      apt-get "${apt_options[@]}" install -y "${packages[@]}"
  }

  if ! update || ! install; then
    # Some self-hosted runners provide an unreliable apt mirrorlist. A direct
    # Ubuntu mirror was reachable in the failing job; use it only as fallback.
    fallback=/etc/apt/sources.list.d/plan9asm-ci-fallback.list
    {
      echo "deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://mirrors.edge.kernel.org/ubuntu $suite main universe restricted multiverse"
      echo "deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://mirrors.edge.kernel.org/ubuntu $suite-updates main universe restricted multiverse"
      echo "deb https://apt.llvm.org/$suite/ llvm-toolchain-$suite-22 main"
    } | sudo tee "$fallback" >/dev/null
    apt_options+=(
      -o "Dir::Etc::sourcelist=$fallback"
      -o Dir::Etc::sourceparts=-
    )
    update
    install
  fi
fi

for tool in llvm-config-22 clang-22 llc-22; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "missing LLVM 22 tool after installation: $tool" >&2
    exit 1
  fi
done
if [[ "$(llvm-config-22 --version)" != 22.* ]]; then
  echo "llvm-config-22 does not select LLVM 22" >&2
  exit 1
fi
if [[ -n "${GITHUB_ENV:-}" ]]; then
  echo "PATH=/usr/lib/llvm-22/bin:$PATH" >> "$GITHUB_ENV"
fi
