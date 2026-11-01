#!/usr/bin/env bash
set -euo pipefail

# QEMU 8.2 misexecutes indexed 64-bit SVE dot products, including writes past
# the vector register at VL=2048. Upstream fix: qemu/qemu@e6b2fa1b81ac.
# Use pinned static user-mode binaries, without registering binfmt handlers or
# replacing any system packages. LLVM remains independently pinned to 22.
version=10.2.3
release=deploy/v10.2.3-68
checksum=8e7d8f4c0c7809fc3fea0085199fd6b16f671e7c73d9bf6bec711e1cb535920a
if [[ "$(uname -s)/$(uname -m)" != Linux/x86_64 ]]; then
  echo "cross-runtime QEMU installation requires Linux/x86_64" >&2
  exit 1
fi

destination=${1:-"$PWD/_out/qemu-$version-linux-amd64"}
mkdir -p "$destination"
destination=$(cd "$destination" && pwd)
scratch=$(mktemp -d)
trap 'rm -r "$scratch"' EXIT
archive="$scratch/qemu.tar.gz"
curl -fLsS --connect-timeout 15 --max-time 180 --retry 2 \
  "https://github.com/tonistiigi/binfmt/releases/download/$release/qemu_v${version}_linux-amd64.tar.gz" \
  -o "$archive"
echo "$checksum  $archive" | sha256sum --check --status

tools=(qemu-aarch64 qemu-arm qemu-i386)
tar -xzf "$archive" -C "$scratch" "${tools[@]}"
for tool in "${tools[@]}"; do
  if [[ "$("$scratch/$tool" --version)" != "$tool version $version "* ]]; then
    echo "unexpected version for $tool" >&2
    exit 1
  fi
done
for tool in "${tools[@]}"; do
  install -m 0755 "$scratch/$tool" "$destination/$tool"
done
if [[ -n "${GITHUB_PATH:-}" ]]; then
  echo "$destination" >> "$GITHUB_PATH"
fi
echo "QEMU $version installed in $destination; prepend this directory to PATH."
