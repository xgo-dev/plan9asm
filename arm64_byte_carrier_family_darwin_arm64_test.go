//go:build go1.27

package plan9asm

import "testing"

func TestARM64ByteCarrierNativeResultFamily(t *testing.T) {
	llc, clang := findLLVM22Tool("llc"), findLLVM22Tool("clang")
	if llc == "" || clang == "" {
		t.Fatal("LLVM22 llc and clang are required")
	}
	arm64ByteCarrierRuntimeFamily(t, "darwin", "aarch64-apple-darwin", llc, []string{clang}, nil)
}
