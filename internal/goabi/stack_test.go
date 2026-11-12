package goabi

import (
	"math"
	"testing"
)

func TestABI0StackSize(t *testing.T) {
	for _, arch := range []string{"386", "amd64", "arm", "arm64", "wasm"} {
		word := int64(8)
		if arch == "386" || arch == "arm" {
			word = 4
		}
		for _, size := range []int64{0, 1, 4, 8, 12, 17, 28, math.MaxInt64 - 7} {
			want := (size + word - 1) &^ (word - 1)
			got, ok := ABI0StackSize(arch, size)
			if !ok || got != want {
				t.Fatalf("%s logical=%d: aligned=%d, valid=%t, want %d", arch, size, got, ok, want)
			}
			if !MatchesABI0TextSize(arch, size, size) || !MatchesABI0TextSize(arch, want, size) {
				t.Fatalf("%s rejected logical/aligned metadata for %d", arch, size)
			}
			if MatchesABI0TextSize(arch, want+1, size) || MatchesABI0TextSize(arch, want+word, size) {
				t.Fatalf("%s accepted arbitrary excess metadata for %d", arch, size)
			}
		}
		for _, bad := range []int64{-1, math.MinInt64, math.MaxInt64} {
			if _, ok := ABI0StackSize(arch, bad); ok || MatchesABI0TextSize(arch, bad, bad) {
				t.Fatalf("%s accepted invalid/overflowing data size %d", arch, bad)
			}
		}
	}
	if _, ok := ABI0StackSize("unknown", 12); ok || MatchesABI0TextSize("unknown", 16, 12) {
		t.Fatal("invented a stack alignment for an unknown architecture")
	}
}
