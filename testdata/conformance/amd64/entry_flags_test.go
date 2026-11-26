//go:build amd64

package amd64conformance

import "testing"

func callWithEntryFlags(sel int64, flags uint64) uint64

// TestAMD64EntryFlagsPerBitOracle verifies:
//  1. Zero prologue clobber between POPFQ and target's first instruction across
//     all 8 flag patterns (all-0, 6 individual status-bit flips, and all-1).
//  2. Per-bit flipping detects CF^OF dependency that all-0/all-1 alone misses.
//  3. Symmetric PEXTRQ $0/$1 independence (clean lane always 41) vs dependence
//     (dirty lane tracks entry CF) on real amd64 hardware.
func TestAMD64EntryFlagsPerBitOracle(t *testing.T) {
	patterns := []struct {
		name  string
		flags uint64
	}{
		{"all0", 0x000},
		{"cf", 0x001},
		{"pf", 0x004},
		{"af", 0x010},
		{"zf", 0x040},
		{"sf", 0x080},
		{"of", 0x800},
		{"all1", 0x8d5},
	}

	// 1. Prove ZERO prologue clobber between POPFQ and target's first instruction.
	for _, p := range patterns {
		if got := callWithEntryFlags(0, p.flags); got != p.flags {
			t.Fatalf("raw entry flags(%s=%#x) = %#x (prologue clobbered RFLAGS!)", p.name, p.flags, got)
		}
	}

	// 2. Prove CF^OF is 0 on both all0 and all1, yet 1 on single-bit CF or OF flip.
	all0Xor := callWithEntryFlags(1, 0x000)
	all1Xor := callWithEntryFlags(1, 0x8d5)
	cfXor := callWithEntryFlags(1, 0x001)
	ofXor := callWithEntryFlags(1, 0x800)
	if all0Xor != 0 || all1Xor != 0 || cfXor != 1 || ofXor != 1 {
		t.Fatalf("CF^OF results: all0=%d all1=%d cf=%d of=%d, want 0, 0, 1, 1", all0Xor, all1Xor, cfXor, ofXor)
	}

	// 3. Prove symmetric PEXTRQ lane independence vs CF dependence across all 8 bit patterns.
	for _, p := range patterns {
		wantCF := p.flags & 1
		if got := callWithEntryFlags(2, p.flags); got != 41 {
			t.Fatalf("PEXTRQ $0 (low=41, high=CF) flags=%s: got %d, want 41", p.name, got)
		}
		if got := callWithEntryFlags(3, p.flags); got != wantCF {
			t.Fatalf("PEXTRQ $1 (low=41, high=CF) flags=%s: got %d, want %d", p.name, got, wantCF)
		}
		if got := callWithEntryFlags(4, p.flags); got != 41 {
			t.Fatalf("PEXTRQ $1 (low=CF, high=41) flags=%s: got %d, want 41", p.name, got)
		}
		if got := callWithEntryFlags(5, p.flags); got != wantCF {
			t.Fatalf("PEXTRQ $0 (low=CF, high=41) flags=%s: got %d, want %d", p.name, got, wantCF)
		}
	}
}
