package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// The independent Go-table inventory already checks all sixteen operations,
// every encoder row and its individual broadcast/zeroing attributes. Reuse
// those names, not production-map keys, for the missing native continuation.
func x86NativeVectorArithmeticRows(arch string, start, end int) []struct{ op, bank, mode string } {
	var names, broadcasts []string
	for _, member := range x86ResultVectorArithmeticNames[start:end] {
		names = append(names, member.name)
		if member.bits >= 32 {
			broadcasts = append(broadcasts, member.name+".BCST")
		}
	}
	rows := x86FixedBinaryValueRows(arch, names)
	return append(rows, x86FixedBinaryValueRows(arch, broadcasts)...)
}

func TestX86VectorArithmeticPairedNativeReadCompleteFamily(t *testing.T) {
	for batch, name := range []string{"add", "subtract"} {
		t.Run(name, func(t *testing.T) {
			x86FixedBinaryCompleteFamilyObjects(t, func(arch string) []struct{ op, bank, mode string } {
				return x86NativeVectorArithmeticRows(arch, batch*8, (batch+1)*8)
			}, 90, 30)
		})
	}
}

func TestX86VectorArithmeticPairedNativeReadCannotBorrowSourceFacts(t *testing.T) {
	x86FixedBinaryNativeInputBoundaries(t, func(arch string) []struct{ op, bank, mode string } {
		return x86NativeVectorArithmeticRows(arch, 0, 16)
	})

	// Keep the existing KMOV whole-source obligation even with an unused mask
	// and no result. Its initialized mask cannot supply an incoming address.
	for _, member := range x86ResultVectorArithmeticNames {
		for _, bank := range []string{"X", "Y", "Z"} {
			source := fmt.Sprintf("TEXT ·Value(SB),4,$0-8\nMOVQ p+0(FP),AX\n"+
				"MOVL $0,CX\nKMOVD CX,K1\nVPXORD Z1,Z1,Z1\n%s (AX),%s1,%s2\nRET\n", member.name, bank, bank)
			goAssemblerOracleOutput(t, "amd64", source, "", true)
			for _, api := range []string{"text", "module", "Go"} {
				if ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(p *[64]byte)",
					"amd64", "x86_64-unknown-linux-gnu", api); err != nil || ir == "" {
					t.Fatal("initialized Void native arithmetic rejected", member.name, bank, api, err)
				}
				for _, replacement := range []string{"MOVL $1,AX", "MOVQ p+0(FP),DI"} {
					bad := strings.Replace(source, "MOVQ p+0(FP),AX", replacement, 1)
					if ir, err := x86ScalarFPBitViewAPI(t, bad, "func Value(p *[64]byte)",
						"amd64", "x86_64-unknown-linux-gnu", api); !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
						t.Fatal("Void native arithmetic invented address context", member.name, bank, api, err)
					}
				}
			}
		}
	}
}
