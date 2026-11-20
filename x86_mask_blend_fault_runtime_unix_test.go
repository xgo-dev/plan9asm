//go:build darwin || linux

package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// E4 reads only active elements, even when the numerical result is dead. This
// portable guard-page oracle does not qualify original AVX512 execution.
func TestX86MaskBlendDeadNativeReadFaults(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("portable guard pages require the native 64-bit host counterpart")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("mask blend faults require LLVM22 llc and clang")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var source, declarations, prototypes, metadata strings.Builder
	count := 0
	for _, member := range []struct {
		op        string
		lane      int
		broadcast bool
	}{
		{"VBLENDMPS", 4, true}, {"VBLENDMPD", 8, true},
		{"VPBLENDMB", 1, false}, {"VPBLENDMW", 2, false},
		{"VPBLENDMD", 4, true}, {"VPBLENDMQ", 8, true},
	} {
		for _, bank := range []string{"X", "Y", "Z"} {
			for _, broadcast := range []bool{false, true} {
				if broadcast && !member.broadcast {
					continue
				}
				op := member.op
				width := amd64VectorByteWidth(Reg(bank + "0"))
				extent := width
				if broadcast {
					op += ".BCST"
					extent = member.lane
				}
				name := fmt.Sprint("BlendFault", count)
				fmt.Fprintf(&declarations, "func %s(p *[64]byte,mask uint64)\n", name)
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-16\nMOVQ p+0(FP),AX\n"+
					"KMOVQ mask+8(FP),K1\n%s.Z (AX),%s1,K1,%s2\nRET\n", name, op, bank, bank)
				fmt.Fprintf(&prototypes, "extern void %s(const uint8_t *,uint64_t);\n", name)
				fmt.Fprintf(&metadata, "{%s,%d,%d,%d},\n", name, extent, member.lane, width/member.lane)
				count++
			}
		}
	}
	if count != 30 {
		t.Fatal("incomplete independent E4 memory shape inventory", count)
	}
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source.String())
	ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", triple, "text")
	if err != nil {
		t.Fatal("complete dead E4 source rejected", err)
	}
	mainC := x86E4DeadReadFaultOracle(prototypes.String(), metadata.String())
	x86ConflictFunnelPortableRuntime(t, llc, clang, "mask_blend_dead_faults", triple, ir, mainC)
}
