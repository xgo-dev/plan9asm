//go:build darwin || linux

package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestX86IntegerMinMaxDeadE4ReadFaults(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("portable guard pages require the native 64-bit host counterpart")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("integer min/max faults require LLVM22 llc and clang")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	for batch := 0; batch < 2; batch++ {
		t.Run(fmt.Sprint("batch-", batch), func(t *testing.T) {
			var source, declarations, prototypes, metadata strings.Builder
			count, owned := 0, 0
			for _, op := range x86MinMaxTestOps {
				lane := map[byte]int{'B': 1, 'W': 2, 'D': 4, 'Q': 8}[op[6]]
				for _, bank := range []string{"X", "Y", "Z"} {
					for _, broadcast := range []bool{false, true} {
						if broadcast && lane < 4 {
							continue
						}
						index := count
						count++
						if index/36 != batch {
							continue
						}
						owned++
						name := fmt.Sprint("MinMaxFault", index)
						width := amd64VectorByteWidth(Reg(bank + "0"))
						extent, suffix := width, ".Z"
						if broadcast {
							extent, suffix = lane, ".BCST.Z"
						}
						fmt.Fprintf(&declarations, "func %s(p *[64]byte,mask uint64)\n", name)
						fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-16\nMOVQ p+0(FP),AX\n"+
							"KMOVQ mask+8(FP),K1\nVPXORD Z1,Z1,Z1\n%s%s (AX),%s1,K1,%s2\nRET\n",
							name, op, suffix, bank, bank)
						fmt.Fprintf(&prototypes, "extern void %s(const uint8_t *,uint64_t);\n", name)
						fmt.Fprintf(&metadata, "{%s,%d,%d,%d},\n", name, extent, lane, width/lane)
					}
				}
			}
			if count != 72 || owned != 36 {
				t.Fatal("incomplete or overlapping independent E4 family union", count, owned)
			}
			x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source.String())
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", triple, "text")
			if err != nil {
				t.Fatal("complete original dead E4 source rejected", err)
			}
			x86ConflictFunnelPortableRuntime(t, llc, clang, fmt.Sprint("integer_minmax_faults_", batch),
				triple, ir, x86E4DeadReadFaultOracle(prototypes.String(), metadata.String()))
		})
	}
}
