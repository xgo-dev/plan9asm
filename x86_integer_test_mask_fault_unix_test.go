//go:build darwin || linux

package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestX86IntegerTestMaskLiveAndDeadE4ReadFaults(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("test-to-mask faults require LLVM22 llc/clang")
	}
	for _, discard := range []bool{false, true} {
		var source, declarations, prototypes, metadata strings.Builder
		count := 0
		for _, row := range x86IntegerTestMaskValueCases() {
			// The independent full family has 36 full/scalar memory shapes.
			// K0 and masking are fixed here; both K0/K2 value roles stay in
			// the numerical owner rather than duplicating the fault matrix.
			if row.first == 0 || row.masked == 0 || row.destination != "K0" {
				continue
			}
			op, extent := row.op, row.width
			if row.first == 2 {
				op, extent = op+".BCST", row.bits/8
			}
			name, result := fmt.Sprint("TestMaskFault", count), "KMOVQ K0,AX\n"
			if discard {
				result = "MOVQ $0,AX\n"
			}
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-24\nMOVQ p+0(FP),AX\nKMOVQ mask+8(FP),K1\n"+
				"VPXORD Z1,Z1,Z1\n%s (AX),%s1,K1,K0\n%sMOVQ AX,ret+16(FP)\nRET\n", name, op, row.bank, result)
			fmt.Fprintf(&declarations, "func %s(p *[64]byte,mask uint64) uint64\n", name)
			fmt.Fprintf(&prototypes, "extern uint64_t %s(const uint8_t*,uint64_t);\n", name)
			fmt.Fprintf(&metadata, "{%s,%d,%d,%d},\n", name, extent, row.bits/8, row.width*8/row.bits)
			count++
		}
		if count != 36 {
			t.Fatal("lost a byte/word/dword/qword, width or broadcast fault shape", count)
		}
		x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source.String())
		driver := x86E4DeadReadFaultOracle(prototypes.String(), metadata.String())
		const voidKernel = "typedef void (*Kernel)(const uint8_t *,uint64_t);"
		if strings.Count(driver, voidKernel) != 1 {
			t.Fatal("shared fault oracle lost its single typed kernel declaration")
		}
		// Keep the existing protection/process observer unchanged. The live
		// function returns its K value; the dead function returns a constant.
		driver = strings.Replace(driver, voidKernel, "typedef uint64_t (*Kernel)(const uint8_t *,uint64_t);", 1)
		triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(fmt.Sprintf("discard=%t/%s", discard, api), func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", triple, api)
				if err != nil {
					t.Fatal("initialized memory source rejected before fault observation", err)
				}
				x86ConflictFunnelPortableRuntime(t, llc, clang, "integer-test-mask-e4", triple, ir, driver)
			})
		}
	}
}
