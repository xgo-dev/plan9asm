package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86QwordLookupZeroMasksRetainDistinctNativeReadShapes(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word, suffix := goWordSize(target.arch), "Q"
		if word == 4 {
			suffix = "L"
		}
		for _, bank := range []string{"X", "Y", "Z"} {
			width := amd64VectorByteWidth(Reg(bank + "0"))
			for _, row := range []struct {
				instruction string
				bytes       int
				suppressed  bool
			}{
				{instruction: "VPMULTISHIFTQB (AX)," + bank + "1," + bank + "2", bytes: width},
				{instruction: "VPMULTISHIFTQB.BCST (AX)," + bank + "1," + bank + "2", bytes: 8},
			} {
				// Named mode32 cannot express four operands. Its complete
				// unmasked full/broadcast reads still execute on both targets.
				checkQwordLookupReadShape(t, target.arch, target.triple, word, suffix, row.instruction, row.bytes, row.suppressed)
			}
			if target.arch == "amd64" {
				for _, row := range []struct {
					instruction string
					bytes       int
					suppressed  bool
				}{
					{instruction: "VPMULTISHIFTQB.Z (AX)," + bank + "1,K1," + bank + "2", bytes: width},
					{instruction: "VPMULTISHIFTQB.BCST.Z (AX)," + bank + "1,K1," + bank + "2", bytes: 8},
					{instruction: "VPSHUFBITQMB (AX)," + bank + "1,K1,K3", suppressed: true},
				} {
					checkQwordLookupReadShape(t, target.arch, target.triple, word, suffix, row.instruction, row.bytes, row.suppressed)
				}
			}
		}
	}
}

func checkQwordLookupReadShape(t *testing.T, arch, triple string, word int, suffix, instruction string, width int, suppressed bool) {
	t.Helper()
	for _, api := range []string{"text", "module", "Go"} {
		source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\nMOV%s p+0(FP),AX\n"+
			"MOVL $0,BX\nKMOVD BX,K1\nVPXORD Z1,Z1,Z1\nVPXORD Z2,Z2,Z2\n%s\nRET\n", word, suffix, instruction)
		ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(p *[64]byte)", arch, triple, api)
		if err != nil {
			t.Fatal("complete dead-read source rejected", arch, instruction, api, err)
		}
		optimized := x86DwordProductIROptimize(t, ir)
		if suppressed {
			if !strings.Contains(ir, "load volatile i8") || strings.Contains(optimized, "load volatile") {
				t.Fatal("zero K mask failed to suppress only the bit-control byte reads", instruction, api)
			}
		} else {
			load := fmt.Sprintf("load volatile <%d x i8>", width)
			if strings.Count(ir, load) != 1 || strings.Count(optimized, load) != 1 {
				t.Fatal("dead or zero-masked multishift lost its complete native tuple", instruction, api, width)
			}
		}
	}
}
