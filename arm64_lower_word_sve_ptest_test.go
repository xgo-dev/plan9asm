package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestARM64RawSVEPTestCompleteForm(t *testing.T) {
	for _, registers := range []struct {
		governing uint32
		tested    uint32
	}{
		{0, 1},
		{5, 7},
		{15, 14},
	} {
		word := uint32(0x2550c000) | registers.governing<<10 | registers.tested<<5
		t.Run(fmt.Sprintf("P%d_P%d", registers.governing, registers.tested), func(t *testing.T) {
			source := fmt.Sprintf("TEXT svePTestRaw(SB),$0-0\n\tWORD $%#08x\n\tRET\n", word)
			requireARM64SVEGoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			for _, triple := range []string{
				"aarch64-apple-darwin",
				"aarch64-unknown-linux-gnu",
				"aarch64-pc-windows-msvc",
			} {
				t.Run(triple, func(t *testing.T) {
					ir, err := Translate(file, Options{
						TargetTriple: triple,
						Goarch:       "arm64",
						Sigs: map[string]FuncSig{
							"svePTestRaw": {Name: "svePTestRaw", Ret: Void},
						},
					})
					if err != nil {
						t.Fatal(err)
					}
					for _, want := range []string{
						"@llvm.aarch64.sve.ptest.any.nxv16i1",
						"@llvm.aarch64.sve.ptest.first.nxv16i1",
						"@llvm.aarch64.sve.ptest.last.nxv16i1",
						`"target-features"="+sve"`,
					} {
						if !strings.Contains(ir, want) {
							t.Fatalf("omitted %q:\n%s", want, ir)
						}
					}
					llc := findLLVM22Tool("llc")
					if llc == "" {
						t.Fatal("LLVM 22 llc not found")
					}
					compileLLVMToObject(t, llc, triple, "arm64-sve-ptest-raw.ll", "arm64-sve-ptest-raw.o", ir)
				})
			}
		})
	}
}

func TestDecodeARM64RawSVEPTestPredicateFieldsAndBoundaries(t *testing.T) {
	for governing := uint32(0); governing < 16; governing++ {
		for tested := uint32(0); tested < 16; tested++ {
			word := uint32(0x2550c000) | governing<<10 | tested<<5
			decoded, ok := decodeARM64RawSVEPTest(word)
			if !ok || decoded.Op != "PPTEST" || len(decoded.Args) != 2 {
				t.Fatalf("failed to decode %#08x: %+v", word, decoded)
			}
			if decoded.Args[0].Reg != Reg(fmt.Sprintf("P%d.B", tested)) || decoded.Args[1].Reg != Reg(fmt.Sprintf("P%d", governing)) {
				t.Fatalf("wrong predicate fields for %#08x: %+v", word, decoded.Args)
			}
		}
	}
	for _, word := range []uint32{
		0x2550c001, // Reserved low bit.
		0x2550c200, // Reserved bit between predicate fields.
		0x25508000, // Adjacent instruction class.
	} {
		if decoded, ok := decodeARM64RawSVEPTest(word); ok {
			t.Fatalf("accepted unrelated encoding %#08x as %+v", word, decoded)
		}
	}
}
