package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64SVELogicalCompleteGo127Family(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT sveLogicalFamily(SB), $0-0\n")
	for _, op := range []string{"ZAND", "ZBIC", "ZEOR", "ZORR"} {
		source.WriteString("\t" + op + " Z1.D, Z2.D, Z3.D\n")
		for i, arrangement := range []string{"B", "H", "S", "D"} {
			fmt.Fprintf(&source, "\t%s Z4.%s, Z5.%s, P%d.M, Z5.%s\n", op, arrangement, arrangement, i, arrangement)
		}
		if op != "ZBIC" {
			source.WriteString("\t" + op + " $0x55, Z6.B, Z6.B\n")
		}
	}
	source.WriteString("\tRET\n")
	requireARM64SVEGoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		ir, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"sveLogicalFamily": {Name: "sveLogicalFamily", Ret: Void}}})
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{" and <vscale x ", " or <vscale x ", " xor <vscale x ", " select <vscale x "} {
			if !strings.Contains(ir, want) {
				t.Fatalf("%s SVE logical family IR omitted %q:\n%s", triple, want, ir)
			}
		}
		llc := findLLVM22Tool("llc")
		if llc == "" {
			t.Fatal("LLVM 22 llc not found")
		}
		compileLLVMToObject(t, llc, triple, "arm64-sve-logical-family.ll", "arm64-sve-logical-family.o", ir)
	}
}

func TestARM64RawSVELogicalDecoderDistinguishesCompleteFamily(t *testing.T) {
	for _, test := range []struct {
		op                                  Op
		unpredicated, predicated, immediate uint32
		hasImmediate                        bool
	}{
		{"ZAND", 0x04203000, 0x041a0000, 0x05800000, true},
		{"ZBIC", 0x04e03000, 0x041b0000, 0, false},
		{"ZEOR", 0x04a03000, 0x04190000, 0x05400000, true},
		{"ZORR", 0x04603000, 0x04180000, 0x05000000, true},
	} {
		for _, word := range []uint32{test.unpredicated | 1<<16 | 2<<5 | 3, test.predicated | 2<<22 | 4<<5 | 5<<10 | 6} {
			form, ok := decodeARM64RawSVEEOR(word)
			if !ok || form.op != test.op {
				t.Fatalf("decoded %s word %#08x as %+v, ok=%v", test.op, word, form, ok)
			}
		}
		if test.hasImmediate {
			form, ok := decodeARM64RawSVEEOR(test.immediate | 0x03c<<5 | 7)
			if !ok || form.op != test.op || form.mode != arm64SVEEORImmediate {
				t.Fatalf("decoded %s immediate as %+v, ok=%v", test.op, form, ok)
			}
		}
	}
}
