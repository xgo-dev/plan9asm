package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func arm64RawSVEFloatCompareNativeForms() []string {
	var result []string
	for _, width := range []string{"h", "s", "d"} {
		for _, op := range []string{"facge", "facgt", "fcmeq", "fcmge", "fcmgt", "fcmne", "fcmuo"} {
			result = append(result, fmt.Sprintf("%s p15.%s, p7/z, z30.%s, z31.%s", op, width, width, width))
		}
		for _, op := range []string{"fcmeq", "fcmge", "fcmgt", "fcmle", "fcmlt", "fcmne"} {
			result = append(result, fmt.Sprintf("%s p1.%s, p0/z, z2.%s, #0.0", op, width, width))
		}
	}
	return result
}

func TestARM64RawSVEFloatingCompareCompleteFormats(t *testing.T) {
	lines := arm64RawSVEFloatCompareNativeForms()
	var source strings.Builder
	source.WriteString("TEXT rawfloatcompare(SB),$0-0\n")
	for _, word := range assembleARM64LLVMWords(t, lines, "+sve") {
		fmt.Fprintf(&source, "WORD $%#08x\n", word)
	}
	source.WriteString("RET\n")
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple,
				Sigs: map[string]FuncSig{"rawfloatcompare": {Name: "rawfloatcompare", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, comparison := range []string{"oge", "ogt", "ole", "olt", "oeq", "une", "uno"} {
				if !strings.Contains(ir, "fcmp "+comparison) {
					t.Fatalf("missing %s comparison", comparison)
				}
			}
			compileLLVMToObject(t, llc, triple, "floatcompare.ll", "floatcompare.o", ir)
		})
	}
}

func TestARM64RawSVEFloatingCompareOperandFields(t *testing.T) {
	lines := arm64RawSVEFloatCompareNativeForms()
	for i, word := range assembleARM64LLVMWords(t, lines, "+sve") {
		got, ok := decodeARM64RawSVEFloatCompare(word)
		if !ok {
			t.Fatalf("%s: rejected %#08x", lines[i], word)
		}
		width := "HSD"[i/13]
		wantOp := Op("Z" + strings.ToUpper(strings.Fields(lines[i])[0]))
		first, governing, destination := "Z30", "P7.Z", "P15"
		if i%13 >= 7 {
			first, governing, destination = "Z2", "P0.Z", "P1"
			if got.Args[0].Kind != OpImm || !got.Args[0].ImmIsFloat || got.Args[0].Imm != 0 {
				t.Errorf("%s: expected floating zero, got %+v", lines[i], got.Args[0])
			}
		} else if got.Args[0].Reg != Reg(fmt.Sprintf("Z31.%c", width)) {
			t.Errorf("%s: wrong second source: %+v", lines[i], got.Args[0])
		}
		if got.Op != wantOp || got.Args[1].Reg != Reg(fmt.Sprintf("%s.%c", first, width)) ||
			got.Args[2].Reg != Reg(governing) || got.Args[3].Reg != Reg(fmt.Sprintf("%s.%c", destination, width)) {
			t.Errorf("%s: wrong decoded operands: %+v", lines[i], got)
		}
	}
	for _, word := range []uint32{0x6500c000, 0x65a0c000, 0x6591a000, 0x65922010} {
		if got, ok := decodeARM64RawSVEFloatCompare(word); ok {
			t.Errorf("reserved/neighboring word %#08x decoded as %+v", word, got)
		}
	}
}
