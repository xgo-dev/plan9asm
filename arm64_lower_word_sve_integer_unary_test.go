package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64RawSVEIntegerUnaryGo127PredicatedFamily(t *testing.T) {
	forms := []struct {
		op       Op
		merge    uint32
		zero     uint32
		minWidth int
	}{
		{"ZABS", 0x0416a000, 0x0406a000, 8},
		{"ZCLS", 0x0418a000, 0x0408a000, 8},
		{"ZCLZ", 0x0419a000, 0x0409a000, 8},
		{"ZCNOT", 0x041ba000, 0x040ba000, 8},
		{"ZCNT", 0x041aa000, 0x040aa000, 8},
		{"ZNEG", 0x0417a000, 0x0407a000, 8},
		{"ZNOT", 0x041ea000, 0x040ea000, 8},
		{"ZSXTB", 0x0410a000, 0x0400a000, 16},
		{"ZSXTH", 0x0412a000, 0x0402a000, 32},
		{"ZSXTW", 0x0414a000, 0x0404a000, 64},
		{"ZUXTB", 0x0411a000, 0x0401a000, 16},
		{"ZUXTH", 0x0413a000, 0x0403a000, 32},
		{"ZUXTW", 0x0415a000, 0x0405a000, 64},
	}
	widthNames := [...]string{"B", "H", "S", "D"}
	var source strings.Builder
	source.WriteString("TEXT rawSVEIntegerUnary(SB),$0-0\n")
	for _, form := range forms {
		for size, width := range widthNames {
			if 8<<size < form.minWidth {
				continue
			}
			for _, mode := range []struct {
				name string
				base uint32
			}{
				{"M", form.merge},
				{"Z", form.zero},
			} {
				word := mode.base | uint32(size)<<22 | 6<<5 | 3<<10 | 9
				fmt.Fprintf(&source, "\t%s Z6.%s, P3.%s, Z9.%s\n", form.op, width, mode.name, width)
				fmt.Fprintf(&source, "\tWORD $%#08x\n", word)
			}
		}
	}
	source.WriteString("\tRET\n")
	requireARM64SVEGoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"rawSVEIntegerUnary": {Name: "rawSVEIntegerUnary", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ll, "@llvm.aarch64.sve.cnt.nxv2i64") {
				t.Fatalf("raw CNT was not lowered with typed SVE semantics:\n%s", ll)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-sve-integer-unary.ll", "arm64-raw-sve-integer-unary.o", ll)
		})
	}
}

func TestDecodeARM64RawSVEIntegerUnaryRejectsReservedWidths(t *testing.T) {
	for _, word := range []uint32{
		0x0410a000,         // SXTB requires H/S/D elements.
		0x0452a000,         // SXTH requires S/D elements.
		0x0494a000,         // SXTW requires D elements.
		0x04daa0c6 ^ 1<<13, // Adjacent unmodelled instruction space.
	} {
		if _, ok := decodeARM64RawSVEIntegerUnary(word); ok {
			t.Fatalf("accepted reserved or adjacent unary encoding %#08x", word)
		}
	}
}
