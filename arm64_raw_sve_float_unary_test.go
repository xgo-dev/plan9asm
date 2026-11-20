package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func arm64RawSVEFloatUnaryNativeForms() []string {
	var lines []string
	for _, op := range []string{"fabs", "fneg", "frecpx", "frinta", "frinti", "frintm", "frintn", "frintp", "frintx", "frintz", "fsqrt", "frint32x", "frint32z", "frint64x", "frint64z", "frecpe", "frsqrte"} {
		widths := []string{"h", "s", "d"}
		if strings.HasPrefix(op, "frint32") || strings.HasPrefix(op, "frint64") {
			widths = widths[1:]
		}
		for _, width := range widths {
			if op == "frecpe" || op == "frsqrte" {
				lines = append(lines, fmt.Sprintf("%s z31.%s, z30.%s", op, width, width))
				continue
			}
			for _, mode := range []string{"m", "z"} {
				lines = append(lines, fmt.Sprintf("%s z31.%s, p7/%s, z30.%s", op, width, mode, width))
			}
		}
	}
	return lines
}

func TestARM64RawSVEFloatUnaryCompleteFormats(t *testing.T) {
	lines := arm64RawSVEFloatUnaryNativeForms()
	var source strings.Builder
	source.WriteString("TEXT rawunary(SB),$0-0\n")
	for _, word := range assembleARM64LLVMWords(t, lines, "+sve2p2,+fptoint") {
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
				Sigs: map[string]FuncSig{"rawunary": {Name: "rawunary", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "rawunary.ll", "rawunary.o", ir)
		})
	}
}

func TestARM64RawSVEFloatUnaryOperandFields(t *testing.T) {
	lines := arm64RawSVEFloatUnaryNativeForms()
	for i, word := range assembleARM64LLVMWords(t, lines, "+sve2p2,+fptoint") {
		got, ok := decodeARM64RawSVEFloatUnary(word)
		if !ok {
			t.Fatalf("%s: rejected %#08x", lines[i], word)
		}
		fields := strings.Fields(strings.ReplaceAll(lines[i], ",", ""))
		if got.Op != Op("Z"+strings.ToUpper(fields[0])) ||
			got.Args[0].Reg != Reg(strings.ToUpper(fields[len(fields)-1])) ||
			got.Args[len(got.Args)-1].Reg != Reg(strings.ToUpper(fields[1])) {
			t.Errorf("%s: wrong operands: %+v", lines[i], got)
		}
		if len(fields) == 4 && got.Args[1].Reg != Reg(strings.ToUpper(strings.ReplaceAll(fields[2], "/", "."))) {
			t.Errorf("%s: wrong predicate: %+v", lines[i], got.Args[1])
		}
	}
	for _, word := range []uint32{0x041da000, 0x6591a000, 0x658eb000, 0x658e3400, 0x049de000} {
		if got, ok := decodeARM64RawSVEFloatUnary(word); ok {
			t.Errorf("reserved/neighboring word %#08x decoded as %+v", word, got)
		}
	}
}
