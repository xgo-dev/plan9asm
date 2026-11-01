package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type arm64RawPredicatePermuteForm struct {
	assembly string
	op       Op
	args     []Reg
}

func arm64RawPredicatePermuteForms(destination, first, second int) []arm64RawPredicatePermuteForm {
	var forms []arm64RawPredicatePermuteForm
	for _, width := range []string{"b", "h", "s", "d"} {
		pd := fmt.Sprintf("p%d.%s", destination, width)
		pn := fmt.Sprintf("p%d.%s", first, width)
		pm := fmt.Sprintf("p%d.%s", second, width)
		forms = append(forms, arm64RawPredicatePermuteForm{
			"rev " + pd + ", " + pn, "PREV", []Reg{Reg(strings.ToUpper(pn)), Reg(strings.ToUpper(pd))},
		})
		for _, op := range []string{"trn1", "trn2", "uzp1", "uzp2", "zip1", "zip2"} {
			forms = append(forms, arm64RawPredicatePermuteForm{
				op + " " + pd + ", " + pn + ", " + pm, Op("P" + strings.ToUpper(op)),
				[]Reg{Reg(strings.ToUpper(pm)), Reg(strings.ToUpper(pn)), Reg(strings.ToUpper(pd))},
			})
		}
	}
	for _, op := range []string{"punpkhi", "punpklo"} {
		forms = append(forms, arm64RawPredicatePermuteForm{
			fmt.Sprintf("%s p%d.h, p%d.b", op, destination, first), Op("P" + strings.ToUpper(op)),
			[]Reg{Reg(fmt.Sprintf("P%d.B", first)), Reg(fmt.Sprintf("P%d.H", destination))},
		})
	}
	return forms
}

func TestARM64RawSVEPredicatePermuteCompleteFormats(t *testing.T) {
	var lines []string
	for _, form := range arm64RawPredicatePermuteForms(15, 14, 13) {
		lines = append(lines, form.assembly)
	}
	var source strings.Builder
	source.WriteString("TEXT rawpermute(SB),$0-0\n")
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
				Sigs: map[string]FuncSig{"rawpermute": {Name: "rawpermute", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "rawpermute.ll", "rawpermute.o", ir)
		})
	}
}

func TestARM64RawSVEPredicatePermuteOperandFields(t *testing.T) {
	var forms []arm64RawPredicatePermuteForm
	var lines []string
	for field := 0; field < 3; field++ {
		for register := 0; register < 16; register++ {
			registers := [3]int{15, 14, 13}
			registers[field] = register
			forms = append(forms, arm64RawPredicatePermuteForms(registers[0], registers[1], registers[2])...)
		}
	}
	for _, form := range forms {
		lines = append(lines, form.assembly)
	}
	for i, word := range assembleARM64LLVMWords(t, lines, "+sve") {
		want := forms[i]
		got, ok := decodeARM64RawSVEPredicatePermute(word)
		if !ok || got.Op != want.op || len(got.Args) != len(want.args) {
			t.Fatalf("%s: decoded %#08x as %+v, %v", want.assembly, word, got, ok)
		}
		for j, register := range want.args {
			if got.Args[j].Reg != register {
				t.Errorf("%s: operand %d = %s, want %s", want.assembly, j, got.Args[j].Reg, register)
			}
		}
	}
	for _, word := range []uint32{0x05304010, 0x05304200, 0x05704000, 0x05344010, 0x05205c00, 0x05204010, 0x05204200} {
		if got, ok := decodeARM64RawSVEPredicatePermute(word); ok {
			t.Errorf("reserved/neighboring word %#08x decoded as %+v", word, got)
		}
	}
}
