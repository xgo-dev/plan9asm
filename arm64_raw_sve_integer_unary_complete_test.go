package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type arm64RawSVEUnaryCase struct {
	assembly, reference string
	op                  Op
	width               string
	mode                string
}

func arm64RawSVEUnaryCompleteCases() []arm64RawSVEUnaryCase {
	var cases []arm64RawSVEUnaryCase
	for _, family := range []struct {
		op, widths string
	}{
		{"abs", "bhsd"}, {"cls", "bhsd"}, {"clz", "bhsd"}, {"cnot", "bhsd"},
		{"cnt", "bhsd"}, {"neg", "bhsd"}, {"not", "bhsd"}, {"rbit", "bhsd"},
		{"sqabs", "bhsd"}, {"sqneg", "bhsd"}, {"revb", "hsd"}, {"revh", "sd"},
		{"revw", "d"}, {"sxtb", "hsd"}, {"sxth", "sd"}, {"sxtw", "d"},
		{"uxtb", "hsd"}, {"uxth", "sd"}, {"uxtw", "d"},
		{"urecpe", "s"}, {"ursqrte", "s"}, {"revd", "q"},
	} {
		for _, width := range family.widths {
			for _, mode := range []string{"m", "z"} {
				assembly := fmt.Sprintf("%s z0.%c, p7/%s, z30.%c", family.op, width, mode, width)
				// New zeroing encodings have a baseline merging oracle with a
				// cleared destination. Source and destination are distinct here.
				reference := strings.ReplaceAll(assembly, "/z", "/m")
				if mode == "z" {
					reference = "mov z0.b, #0\\n\\t" + reference
				}
				cases = append(cases, arm64RawSVEUnaryCase{assembly, reference,
					Op("Z" + strings.ToUpper(family.op)), strings.ToUpper(string(width)), strings.ToUpper(mode)})
			}
		}
	}
	for _, width := range "bhsd" {
		assembly := fmt.Sprintf("rev z0.%c, z30.%c", width, width)
		cases = append(cases, arm64RawSVEUnaryCase{assembly, assembly, "ZREV", strings.ToUpper(string(width)), ""})
	}
	return cases
}

func TestARM64RawSVEIntegerUnaryCompleteFormats(t *testing.T) {
	var source strings.Builder
	var lines []string
	for _, form := range arm64RawSVEUnaryCompleteCases() {
		lines = append(lines, form.assembly)
	}
	source.WriteString("TEXT rawunary(SB),$0-0\n")
	for _, word := range assembleARM64LLVMWords(t, lines, "+sve2p2") {
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

func TestARM64RawSVEIntegerUnaryCompleteOperandFields(t *testing.T) {
	forms := arm64RawSVEUnaryCompleteCases()
	var lines []string
	for _, form := range forms {
		lines = append(lines, form.assembly)
	}
	for i, word := range assembleARM64LLVMWords(t, lines, "+sve2p2") {
		form := forms[i]
		decode := decodeARM64RawSVEIntegerUnary
		if form.op == "ZREVD" {
			decode = decodeARM64RawSVERevd
		}
		for field, limit := range []int{32, 32, 8} {
			if form.mode == "" && field == 2 {
				continue
			}
			for register := 0; register < limit; register++ {
				shifts := [3]uint{0, 5, 10}
				mask := uint32(limit-1) << shifts[field]
				probe := word&^mask | uint32(register)<<shifts[field]
				regs := [3]int{0, 30, 7}
				regs[field] = register
				got, ok := decode(probe)
				want := []Reg{Reg(fmt.Sprintf("Z%d.%s", regs[1], form.width))}
				if form.mode != "" {
					want = append(want, Reg(fmt.Sprintf("P%d.%s", regs[2], form.mode)))
				}
				want = append(want, Reg(fmt.Sprintf("Z%d.%s", regs[0], form.width)))
				if !ok || got.Op != form.op || len(got.Args) != len(want) {
					t.Fatalf("%s: decoded %#08x as %+v, %v", form.assembly, probe, got, ok)
				}
				for j, operand := range want {
					if got.Args[j].Reg != operand {
						t.Errorf("%s: operand %d = %s, want %s", form.assembly, j, got.Args[j].Reg, operand)
					}
				}
			}
		}
	}
	for _, word := range []uint32{0x05248000, 0x05658000, 0x05a68000, 0x4400a000, 0x44c1a000, 0x05383c00} {
		if got, ok := decodeARM64RawSVEIntegerUnary(word); ok {
			t.Errorf("reserved/neighboring word %#08x decoded as %+v", word, got)
		}
	}
	for _, word := range []uint32{0x056e8000, 0x052ec000, 0x052e6000} {
		if got, ok := decodeARM64RawSVERevd(word); ok {
			t.Errorf("reserved/neighboring REVD word %#08x decoded as %+v", word, got)
		}
	}
}
