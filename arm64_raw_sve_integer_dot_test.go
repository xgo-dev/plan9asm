package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type arm64RawSVEIntegerDotCase struct {
	op, source, destination string
	indexed                 bool
	maximumVector, lanes    int
}

func arm64RawSVEIntegerDotCases() []arm64RawSVEIntegerDotCase {
	var forms []arm64RawSVEIntegerDotCase
	for _, op := range []string{"sdot", "udot"} {
		for _, widths := range []struct {
			source, destination  string
			maximumVector, lanes int
		}{{"b", "h", 7, 8}, {"h", "s", 7, 4}, {"b", "s", 7, 4}, {"h", "d", 15, 2}} {
			for _, indexed := range []bool{false, true} {
				forms = append(forms, arm64RawSVEIntegerDotCase{op, widths.source, widths.destination, indexed, widths.maximumVector, widths.lanes})
			}
		}
	}
	return append(forms,
		arm64RawSVEIntegerDotCase{"usdot", "b", "s", false, 7, 4},
		arm64RawSVEIntegerDotCase{"usdot", "b", "s", true, 7, 4},
		arm64RawSVEIntegerDotCase{"sudot", "b", "s", true, 7, 4})
}

func (form arm64RawSVEIntegerDotCase) assembly(destination, second, first, lane int) string {
	index := ""
	if form.indexed {
		index = fmt.Sprintf("[%d]", lane)
	}
	return fmt.Sprintf("%s z%d.%s, z%d.%s, z%d.%s%s", form.op, destination, form.destination, second, form.source, first, form.source, index)
}

func TestARM64RawSVEIntegerDotCompleteFormats(t *testing.T) {
	var source strings.Builder
	var lines []string
	for _, form := range arm64RawSVEIntegerDotCases() {
		maximumVector, lanes := 31, 1
		if form.indexed {
			maximumVector, lanes = form.maximumVector, form.lanes
		}
		for lane := 0; lane < lanes; lane++ {
			lines = append(lines, form.assembly(31, 30, maximumVector, lane))
		}
	}
	source.WriteString("TEXT rawintegerdot(SB),$0-0\n")
	for _, word := range assembleARM64LLVMWords(t, lines, "+sve2p3,+i8mm") {
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
				Sigs: map[string]FuncSig{"rawintegerdot": {Name: "rawintegerdot", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "rawintegerdot.ll", "rawintegerdot.o", ir)
		})
	}
}

func TestARM64RawSVEIntegerDotOperandFields(t *testing.T) {
	var lines []string
	var wants []Instr
	for _, form := range arm64RawSVEIntegerDotCases() {
		limits := []int{32, 32, 32, 1}
		if form.indexed {
			limits[2], limits[3] = form.maximumVector+1, form.lanes
		}
		for field, limit := range limits {
			for value := 0; value < limit; value++ {
				fields := [4]int{31, 30, limits[2] - 1, limits[3] - 1}
				fields[field] = value
				lines = append(lines, form.assembly(fields[0], fields[1], fields[2], fields[3]))
				index := ""
				if form.indexed {
					index = fmt.Sprintf("[%d]", fields[3])
				}
				wants = append(wants, Instr{Op: Op("Z" + strings.ToUpper(form.op)), Args: []Operand{
					{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%s%s", fields[2], strings.ToUpper(form.source), index))},
					{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%s", fields[1], strings.ToUpper(form.source)))},
					{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%s", fields[0], strings.ToUpper(form.destination)))},
				}})
			}
		}
	}
	for i, word := range assembleARM64LLVMWords(t, lines, "+sve2p3,+i8mm") {
		got, ok := decodeARM64RawSVEIntegerDot(word)
		if !ok || got.Op != wants[i].Op || fmt.Sprint(got.Args) != fmt.Sprint(wants[i].Args) {
			t.Fatalf("%s: decoded %#08x as %+v, %v; want %+v", lines[i], word, got, ok, wants[i])
		}
	}
	for _, word := range []uint32{0x44000000, 0x44000400, 0x44800800, 0x44807400, 0x44a02000} {
		if got, ok := decodeARM64RawSVEIntegerDot(word); ok {
			t.Errorf("neighboring word %#08x decoded as %+v", word, got)
		}
	}
}
