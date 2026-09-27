package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func arm64RawSVESpliceAssembly(constructive bool, width rune, destination, source, predicate int) string {
	if constructive {
		return fmt.Sprintf("splice z%d.%c, p%d, { z%d.%c, z%d.%c }", destination, width, predicate, source, width, (source+1)%32, width)
	}
	return fmt.Sprintf("splice z%d.%c, p%d, z%d.%c, z%d.%c", destination, width, predicate, destination, width, source, width)
}

func TestARM64RawSVESpliceCompleteFormats(t *testing.T) {
	var source strings.Builder
	var lines []string
	for _, constructive := range []bool{false, true} {
		for _, width := range "bhsd" {
			for _, first := range []int{0, 30, 31} {
				for _, destination := range []int{first, (first + 1) % 32, 15} {
					lines = append(lines, arm64RawSVESpliceAssembly(constructive, width, destination, first, 7))
				}
			}
		}
	}
	source.WriteString("TEXT rawsplice(SB),$0-0\n")
	for _, word := range assembleARM64LLVMWords(t, lines, "+sve2") {
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
				Sigs: map[string]FuncSig{"rawsplice": {Name: "rawsplice", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "rawsplice.ll", "rawsplice.o", ir)
		})
	}
}

func TestARM64RawSVESpliceOperandFields(t *testing.T) {
	var lines []string
	var wants []Instr
	for _, constructive := range []bool{false, true} {
		for size, width := range "bhsd" {
			for field, limit := range []int{32, 32, 8} {
				for value := 0; value < limit; value++ {
					fields := [3]int{31, 31, 7}
					fields[field] = value
					dst, src, pred := fields[0], fields[1], fields[2]
					lines = append(lines, arm64RawSVESpliceAssembly(constructive, width, dst, src, pred))
					destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", dst, "BHSD"[size]))}
					source := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", src, "BHSD"[size]))}
					predicate := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d", pred))}
					args := []Operand{source, destination, predicate, destination}
					if constructive {
						list := Operand{Kind: OpRegList, RegList: []Reg{source.Reg, Reg(fmt.Sprintf("Z%d.%c", (src+1)%32, "BHSD"[size]))}}
						args = []Operand{list, predicate, destination}
					}
					wants = append(wants, Instr{Op: "ZSPLICE", Args: args})
				}
			}
		}
	}
	for i, word := range assembleARM64LLVMWords(t, lines, "+sve2") {
		got, ok := decodeARM64RawSVESplice(word)
		if !ok || got.Op != wants[i].Op || fmt.Sprint(got.Args) != fmt.Sprint(wants[i].Args) {
			t.Fatalf("%s: decoded %#08x as %+v, %v; want %+v", lines[i], word, got, ok, wants[i])
		}
	}
	for _, word := range []uint32{0x052c6000, 0x052ca000, 0x052da000, 0x052e8000} {
		if got, ok := decodeARM64RawSVESplice(word); ok {
			t.Errorf("neighboring word %#08x decoded as %+v", word, got)
		}
	}
}
