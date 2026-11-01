package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestARM64RawSVECompactCompleteFormats(t *testing.T) {
	var source strings.Builder
	var lines []string
	for _, width := range []string{"b", "h", "s", "d"} {
		lines = append(lines, fmt.Sprintf("compact z31.%s, p7, z30.%s", width, width))
	}
	source.WriteString("TEXT rawcompact(SB),$0-0\n")
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
				Sigs: map[string]FuncSig{"rawcompact": {Name: "rawcompact", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "rawcompact.ll", "rawcompact.o", ir)
		})
	}
}

func TestARM64RawSVECompactOperandFields(t *testing.T) {
	var lines []string
	var args [][]Reg
	for _, width := range []string{"b", "h", "s", "d"} {
		for field, limit := range []int{32, 8, 32} {
			for register := 0; register < limit; register++ {
				registers := [3]int{31, 7, 30}
				registers[field] = register
				destination := fmt.Sprintf("Z%d.%s", registers[0], strings.ToUpper(width))
				predicate := fmt.Sprintf("P%d", registers[1])
				source := fmt.Sprintf("Z%d.%s", registers[2], strings.ToUpper(width))
				lines = append(lines, "compact "+destination+", "+predicate+", "+source)
				args = append(args, []Reg{Reg(source), Reg(predicate), Reg(destination)})
			}
		}
	}
	for i, word := range assembleARM64LLVMWords(t, lines, "+sve2p2") {
		got, ok := decodeARM64RawSVECompact(word)
		if !ok || got.Op != "ZCOMPACT" || len(got.Args) != 3 {
			t.Fatalf("%s: decoded %#08x as %+v, %v", lines[i], word, got, ok)
		}
		for j, register := range args[i] {
			if got.Args[j].Reg != register {
				t.Errorf("%s: operand %d = %s, want %s", lines[i], j, got.Args[j].Reg, register)
			}
		}
	}
	for _, word := range []uint32{0x05208000, 0x05218000 ^ 0x2000, 0x05218000 ^ 0x4000, 0x04218000} {
		if got, ok := decodeARM64RawSVECompact(word); ok {
			t.Errorf("reserved/neighboring word %#08x decoded as %+v", word, got)
		}
	}
}
