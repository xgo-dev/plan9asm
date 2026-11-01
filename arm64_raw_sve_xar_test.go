package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestARM64RawSVEXARCompleteFormats(t *testing.T) {
	var source strings.Builder
	var lines []string
	for size, width := range "bhsd" {
		for shift := 1; shift <= 8<<size; shift++ {
			lines = append(lines, fmt.Sprintf("xar z31.%c, z31.%c, z30.%c, #%d", width, width, width, shift))
		}
	}
	source.WriteString("TEXT rawxar(SB),$0-0\n")
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
				Sigs: map[string]FuncSig{"rawxar": {Name: "rawxar", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "rawxar.ll", "rawxar.o", ir)
		})
	}
}

func TestARM64RawSVEXAROperandFields(t *testing.T) {
	var lines []string
	var wants []Instr
	for size, width := range "bhsd" {
		limits := []int{32, 32, 8 << size}
		for field, limit := range limits {
			for value := 0; value < limit; value++ {
				fields := [3]int{31, 30, (8 << size) - 1}
				fields[field] = value
				dst, src, shift := fields[0], fields[1], fields[2]+1
				lines = append(lines, fmt.Sprintf("xar z%d.%c, z%d.%c, z%d.%c, #%d", dst, width, dst, width, src, width, shift))
				destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", dst, "BHSD"[size]))}
				wants = append(wants, Instr{Op: "ZXAR", Args: []Operand{
					{Kind: OpImm, Imm: int64(shift)},
					{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", src, "BHSD"[size]))},
					destination, destination,
				}})
			}
		}
	}
	for i, word := range assembleARM64LLVMWords(t, lines, "+sve2") {
		got, ok := decodeARM64RawSVEXAR(word)
		if !ok || got.Op != wants[i].Op || fmt.Sprint(got.Args) != fmt.Sprint(wants[i].Args) {
			t.Fatalf("%s: decoded %#08x as %+v, %v; want %+v", lines[i], word, got, ok, wants[i])
		}
	}
	for shift := uint32(0); shift < 8; shift++ {
		word := uint32(0x04203400) | shift<<16
		if got, ok := decodeARM64RawSVEXAR(word); ok {
			t.Errorf("reserved tsize=0000 word %#08x decoded as %+v", word, got)
		}
	}
	for _, word := range []uint32{0x04283000, 0x04283800, 0x04283020} {
		if got, ok := decodeARM64RawSVEXAR(word); ok {
			t.Errorf("neighboring word %#08x decoded as %+v", word, got)
		}
	}
}
