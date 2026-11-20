package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func arm64RawSVETernaryAssembly(op string, destination, second, third int) string {
	return fmt.Sprintf("%s z%d.d, z%d.d, z%d.d, z%d.d", op, destination, destination, second, third)
}

func TestARM64RawSVETernaryBitwiseCompleteFormats(t *testing.T) {
	var source strings.Builder
	var lines []string
	for _, op := range []string{"bcax", "bsl", "bsl1n", "bsl2n", "eor3", "nbsl"} {
		lines = append(lines, arm64RawSVETernaryAssembly(op, 31, 30, 29))
	}
	source.WriteString("TEXT rawternary(SB),$0-0\n")
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
				Sigs: map[string]FuncSig{"rawternary": {Name: "rawternary", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "rawternary.ll", "rawternary.o", ir)
		})
	}
}

func TestARM64RawSVETernaryBitwiseOperandFields(t *testing.T) {
	var lines []string
	var wants []Instr
	for _, op := range []string{"bcax", "bsl", "bsl1n", "bsl2n", "eor3", "nbsl"} {
		for field := 0; field < 3; field++ {
			for value := 0; value < 32; value++ {
				fields := [3]int{31, 31, 31}
				fields[field] = value
				dst, second, third := fields[0], fields[1], fields[2]
				lines = append(lines, arm64RawSVETernaryAssembly(op, dst, second, third))
				vector := func(index int) Operand {
					return Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.D", index))}
				}
				wants = append(wants, Instr{Op: Op("Z" + strings.ToUpper(op)), Args: []Operand{
					vector(third), vector(second), vector(dst), vector(dst),
				}})
			}
		}
	}
	for i, word := range assembleARM64LLVMWords(t, lines, "+sve2") {
		got, ok := decodeARM64RawSVETernaryBitwise(word)
		if !ok || got.Op != wants[i].Op || fmt.Sprint(got.Args) != fmt.Sprint(wants[i].Args) {
			t.Fatalf("%s: decoded %#08x as %+v, %v; want %+v", lines[i], word, got, ok, wants[i])
		}
	}
	for _, word := range []uint32{0x04a03800, 0x04e03800, 0x04203000, 0x04203400, 0x04603400} {
		if got, ok := decodeARM64RawSVETernaryBitwise(word); ok {
			t.Errorf("neighboring word %#08x decoded as %+v", word, got)
		}
	}
}
