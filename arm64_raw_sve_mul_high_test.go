package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func arm64RawSVEMulHighAssembly(op string, size, dst, first, second, predicate int) string {
	width := "bhsd"[size]
	if predicate >= 0 {
		return fmt.Sprintf("%s z%d.%c, p%d/m, z%d.%c, z%d.%c", op, dst, width, predicate, dst, width, second, width)
	}
	return fmt.Sprintf("%s z%d.%c, z%d.%c, z%d.%c", op, dst, width, first, width, second, width)
}

func TestARM64RawSVEMultiplyHighCompleteFormats(t *testing.T) {
	var lines []string
	for _, op := range []string{"smulh", "umulh"} {
		for size := 0; size < 4; size++ {
			for _, predicate := range []int{-1, 7} {
				lines = append(lines, arm64RawSVEMulHighAssembly(op, size, 31, 30, 29, predicate))
			}
		}
	}
	var source strings.Builder
	source.WriteString("TEXT rawmulhigh(SB),$0-0\n")
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
				Sigs: map[string]FuncSig{"rawmulhigh": {Name: "rawmulhigh", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "rawmulhigh.ll", "rawmulhigh.o", ir)
		})
	}
}

func TestARM64RawSVEMultiplyHighOperandFields(t *testing.T) {
	var lines []string
	var wants []Instr
	for _, op := range []string{"smulh", "umulh"} {
		for size := 0; size < 4; size++ {
			for _, predicated := range []bool{false, true} {
				limits := []int{32, 32, 32, 1}
				if predicated {
					limits[1], limits[3] = 1, 8
				}
				for field, limit := range limits {
					for value := 0; value < limit; value++ {
						fields := [4]int{31, 30, 29, 0}
						fields[field] = value
						dst, first, second, pred := fields[0], fields[1], fields[2], fields[3]
						if predicated {
							first = dst
						} else {
							pred = -1
						}
						lines = append(lines, arm64RawSVEMulHighAssembly(op, size, dst, first, second, pred))
						reg := func(number int) Operand {
							return Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", number, "BHSD"[size]))}
						}
						args := []Operand{reg(second), reg(first)}
						if predicated {
							args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d.M", pred))})
						}
						args = append(args, reg(dst))
						wants = append(wants, Instr{Op: Op("Z" + strings.ToUpper(op)), Args: args})
					}
				}
			}
		}
	}
	for i, word := range assembleARM64LLVMWords(t, lines, "+sve2") {
		got, ok := decodeARM64RawSVEMultiplyHigh(word)
		if !ok || got.Op != wants[i].Op || fmt.Sprint(got.Args) != fmt.Sprint(wants[i].Args) {
			t.Fatalf("%s: decoded %#08x as %+v, %v; want %+v", lines[i], word, got, ok, wants[i])
		}
	}
	for _, word := range []uint32{0, 0x04100000, 0x04206400, 0x04207000} {
		if got, ok := decodeARM64RawSVEMultiplyHigh(word); ok {
			t.Errorf("neighboring word %#08x decoded as %+v", word, got)
		}
	}
}
