package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

var arm64SVEAddSubWideNativeOps = []string{
	"saddwb", "saddwt", "ssubwb", "ssubwt", "uaddwb", "uaddwt", "usubwb", "usubwt",
}

func arm64SVEAddSubWideAssembly(op string, size, dst, first, second int) string {
	return fmt.Sprintf("%s z%d.%c, z%d.%c, z%d.%c", op, dst, "bhsd"[size], first, "bhsd"[size], second, "bhsd"[size-1])
}

func TestARM64RawSVEAddSubWideCompleteFormats(t *testing.T) {
	var lines []string
	for _, op := range arm64SVEAddSubWideNativeOps {
		for size := 1; size < 4; size++ {
			lines = append(lines, arm64SVEAddSubWideAssembly(op, size, 31, 30, 29))
		}
	}
	var source strings.Builder
	source.WriteString("TEXT rawaddsubwide(SB),$0-0\n")
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
				Sigs: map[string]FuncSig{"rawaddsubwide": {Name: "rawaddsubwide", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "rawaddsubwide.ll", "rawaddsubwide.o", ir)
		})
	}
}

func TestARM64RawSVEAddSubWideOperandFields(t *testing.T) {
	var lines []string
	var wants []Instr
	for _, op := range arm64SVEAddSubWideNativeOps {
		for size := 1; size < 4; size++ {
			for field := 0; field < 3; field++ {
				for value := 0; value < 32; value++ {
					registers := [3]int{31, 30, 29}
					registers[field] = value
					dst, first, second := registers[0], registers[1], registers[2]
					lines = append(lines, arm64SVEAddSubWideAssembly(op, size, dst, first, second))
					wants = append(wants, Instr{Op: Op("Z" + strings.ToUpper(op)), Args: []Operand{
						{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", second, "BHSD"[size-1]))},
						{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", first, "BHSD"[size]))},
						{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", dst, "BHSD"[size]))},
					}})
				}
			}
		}
	}
	for i, word := range assembleARM64LLVMWords(t, lines, "+sve2") {
		got, ok := decodeARM64RawSVEAddSubWide(word)
		if !ok || got.Op != wants[i].Op || fmt.Sprint(got.Args) != fmt.Sprint(wants[i].Args) {
			t.Fatalf("%s: decoded %#08x as %+v, %v; want %+v", lines[i], word, got, ok, wants[i])
		}
		if got, ok := decodeARM64RawSVEAddSubWide(word &^ (3 << 22)); ok {
			t.Fatalf("unallocated byte destination decoded as %+v", got)
		}
	}
	for _, word := range []uint32{0, 0x45400000, 0x45406000, 0x45c08000} {
		if got, ok := decodeARM64RawSVEAddSubWide(word); ok {
			t.Errorf("neighboring word %#08x decoded as %+v", word, got)
		}
	}
}
