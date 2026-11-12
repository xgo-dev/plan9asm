package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func arm64SVEAddressGenerationAssembly(mode, shift, dst, base, index int) string {
	width, modifier := byte('d'), "lsl"
	switch mode {
	case 0:
		modifier = "sxtw"
	case 1:
		modifier = "uxtw"
	case 2:
		width = 's'
	}
	return fmt.Sprintf("adr z%d.%c, [z%d.%c, z%d.%c, %s #%d]", dst, width, base, width, index, width, modifier, shift)
}

func TestARM64RawSVEAddressGenerationCompleteFormats(t *testing.T) {
	var lines []string
	for mode := 0; mode < 4; mode++ {
		for shift := 0; shift < 4; shift++ {
			lines = append(lines, arm64SVEAddressGenerationAssembly(mode, shift, 31, 30, 29))
		}
	}
	var source strings.Builder
	source.WriteString("TEXT rawaddressgeneration(SB),$0-0\n")
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
				Sigs: map[string]FuncSig{"rawaddressgeneration": {Name: "rawaddressgeneration", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "rawaddressgeneration.ll", "rawaddressgeneration.o", ir)
		})
	}
}

func TestARM64RawSVEAddressGenerationOperandFields(t *testing.T) {
	var lines []string
	var wants []Instr
	for mode := 0; mode < 4; mode++ {
		for shift := 0; shift < 4; shift++ {
			for field := 0; field < 3; field++ {
				for value := 0; value < 32; value++ {
					fields := [3]int{31, 30, 29}
					fields[field] = value
					dst, base, index := fields[0], fields[1], fields[2]
					lines = append(lines, arm64SVEAddressGenerationAssembly(mode, shift, dst, base, index))
					width := byte('D')
					if mode == 2 {
						width = 'S'
					}
					reg := func(number int) Reg { return Reg(fmt.Sprintf("Z%d.%c", number, width)) }
					extension := [...]ExtendOp{ExtendSXTW, ExtendUXTW, "", ""}[mode]
					wants = append(wants, Instr{Op: "ZADR", Args: []Operand{
						{Kind: OpMem, Mem: MemRef{Base: reg(base), Index: reg(index), IndexExt: extension, Scale: 1 << shift}},
						{Kind: OpReg, Reg: reg(dst)},
					}})
				}
			}
		}
	}
	for i, word := range assembleARM64LLVMWords(t, lines, "+sve") {
		got, ok := decodeARM64RawSVEAddressGeneration(word)
		if !ok || got.Op != wants[i].Op || fmt.Sprint(got.Args) != fmt.Sprint(wants[i].Args) {
			t.Fatalf("%s: decoded %#08x as %+v, %v; want %+v", lines[i], word, got, ok, wants[i])
		}
	}
	for _, word := range []uint32{0, 0x0420b000, 0x04208000, 0x0400a000} {
		if got, ok := decodeARM64RawSVEAddressGeneration(word); ok {
			t.Errorf("neighboring word %#08x decoded as %+v", word, got)
		}
	}
}
