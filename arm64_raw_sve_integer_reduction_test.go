package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func arm64RawSVEIntegerReductionAssembly(op string, size, destination, source, predicate int) string {
	width := "bhsd"[size]
	register := fmt.Sprintf("%c%d", width, destination)
	if strings.HasSuffix(op, "qv") {
		register = fmt.Sprintf("v%d.%d%c", destination, 16>>size, width)
	}
	return fmt.Sprintf("%s %s, p%d, z%d.%c", op, register, predicate, source, width)
}

func TestARM64RawSVEIntegerReductionCompleteFormats(t *testing.T) {
	var source strings.Builder
	var lines []string
	for _, op := range []string{"andv", "eorv", "orv", "addqv", "andqv", "eorqv", "orqv"} {
		for size := 0; size < 4; size++ {
			lines = append(lines, arm64RawSVEIntegerReductionAssembly(op, size, 31, 30, 7))
		}
	}
	source.WriteString("TEXT rawintegerreduce(SB),$0-0\n")
	for _, word := range assembleARM64LLVMWords(t, lines, "+sve2p1") {
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
				Sigs: map[string]FuncSig{"rawintegerreduce": {Name: "rawintegerreduce", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "rawintegerreduce.ll", "rawintegerreduce.o", ir)
		})
	}
}

func TestARM64RawSVEIntegerReductionOperandFields(t *testing.T) {
	var lines []string
	var wants []Instr
	for _, op := range []string{"andv", "eorv", "orv", "addqv", "andqv", "eorqv", "orqv"} {
		for size := 0; size < 4; size++ {
			for field, limit := range []int{32, 32, 8} {
				for value := 0; value < limit; value++ {
					fields := [3]int{31, 31, 7}
					fields[field] = value
					dst, src, pred := fields[0], fields[1], fields[2]
					lines = append(lines, arm64RawSVEIntegerReductionAssembly(op, size, dst, src, pred))
					width := "BHSD"[size]
					mnemonic := "Z" + strings.ToUpper(op)
					destination := fmt.Sprintf("V%d", dst)
					if strings.HasSuffix(op, "qv") {
						destination += fmt.Sprintf(".%c%d", width, 16>>size)
					} else {
						mnemonic += string(width)
					}
					wants = append(wants, Instr{Op: Op(mnemonic), Args: []Operand{
						{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", src, width))},
						{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d", pred))},
						{Kind: OpReg, Reg: Reg(destination)},
					}})
				}
			}
		}
	}
	for i, word := range assembleARM64LLVMWords(t, lines, "+sve2p1") {
		if !arm64RawPoolSVEPreservesNZCV(word) {
			t.Fatalf("%s: integer reduction unexpectedly clobbers NZCV", lines[i])
		}
		if writes, known := arm64RawPoolGPWrites(word); !known || writes != 0 || !arm64RawPoolSVEIgnoresAddress(word, 9) {
			t.Fatalf("%s: vector reduction has unknown or address-dependent GP effects", lines[i])
		}
		got, ok := decodeARM64RawSVEIntegerReduction(word)
		if !ok || got.Op != wants[i].Op || fmt.Sprint(got.Args) != fmt.Sprint(wants[i].Args) {
			t.Fatalf("%s: decoded %#08x as %+v, %v; want %+v", lines[i], word, got, ok, wants[i])
		}
	}
	for _, word := range []uint32{0x04050000, 0x04054000, 0x04182000 ^ (1 << 13), 0x041b2000, 0x041f2000} {
		if got, ok := decodeARM64RawSVEIntegerReduction(word); ok {
			t.Errorf("neighboring word %#08x decoded as %+v", word, got)
		}
	}
}
