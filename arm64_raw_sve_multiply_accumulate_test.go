package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func arm64RawSVEMultiplyAccumulateAssembly(op string, size, destination, first, second, predicate, lane int) string {
	width := "bhsd"[size]
	if lane >= 0 {
		return fmt.Sprintf("%s z%d.%c, z%d.%c, z%d.%c[%d]", op, destination, width, first, width, second, width, lane)
	}
	return fmt.Sprintf("%s z%d.%c, p%d/m, z%d.%c, z%d.%c", op, destination, width, predicate, first, width, second, width)
}

func TestARM64RawSVEMultiplyAccumulateCompleteFormats(t *testing.T) {
	var source strings.Builder
	var lines []string
	for _, op := range []string{"mla", "mls", "mad", "msb"} {
		for size := 0; size < 4; size++ {
			lines = append(lines, arm64RawSVEMultiplyAccumulateAssembly(op, size, 31, 30, 29, 7, -1))
			if size == 0 || op == "mad" || op == "msb" {
				continue
			}
			for lane := 0; lane < 16>>size; lane++ {
				second := 7
				if size == 3 {
					second = 15
				}
				lines = append(lines, arm64RawSVEMultiplyAccumulateAssembly(op, size, 31, 30, second, 0, lane))
			}
		}
	}
	source.WriteString("TEXT rawmultiplyaccumulate(SB),$0-0\n")
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
				Sigs: map[string]FuncSig{"rawmultiplyaccumulate": {Name: "rawmultiplyaccumulate", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "rawmultiplyaccumulate.ll", "rawmultiplyaccumulate.o", ir)
		})
	}
}

func TestARM64RawSVEMultiplyAccumulateOperandFields(t *testing.T) {
	var lines []string
	var wants []Instr
	for _, op := range []string{"mla", "mls", "mad", "msb"} {
		for size := 0; size < 4; size++ {
			for _, indexed := range []bool{false, true} {
				if indexed && (size == 0 || op == "mad" || op == "msb") {
					continue
				}
				limits := []int{32, 32, 32, 8, 1}
				if indexed {
					limits[2], limits[3], limits[4] = 8, 1, 16>>size
					if size == 3 {
						limits[2] = 16
					}
				}
				for field, limit := range limits {
					for value := 0; value < limit; value++ {
						fields := [5]int{31, 31, limits[2] - 1, limits[3] - 1, limits[4] - 1}
						fields[field] = value
						dst, first, second, pred, lane := fields[0], fields[1], fields[2], fields[3], fields[4]
						index := ""
						if indexed {
							index = fmt.Sprintf("[%d]", lane)
						} else {
							lane = -1
						}
						lines = append(lines, arm64RawSVEMultiplyAccumulateAssembly(op, size, dst, first, second, pred, lane))
						width := "BHSD"[size]
						args := []Operand{
							{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c%s", second, width, index))},
							{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", first, width))},
						}
						if !indexed {
							args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d.M", pred))})
						}
						args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", dst, width))})
						wants = append(wants, Instr{Op: Op("Z" + strings.ToUpper(op)), Args: args})
					}
				}
			}
		}
	}
	for i, word := range assembleARM64LLVMWords(t, lines, "+sve2") {
		if !arm64RawPoolSVEPreservesNZCV(word) {
			t.Fatalf("%s: multiply-accumulate unexpectedly clobbers NZCV", lines[i])
		}
		if writes, known := arm64RawPoolGPWrites(word); !known || writes != 0 || !arm64RawPoolSVEIgnoresAddress(word, 9) {
			t.Fatalf("%s: vector-only operation has unknown or address-dependent GP effects", lines[i])
		}
		got, ok := decodeARM64RawSVEMultiplyAccumulate(word)
		if !ok || got.Op != wants[i].Op || fmt.Sprint(got.Args) != fmt.Sprint(wants[i].Args) {
			t.Fatalf("%s: decoded %#08x as %+v, %v; want %+v", lines[i], word, got, ok, wants[i])
		}
	}
	for _, word := range []uint32{0, 0x04008000, 0x04204000, 0x44200400, 0x44a01000, 0x44c00800} {
		if got, ok := decodeARM64RawSVEMultiplyAccumulate(word); ok {
			t.Errorf("neighboring word %#08x decoded as %+v", word, got)
		}
	}
}
