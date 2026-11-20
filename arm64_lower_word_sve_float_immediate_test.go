package plan9asm

import (
	"fmt"
	"math"
	"strings"
	"testing"
)

func TestTranslateARM64RawSVEFloatImmediateGoHighwayRegression(t *testing.T) {
	const source = `
TEXT rawSVEFloatImmediate(SB),$0-0
	WORD $0x2579cc00 // FMOV Z0.H, #0.5
	WORD $0x25b9cc1b // FMOV Z27.S, #0.5
	WORD $0x25f9ce1f // FMOV Z31.D, #1.0
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"rawSVEFloatImmediate": {Name: "rawSVEFloatImmediate", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"<vscale x 8 x half>", "<vscale x 4 x float>", "<vscale x 2 x double>"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("SVE FMOV immediate omitted %q:\n%s", want, ir)
				}
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-sve-fmov.ll", "arm64-raw-sve-fmov.o", ir)
		})
	}
}

func arm64SVEFloatImmediateTestValue(imm int) float64 {
	value := math.Ldexp(float64(16+(imm&15)), ((imm>>4&7)^4)-7)
	if imm&128 != 0 {
		value = -value
	}
	return value
}

func arm64SVEFloatImmediateAssembly(size, dst, predicate, imm int) string {
	if predicate < 0 {
		return fmt.Sprintf("fmov z%d.%c, #%g", dst, "bhsd"[size], arm64SVEFloatImmediateTestValue(imm))
	}
	return fmt.Sprintf("fmov z%d.%c, p%d/m, #%g", dst, "bhsd"[size], predicate, arm64SVEFloatImmediateTestValue(imm))
}

func TestARM64RawSVEFloatImmediateOperandFields(t *testing.T) {
	var lines []string
	var wants []Instr
	for size := 1; size < 4; size++ {
		for _, predicated := range []bool{false, true} {
			limits := [3]int{32, 1, 256}
			if predicated {
				limits[1] = 16
			}
			for field, limit := range limits {
				for value := 0; value < limit; value++ {
					fields := [3]int{31, 15, 255}
					fields[field] = value
					dst, pred, imm := fields[0], fields[1], fields[2]
					want := Instr{Op: "ZFDUP", Args: []Operand{{Kind: OpImm, ImmIsFloat: true, Imm: int64(math.Float64bits(arm64SVEFloatImmediateTestValue(imm)))}}}
					if predicated {
						want.Op = "ZFCPY"
						want.Args = append(want.Args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d.M", pred))})
					} else {
						pred = -1
					}
					want.Args = append(want.Args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", dst, "BHSD"[size]))})
					wants = append(wants, want)
					lines = append(lines, arm64SVEFloatImmediateAssembly(size, dst, pred, imm))
				}
			}
		}
	}
	for i, word := range assembleARM64LLVMWords(t, lines, "+sve") {
		got, ok := decodeARM64RawSVEFloatImmediate(word)
		if !ok || got.Op != wants[i].Op || fmt.Sprint(got.Args) != fmt.Sprint(wants[i].Args) {
			t.Fatalf("%s: %#08x = %+v, %v; want %+v", lines[i], word, got, ok, wants[i])
		}
		if got, ok := decodeARM64RawSVEFloatImmediate(word &^ (3 << 22)); ok {
			t.Errorf("reserved byte-width encoding decoded as %+v", got)
		}
	}
	for _, word := range []uint32{0x0593ee1b, 0x05934e1b, 0x25b9ec00, 0x25b8cc00} {
		if got, ok := decodeARM64RawSVEFloatImmediate(word); ok {
			t.Errorf("reserved/neighboring word %#08x decoded as %+v", word, got)
		}
	}
}

func TestARM64RawSVEFloatCopyCompleteFormats(t *testing.T) {
	var lines []string
	for _, width := range []string{"h", "s", "d"} {
		for _, predicate := range []int{0, 7, 8, 15} {
			for _, value := range []float64{-31.0, -0.125, 1.0, 31.0} {
				lines = append(lines, fmt.Sprintf("fmov z31.%s, p%d/m, #%g", width, predicate, value))
			}
		}
	}
	var source strings.Builder
	source.WriteString("TEXT rawfloatcopy(SB),$0-0\n")
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
				Sigs: map[string]FuncSig{"rawfloatcopy": {Name: "rawfloatcopy", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "rawfloatcopy.ll", "rawfloatcopy.o", ir)
		})
	}
}
