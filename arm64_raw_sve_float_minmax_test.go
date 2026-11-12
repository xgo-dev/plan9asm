package plan9asm

import (
	"fmt"
	"math"
	"strings"
	"testing"
)

func arm64RawSVEFloatMinMaxNativeForms() []string {
	var lines []string
	for _, op := range []string{"fmax", "fmin", "fmaxnm", "fminnm"} {
		for i, width := range []string{"h", "s", "d"} {
			lines = append(lines,
				fmt.Sprintf("%s z31.%s, p7/m, z31.%s, z30.%s", op, width, width, width),
				fmt.Sprintf("%s z31.%s, p7/m, z31.%s, #0.0", op, width, width),
				fmt.Sprintf("%s z31.%s, p7/m, z31.%s, #1.0", op, width, width),
				fmt.Sprintf("%sp z31.%s, p7/m, z31.%s, z30.%s", op, width, width, width),
				fmt.Sprintf("%sqv v31.%d%s, p7, z30.%s", op, 8>>i, width, width),
				fmt.Sprintf("%sv %s31, p7, z30.%s", op, width, width))
		}
	}
	return lines
}

func TestARM64RawSVEFloatMinMaxOperandFields(t *testing.T) {
	lines := arm64RawSVEFloatMinMaxNativeForms()
	for i, word := range assembleARM64LLVMWords(t, lines, "+sve2p1") {
		if i%6 == 5 {
			if _, ok := decodeARM64RawSVEFloatMinMaxReduction(word); !ok {
				t.Errorf("missing ordinary reduction %s", lines[i])
			}
			continue
		}
		got, ok := decodeARM64RawSVEFloatMinMax(word)
		if !ok {
			t.Fatalf("%s: rejected %#08x", lines[i], word)
		}
		fields := strings.Fields(lines[i])
		width := "HSD"[(i/6)%3]
		if got.Op != Op("Z"+strings.ToUpper(fields[0])) {
			t.Errorf("%s: wrong opcode %s", lines[i], got.Op)
		}
		if i%6 == 1 || i%6 == 2 {
			if got.Args[0].Kind != OpImm || !got.Args[0].ImmIsFloat || math.Float64frombits(uint64(got.Args[0].Imm)) != float64(i%6-1) {
				t.Errorf("%s: wrong immediate %+v", lines[i], got.Args[0])
			}
		} else if got.Args[0].Reg != Reg(fmt.Sprintf("Z30.%c", width)) {
			t.Errorf("%s: wrong source %+v", lines[i], got.Args[0])
		}
		if i%6 == 4 {
			if got.Args[1].Reg != "P7" || got.Args[2].Reg != Reg(fmt.Sprintf("V31.%c%d", width, 8>>((i/6)%3))) {
				t.Errorf("%s: wrong quad reduction %+v", lines[i], got)
			}
		} else if got.Args[1].Reg != Reg(fmt.Sprintf("Z31.%c", width)) || got.Args[2].Reg != "P7.M" || got.Args[3].Reg != got.Args[1].Reg {
			t.Errorf("%s: wrong destructive form %+v", lines[i], got)
		}
	}
	for _, word := range []uint32{0x65068000, 0x659e8040, 0x65888000, 0x659ea000} {
		if got, ok := decodeARM64RawSVEFloatMinMax(word); ok {
			t.Errorf("reserved/neighboring word %#08x decoded as %+v", word, got)
		}
	}
}

func TestARM64RawSVEFloatMinMaxCompleteFormats(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawminmax(SB),$0-0\n")
	for _, word := range assembleARM64LLVMWords(t, arm64RawSVEFloatMinMaxNativeForms(), "+sve2p1") {
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
				Sigs: map[string]FuncSig{"rawminmax": {Name: "rawminmax", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "rawminmax.ll", "rawminmax.o", ir)
		})
	}
}
