package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type arm64RawSVEFloatArithmeticCase struct {
	op        string
	size      int
	mode      string
	immediate float64
	lane      int
}

func arm64RawSVEFloatArithmeticCases() []arm64RawSVEFloatArithmeticCase {
	var forms []arm64RawSVEFloatArithmeticCase
	for _, op := range []string{"fadd", "fsub", "fsubr", "fmul"} {
		for size := 1; size < 4; size++ {
			forms = append(forms, arm64RawSVEFloatArithmeticCase{op: op, size: size, mode: "predicated"})
			if op != "fsubr" {
				forms = append(forms, arm64RawSVEFloatArithmeticCase{op: op, size: size, mode: "vector"})
			}
			largeImmediate := 1.0
			if op == "fmul" {
				largeImmediate = 2.0
				for lane := 0; lane < 16>>size; lane++ {
					forms = append(forms, arm64RawSVEFloatArithmeticCase{op: op, size: size, mode: "indexed", lane: lane})
				}
			}
			for _, immediate := range []float64{0.5, largeImmediate} {
				forms = append(forms, arm64RawSVEFloatArithmeticCase{op: op, size: size, mode: "immediate", immediate: immediate})
			}
		}
	}
	return forms
}

func (form arm64RawSVEFloatArithmeticCase) assembly(dst, first, second, predicate int) string {
	width := "bhsd"[form.size]
	switch form.mode {
	case "vector":
		return fmt.Sprintf("%s z%d.%c, z%d.%c, z%d.%c", form.op, dst, width, first, width, second, width)
	case "indexed":
		return fmt.Sprintf("%s z%d.%c, z%d.%c, z%d.%c[%d]", form.op, dst, width, first, width, second, width, form.lane)
	case "immediate":
		return fmt.Sprintf("%s z%d.%c, p%d/m, z%d.%c, #%0.1f", form.op, dst, width, predicate, dst, width, form.immediate)
	default:
		return fmt.Sprintf("%s z%d.%c, p%d/m, z%d.%c, z%d.%c", form.op, dst, width, predicate, dst, width, second, width)
	}
}

func TestARM64RawSVEFloatArithmeticCompleteFormats(t *testing.T) {
	forms := arm64RawSVEFloatArithmeticCases()
	if len(forms) != 59 {
		t.Fatalf("floating arithmetic cases=%d, want 59 including every indexed lane", len(forms))
	}
	testARM64RawSVEFloatArithmeticObjects(t, forms)
}

func testARM64RawSVEFloatArithmeticObjects(t *testing.T, forms []arm64RawSVEFloatArithmeticCase) {
	t.Helper()
	var lines []string
	for _, form := range forms {
		second := 29
		if form.mode == "indexed" {
			second = 7
			if form.size == 3 {
				second = 15
			}
		}
		lines = append(lines, form.assembly(31, 30, second, 7))
	}
	var source strings.Builder
	source.WriteString("TEXT rawfloatarithmetic(SB),$0-0\n")
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
				Sigs: map[string]FuncSig{"rawfloatarithmetic": {Name: "rawfloatarithmetic", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "rawfloatarithmetic.ll", "rawfloatarithmetic.o", ir)
		})
	}
}

func TestARM64RawSVEFloatArithmeticOperandFields(t *testing.T) {
	var lines []string
	var wants []arm64RawSVEFloat
	for _, form := range arm64RawSVEFloatArithmeticCases() {
		predicated := form.mode == "predicated" || form.mode == "immediate"
		limits := []int{32, 32, 32, 1}
		if predicated {
			limits[1], limits[3] = 1, 8
		}
		if form.mode == "immediate" {
			limits[2] = 1
		} else if form.mode == "indexed" {
			limits[2] = 8
			if form.size == 3 {
				limits[2] = 16
			}
		}
		for field, limit := range limits {
			for value := 0; value < limit; value++ {
				fields := [4]int{31, 30, limits[2] - 1, limits[3] - 1}
				fields[field] = value
				dst, first, second, predicate := fields[0], fields[1], fields[2], fields[3]
				lines = append(lines, form.assembly(dst, first, second, predicate))
				kind := map[string]arm64RawSVEFloatKind{
					"fadd": arm64RawSVEFloatAdd, "fsub": arm64RawSVEFloatSub,
					"fsubr": arm64RawSVEFloatSubReverse, "fmul": arm64RawSVEFloatMul,
				}[form.op]
				want := arm64RawSVEFloat{kind: kind, elementBits: 8 << form.size,
					destination: dst, first: first, second: second, predicated: predicated}
				if predicated {
					want.first, want.second, want.predicate = second, 0, predicate
				}
				if form.mode == "immediate" {
					want.first, want.hasImmediate, want.immediate = dst, true, form.immediate
				} else if form.mode == "indexed" {
					want.hasLane, want.lane = true, form.lane
				}
				wants = append(wants, want)
			}
		}
	}
	for i, word := range assembleARM64LLVMWords(t, lines, "+sve") {
		got, ok := decodeARM64RawSVEFloat(word)
		if !ok || got != wants[i] {
			t.Fatalf("%s: decoded %#08x as %+v, %v; want %+v", lines[i], word, got, ok, wants[i])
		}
		if wants[i].hasImmediate {
			for bit := uint32(6); bit < 10; bit++ {
				if got, ok := decodeARM64RawSVEFloat(word | 1<<bit); ok {
					t.Fatalf("reserved immediate bit %d decoded as %+v", bit, got)
				}
			}
		}
		if !wants[i].hasLane {
			if got, ok := decodeARM64RawSVEFloat(word &^ (3 << 22)); ok {
				t.Fatalf("reserved byte-width encoding decoded as %+v", got)
			}
		}
	}
	for _, word := range []uint32{0, 0x651c8000, 0x64a02400, 0x65048000} {
		if got, ok := decodeARM64RawSVEFloat(word); ok {
			t.Errorf("neighboring word %#08x decoded as %+v", word, got)
		}
	}
}
