package plan9asm

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"testing"
)

func TestARM64SVEFloatImmediateCompleteEncodingDomain(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT svefloatimmediatedomain(SB),$0-0\n")
	count := 0
	for _, sign := range []float64{1, -1} {
		for exponent := -3; exponent <= 4; exponent++ {
			for numerator := 16; numerator <= 31; numerator++ {
				value := math.Ldexp(sign*float64(numerator)/16, exponent)
				operand := Operand{Kind: OpImm, Imm: int64(math.Float64bits(value)), ImmIsFloat: true}
				if !arm64SVEFloatImmediateRepresentable(operand) {
					t.Fatalf("representable ARM floating immediate rejected: %g", value)
				}
				literal := strconv.FormatFloat(value, 'g', -1, 64)
				if !strings.ContainsAny(literal, ".eE") {
					literal += ".0"
				}
				fmt.Fprintf(&source, "\tZFDUP $(%s), Z0.%s\n", literal, []string{"H", "S", "D"}[count%3])
				count++
			}
		}
	}
	if count != 256 {
		t.Fatalf("floating immediate domain has %d values, want 256", count)
	}
	source.WriteString("\tRET\n")
	requireARM64SVEGoAssemblerResult(t, source.String(), true)
	for _, value := range []float64{0, 0.1, math.Inf(1), math.Inf(-1), math.NaN()} {
		operand := Operand{Kind: OpImm, Imm: int64(math.Float64bits(value)), ImmIsFloat: true}
		if arm64SVEFloatImmediateRepresentable(operand) {
			t.Fatalf("non-encodable ARM floating immediate accepted: %g", value)
		}
	}
}

func TestTranslateARM64SVEFloatImmediateCompleteGo127Family(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT svefloatimmediate(SB),$0-0\n")
	values := []string{"1.0", "-1.0", "0.5"}
	for index, width := range []string{"H", "S", "D"} {
		predicate := []int{0, 8, 15}[index]
		fmt.Fprintf(&source, "\tZFCPY $(%s), P%d.M, Z%d.%s\n", values[index], predicate, index+4, width)
		fmt.Fprintf(&source, "\tZFDUP $(%s), Z%d.%s\n", values[index], index+8, width)
	}
	source.WriteString("\tRET\n")
	requireARM64SVEGoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svefloatimmediate": {Name: "svefloatimmediate", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve"`,
				"<vscale x 8 x half>",
				"<vscale x 4 x float>",
				"<vscale x 2 x double>",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE floating immediate lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-float-immediate.ll", "arm64-sve-float-immediate.o", ll)
		})
	}
}

func TestTranslateARM64SVEFloatImmediateRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZFCPY $(1.0), P0.M, Z1.B",
		"ZFCPY $(1.0), P16.M, Z1.S",
		"ZFCPY $(1.0), P0.Z, Z1.S",
		"ZFCPY $(0.0), P0.M, Z1.S",
		"ZFDUP $(1.0), Z1.B",
		"ZFDUP $(0.0), Z1.S",
		"ZFDUP.Z $(1.0), Z1.D",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvefloatimmediate(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvefloatimmediate": {Name: "badsvefloatimmediate", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's floating immediate forms", instruction)
			}
		})
	}
}
