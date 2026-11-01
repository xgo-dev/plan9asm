package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64SVEFloatReciprocalStepCompleteGo127Family(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT svefloatreciprocalstep(SB),$0-0\n")
	for opIndex, op := range []string{"ZFRECPS", "ZFRSQRTS"} {
		for widthIndex, width := range []string{"H", "S", "D"} {
			reg := opIndex*3 + widthIndex
			fmt.Fprintf(&source, "\t%s Z%d.%s, Z%d.%s, Z%d.%s\n", op, reg, width, reg+1, width, reg+2, width)
		}
	}
	source.WriteString("\tRET\n")
	requireARM64SVEGoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svefloatreciprocalstep": {Name: "svefloatreciprocalstep", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve"`,
				"@llvm.aarch64.sve.frecps.x.nxv8f16",
				"@llvm.aarch64.sve.frecps.x.nxv4f32",
				"@llvm.aarch64.sve.frsqrts.x.nxv2f64",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE floating reciprocal-step lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-float-reciprocal-step.ll", "arm64-sve-float-reciprocal-step.o", ll)
		})
	}
}

func TestTranslateARM64SVEFloatReciprocalStepRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZFRECPS Z1.B, Z2.B, Z3.B",
		"ZFRECPS Z1.H, Z2.S, Z3.S",
		"ZFRSQRTS Z1.S, Z2.S, Z3.D",
		"ZFRSQRTS Z1.Q, Z2.Q, Z3.Q",
		"ZFRECPS Z1.S, Z2.S",
		"ZFRSQRTS.Z Z1.D, Z2.D, Z3.D",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvefloatreciprocalstep(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvefloatreciprocalstep": {Name: "badsvefloatreciprocalstep", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's floating reciprocal-step forms", instruction)
			}
		})
	}
}
