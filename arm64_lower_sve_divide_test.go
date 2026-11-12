package plan9asm

import (
	"strings"
	"testing"
)

func arm64SVEDivideCompleteForms() string {
	var source strings.Builder
	source.WriteString("TEXT svedivideforms(SB),$0-0\n")
	for _, op := range []string{"ZSDIV", "ZSDIVR", "ZUDIV", "ZUDIVR"} {
		for predicate, width := range []string{"S", "D"} {
			source.WriteString("\t" + op + " Z1." + width + ", Z2." + width + ", P" + string(rune('0'+predicate)) + ".M, Z2." + width + "\n")
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64SVEDivideCompleteGo127Family(t *testing.T) {
	source := arm64SVEDivideCompleteForms()
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svedivideforms": {Name: "svedivideforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve"`,
				"@llvm.aarch64.sve.sdiv.nxv4i32",
				"@llvm.aarch64.sve.sdivr.nxv2i64",
				"@llvm.aarch64.sve.udiv.nxv4i32",
				"@llvm.aarch64.sve.udivr.nxv2i64",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE divide lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-divide.ll", "arm64-sve-divide.o", ll)
		})
	}
}

func TestTranslateARM64SVEDivideRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZSDIV Z1.B, Z2.B, P0.M, Z2.B",
		"ZUDIV Z1.H, Z2.H, P0.M, Z2.H",
		"ZSDIVR Z1.S, Z2.D, P0.M, Z2.D",
		"ZUDIVR Z1.D, Z2.D, P0, Z2.D",
		"ZSDIV Z1.S, Z2.S, P8.M, Z2.S",
		"ZUDIV Z1.S, Z2.S, P0.M, Z3.S",
		"ZSDIV.Z Z1.S, Z2.S, P0.M, Z2.S",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvedivide(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvedivide": {Name: "badsvedivide", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE divide forms", instruction)
			}
		})
	}
}
