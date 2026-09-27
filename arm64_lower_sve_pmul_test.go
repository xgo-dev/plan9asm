package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64SVEPMULCompleteGo127Family(t *testing.T) {
	source := "TEXT svepmulforms(SB),$0-0\n\tZPMUL Z1.B, Z2.B, Z3.B\n\tRET\n"
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svepmulforms": {Name: "svepmulforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{`"target-features"="+sve,+sve2"`, "@llvm.aarch64.sve.pmul.nxv16i8"} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE PMUL lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-pmul.ll", "arm64-sve-pmul.o", ll)
		})
	}
}

func TestTranslateARM64SVEPMULRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZPMUL Z1.H, Z2.H, Z3.H",
		"ZPMUL Z1.B, Z2.H, Z3.B",
		"ZPMUL Z1.B, Z2.B",
		"ZPMUL.Z Z1.B, Z2.B, Z3.B",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvepmul(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvepmul": {Name: "badsvepmul", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE PMUL forms", instruction)
			}
		})
	}
}
