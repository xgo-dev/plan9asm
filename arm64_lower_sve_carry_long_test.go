package plan9asm

import (
	"strings"
	"testing"
)

func arm64SVECarryLongCompleteForms() string {
	var source strings.Builder
	source.WriteString("TEXT svecarrylongforms(SB),$0-0\n")
	for _, op := range []string{"ZADCLB", "ZADCLT", "ZSBCLB", "ZSBCLT"} {
		for _, width := range []string{"S", "D"} {
			source.WriteString("\t" + op + " Z1." + width + ", Z2." + width + ", Z3." + width + "\n")
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64SVECarryLongCompleteGo127Family(t *testing.T) {
	source := arm64SVECarryLongCompleteForms()
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svecarrylongforms": {Name: "svecarrylongforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve,+sve2"`,
				"@llvm.aarch64.sve.adclb.nxv4i32",
				"@llvm.aarch64.sve.adclt.nxv2i64",
				"@llvm.aarch64.sve.sbclb.nxv4i32",
				"@llvm.aarch64.sve.sbclt.nxv2i64",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE carry-long lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-carry-long.ll", "arm64-sve-carry-long.o", ll)
		})
	}
}

func TestTranslateARM64SVECarryLongRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZADCLB Z1.B, Z2.B, Z3.B",
		"ZADCLT Z1.H, Z2.H, Z3.H",
		"ZSBCLB Z1.S, Z2.D, Z3.S",
		"ZSBCLT Z1.D, Z2.D",
		"ZADCLB.Z Z1.D, Z2.D, Z3.D",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvecarrylong(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvecarrylong": {Name: "badsvecarrylong", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE carry-long forms", instruction)
			}
		})
	}
}
