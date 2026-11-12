package plan9asm

import (
	"strings"
	"testing"
)

var arm64SVERoundingShiftOps = []string{
	"ZSQRSHL", "ZSQRSHLR", "ZSQSHLR",
	"ZUQRSHL", "ZUQRSHLR", "ZUQSHLR",
	"ZSRSHL", "ZSRSHLR", "ZURSHL", "ZURSHLR",
}

func arm64SVERoundingShiftCompleteForms() string {
	var source strings.Builder
	source.WriteString("TEXT sveroundingshiftforms(SB),$0-0\n")
	for _, op := range arm64SVERoundingShiftOps {
		for _, width := range []string{"B", "H", "S", "D"} {
			source.WriteString("\t" + op + " Z1." + width + ", Z2." + width + ", P0.M, Z2." + width + "\n")
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64SVERoundingShiftCompleteGo127Family(t *testing.T) {
	source := arm64SVERoundingShiftCompleteForms()
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"sveroundingshiftforms": {Name: "sveroundingshiftforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve,+sve2"`,
				"@llvm.aarch64.sve.sqrshl.nxv",
				"@llvm.aarch64.sve.uqrshl.nxv",
				"@llvm.aarch64.sve.sqshl.nxv",
				"@llvm.aarch64.sve.uqshl.nxv",
				"@llvm.aarch64.sve.srshl.nxv",
				"@llvm.aarch64.sve.urshl.nxv",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE rounding-shift lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-rounding-shift.ll", "arm64-sve-rounding-shift.o", ll)
		})
	}
}

func TestTranslateARM64SVERoundingShiftRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZSQRSHL Z1.B, Z2.H, P0.M, Z2.H",
		"ZSQRSHLR Z1.S, Z2.S, P0.M, Z3.S",
		"ZSQSHLR $1, Z2.S, P0.M, Z2.S",
		"ZUQRSHL Z1.D, Z2.D, P8.M, Z2.D",
		"ZSRSHL Z1.S, Z2.S, P0, Z2.S",
		"ZURSHLR.Z Z1.S, Z2.S, P0.M, Z2.S",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_", "$", "imm").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsveroundingshift(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsveroundingshift": {Name: "badsveroundingshift", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE rounding-shift forms", instruction)
			}
		})
	}
}
