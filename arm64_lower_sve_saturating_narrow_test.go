package plan9asm

import (
	"strings"
	"testing"
)

func arm64SVESaturatingNarrowCompleteForms() string {
	var source strings.Builder
	source.WriteString("TEXT svesaturatingnarrowforms(SB),$0-0\n")
	for _, op := range []string{"ZSQXTNB", "ZSQXTNT", "ZSQXTUNB", "ZSQXTUNT", "ZUQXTNB", "ZUQXTNT"} {
		for _, widths := range [][2]string{{"H", "B"}, {"S", "H"}, {"D", "S"}} {
			source.WriteString("\t" + op + " Z1." + widths[0] + ", Z2." + widths[1] + "\n")
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64SVESaturatingNarrowCompleteGo127Family(t *testing.T) {
	source := arm64SVESaturatingNarrowCompleteForms()
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svesaturatingnarrowforms": {Name: "svesaturatingnarrowforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve,+sve2"`,
				"@llvm.aarch64.sve.sqxtnb.nxv8i16",
				"@llvm.aarch64.sve.sqxtnt.nxv4i32",
				"@llvm.aarch64.sve.sqxtunb.nxv2i64",
				"@llvm.aarch64.sve.sqxtunt.nxv8i16",
				"@llvm.aarch64.sve.uqxtnb.nxv4i32",
				"@llvm.aarch64.sve.uqxtnt.nxv2i64",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE saturating-narrow lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-saturating-narrow.ll", "arm64-sve-saturating-narrow.o", ll)
		})
	}
}

func TestTranslateARM64SVESaturatingNarrowRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZSQXTNB Z1.B, Z2.B",
		"ZSQXTNT Z1.H, Z2.H",
		"ZSQXTUNB Z1.S, Z2.B",
		"ZSQXTUNT Z1.D, Z2.H",
		"ZUQXTNB Z1.Q, Z2.D",
		"ZUQXTNT Z1.D",
		"ZSQXTNB.Z Z1.H, Z2.B",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvesaturatingnarrow(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvesaturatingnarrow": {Name: "badsvesaturatingnarrow", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE saturating-narrow forms", instruction)
			}
		})
	}
}
