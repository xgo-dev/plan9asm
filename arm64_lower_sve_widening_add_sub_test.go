package plan9asm

import (
	"strings"
	"testing"
)

func arm64SVEWideningAddSubCompleteForms() string {
	var source strings.Builder
	source.WriteString("TEXT svewidenaddsubforms(SB),$0-0\n")
	for _, op := range []string{
		"ZSADDLB", "ZSADDLBT", "ZSADDLT",
		"ZSSUBLB", "ZSSUBLBT", "ZSSUBLT", "ZSSUBLTB",
		"ZUADDLB", "ZUADDLT", "ZUSUBLB", "ZUSUBLT",
	} {
		for _, width := range []string{"B", "H", "S"} {
			destinationWidth := map[string]string{"B": "H", "H": "S", "S": "D"}[width]
			source.WriteString("\t" + op + " Z1." + width + ", Z2." + width + ", Z3." + destinationWidth + "\n")
		}
	}
	for _, op := range []string{
		"ZSADDWB", "ZSADDWT", "ZSSUBWB", "ZSSUBWT",
		"ZUADDWB", "ZUADDWT", "ZUSUBWB", "ZUSUBWT",
	} {
		for _, narrowWidth := range []string{"B", "H", "S"} {
			wideWidth := map[string]string{"B": "H", "H": "S", "S": "D"}[narrowWidth]
			source.WriteString("\t" + op + " Z4." + narrowWidth + ", Z5." + wideWidth + ", Z6." + wideWidth + "\n")
		}
	}
	for _, op := range []string{
		"ZADDHNB", "ZADDHNT", "ZRADDHNB", "ZRADDHNT",
		"ZSUBHNB", "ZSUBHNT", "ZRSUBHNB", "ZRSUBHNT",
	} {
		for _, wideWidth := range []string{"H", "S", "D"} {
			narrowWidth := map[string]string{"H": "B", "S": "H", "D": "S"}[wideWidth]
			source.WriteString("\t" + op + " Z7." + wideWidth + ", Z8." + wideWidth + ", Z9." + narrowWidth + "\n")
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64SVEWideningAddSubCompleteGo127Family(t *testing.T) {
	source := arm64SVEWideningAddSubCompleteForms()
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svewidenaddsubforms": {Name: "svewidenaddsubforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve,+sve2"`,
				"@llvm.aarch64.sve.saddlb.nxv8i16",
				"@llvm.aarch64.sve.saddlbt.nxv4i32",
				"@llvm.aarch64.sve.ssubltb.nxv2i64",
				"@llvm.aarch64.sve.uaddlt.nxv8i16",
				"@llvm.aarch64.sve.usublt.nxv2i64",
				"@llvm.aarch64.sve.saddwb.nxv8i16",
				"@llvm.aarch64.sve.usubwt.nxv2i64",
				"@llvm.aarch64.sve.addhnb.nxv8i16",
				"@llvm.aarch64.sve.raddhnt.nxv4i32",
				"@llvm.aarch64.sve.rsubhnb.nxv2i64",
				"@llvm.aarch64.sve.subhnt.nxv8i16",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE widening/narrowing add/sub lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-widening-add-sub.ll", "arm64-sve-widening-add-sub.o", ll)
		})
	}
}

func TestTranslateARM64SVEWideningAddSubRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZSADDLB Z1.B, Z2.H, Z3.H",
		"ZSADDLT Z1.B, Z2.B, Z3.S",
		"ZUADDLB Z1.D, Z2.D, Z3.D",
		"ZSSUBLBT Z1.H, Z2.H, Z3.H",
		"ZSSUBLTB Z1.S, Z2.H, Z3.D",
		"ZSADDWB Z1.B, Z2.B, Z3.H",
		"ZUADDWT Z1.S, Z2.S, Z3.D",
		"ZSSUBWB Z1.D, Z2.D, Z3.D",
		"ZUSUBWT Z1.H, Z2.S, Z3.H",
		"ZADDHNB Z1.B, Z2.B, Z3.B",
		"ZRADDHNT Z1.S, Z2.S, Z3.S",
		"ZSUBHNB Z1.D, Z2.S, Z3.S",
		"ZRSUBHNT Z1.D, Z2.D, Z3.H",
		"ZSADDLB.Z Z1.B, Z2.B, Z3.H",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvewidenaddsub(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvewidenaddsub": {Name: "badsvewidenaddsub", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE widening/narrowing add/sub forms", instruction)
			}
		})
	}
}
