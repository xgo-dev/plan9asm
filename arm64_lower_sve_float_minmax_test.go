package plan9asm

import (
	"strings"
	"testing"
)

func arm64SVEFloatMinMaxCompleteForms() string {
	var source strings.Builder
	source.WriteString("TEXT svefloatminmaxforms(SB),$0-0\n")
	for _, base := range []string{"ZFMAX", "ZFMIN", "ZFMAXNM", "ZFMINNM"} {
		for index, width := range []string{"H", "S", "D"} {
			predicate := string(rune('0' + index))
			source.WriteString("\t" + base + " Z1." + width + ", Z2." + width + ", P" + predicate + ".M, Z2." + width + "\n")
			for _, immediate := range []string{"0.0", "1.0"} {
				source.WriteString("\t" + base + " $(" + immediate + "), Z3." + width + ", P" + predicate + ".M, Z3." + width + "\n")
			}
			source.WriteString("\t" + base + "P Z4." + width + ", Z5." + width + ", P" + predicate + ".M, Z5." + width + "\n")
			for _, opcodeWidth := range []string{"H", "S", "D"} {
				source.WriteString("\t" + base + "V" + opcodeWidth + " Z6." + width + ", P" + predicate + ", V7\n")
			}
			arrangement := map[string]string{"H": "H8", "S": "S4", "D": "D2"}[width]
			source.WriteString("\t" + base + "QV Z8." + width + ", P" + predicate + ", V9." + arrangement + "\n")
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64SVEFloatMinMaxCompleteGo127Family(t *testing.T) {
	source := arm64SVEFloatMinMaxCompleteForms()
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svefloatminmaxforms": {Name: "svefloatminmaxforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{`"target-features"="+sve,+sve2,+sve2p1"`, "@llvm.aarch64.sve.fmax.nxv", "@llvm.aarch64.sve.fminnmp.nxv", "@llvm.aarch64.sve.fmaxnmv.nxv", "@llvm.aarch64.sve.fminqv."} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE floating min/max lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-float-minmax.ll", "arm64-sve-float-minmax.o", ll)
		})
	}
}

func TestTranslateARM64SVEFloatMinMaxRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZFMAX $(0.5), Z1.S, P0.M, Z1.S",
		"ZFMIN Z1.B, Z2.B, P0.M, Z2.B",
		"ZFMAXNM Z1.S, Z2.D, P0.M, Z2.D",
		"ZFMINNM Z1.S, Z2.S, P0.M, Z3.S",
		"ZFMAXP Z1.S, Z2.S, P0.Z, Z2.S",
		"ZFMINVH Z1.S, P8, V2",
		"ZFMAXNMVS Z1.S, P0, V2.S4",
		"ZFMINNMQV Z1.S, P0, V2.H8",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvefloatminmax(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvefloatminmax": {Name: "badsvefloatminmax", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE floating min/max forms", instruction)
			}
		})
	}
}
