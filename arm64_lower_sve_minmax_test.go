package plan9asm

import (
	"strings"
	"testing"
)

func arm64SVEMinMaxCompleteForms() string {
	var source strings.Builder
	source.WriteString("TEXT sveminmaxforms(SB),$0-0\n")
	for _, base := range []string{"ZSMAX", "ZSMIN", "ZUMAX", "ZUMIN"} {
		for index, width := range []string{"B", "H", "S", "D"} {
			predicate := string(rune('0' + index))
			source.WriteString("\t" + base + " Z1." + width + ", Z2." + width + ", P" + predicate + ".M, Z2." + width + "\n")
			immediate := "-128"
			if strings.HasPrefix(base, "ZU") {
				immediate = "255"
			}
			source.WriteString("\t" + base + " $" + immediate + ", Z3." + width + ", Z3." + width + "\n")
			source.WriteString("\t" + base + "P Z4." + width + ", Z5." + width + ", P" + predicate + ".M, Z5." + width + "\n")
			// Go's generated reduction rows use a generic Zn.T operand for each
			// VB/VH/VS/VD spelling. All 4x4 spelling/source-width combinations
			// are therefore accepted; the encoded width is the bitwise union of
			// the mnemonic's fixed size and the operand size.
			for _, opcodeWidth := range []string{"B", "H", "S", "D"} {
				source.WriteString("\t" + base + "V" + opcodeWidth + " Z6." + width + ", P" + predicate + ", V7\n")
			}
			arrangement := map[string]string{"B": "B16", "H": "H8", "S": "S4", "D": "D2"}[width]
			source.WriteString("\t" + base + "QV Z8." + width + ", P" + predicate + ", V9." + arrangement + "\n")
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64SVEMinMaxCompleteGo127Family(t *testing.T) {
	source := arm64SVEMinMaxCompleteForms()
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"sveminmaxforms": {Name: "sveminmaxforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{`"target-features"="+sve,+sve2,+sve2p1"`, "@llvm.aarch64.sve.smax.nxv", "@llvm.aarch64.sve.sminp.nxv", "@llvm.aarch64.sve.umaxv.nxv", "@llvm.aarch64.sve.uminqv."} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE min/max lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-minmax.ll", "arm64-sve-minmax.o", ll)
		})
	}
}

func TestTranslateARM64SVEMinMaxRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZSMAX $128, Z1.S, Z1.S",
		"ZUMAX $-1, Z1.S, Z1.S",
		"ZSMIN Z1.S, Z2.S, P0.M, Z3.S",
		"ZUMIN $1, Z1.S, Z2.S",
		"ZSMAXVB Z1.H, P0.M, V2",
		"ZSMAXVB Z1.H, P8, V2",
		"ZSMAXVB Z1.H, P0, V2.H8",
		"ZUMAXQV Z1.S, P0, V2.H8",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsveminmax(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsveminmax": {Name: "badsveminmax", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE min/max forms", instruction)
			}
		})
	}
}
