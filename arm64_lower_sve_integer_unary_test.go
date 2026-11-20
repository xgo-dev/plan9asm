package plan9asm

import (
	"strings"
	"testing"
)

func arm64SVEIntegerUnaryCompleteForms() string {
	var source strings.Builder
	source.WriteString("TEXT sveintegerunaryforms(SB),$0-0\n")
	for _, op := range []string{"ZABS", "ZCLS", "ZCLZ", "ZCNOT", "ZCNT", "ZNEG", "ZNOT", "ZRBIT", "ZSQABS", "ZSQNEG"} {
		for index, width := range []string{"B", "H", "S", "D"} {
			predicate := string(rune('0' + index))
			for _, mode := range []string{"M", "Z"} {
				source.WriteString("\t" + op + " Z1." + width + ", P" + predicate + "." + mode + ", Z2." + width + "\n")
			}
		}
	}
	for _, spec := range []struct {
		op     string
		widths []string
	}{
		{"ZREVB", []string{"H", "S", "D"}},
		{"ZREVH", []string{"S", "D"}},
		{"ZREVW", []string{"D"}},
		{"ZSXTB", []string{"H", "S", "D"}},
		{"ZUXTB", []string{"H", "S", "D"}},
		{"ZSXTH", []string{"S", "D"}},
		{"ZUXTH", []string{"S", "D"}},
		{"ZSXTW", []string{"D"}},
		{"ZUXTW", []string{"D"}},
		{"ZURECPE", []string{"S"}},
		{"ZURSQRTE", []string{"S"}},
	} {
		for index, width := range spec.widths {
			predicate := string(rune('0' + index))
			for _, mode := range []string{"M", "Z"} {
				source.WriteString("\t" + spec.op + " Z3." + width + ", P" + predicate + "." + mode + ", Z4." + width + "\n")
			}
		}
	}
	for _, width := range []string{"B", "H", "S", "D"} {
		source.WriteString("\tZREV Z5." + width + ", Z6." + width + "\n")
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64SVEIntegerUnaryCompleteGo127Family(t *testing.T) {
	source := arm64SVEIntegerUnaryCompleteForms()
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"sveintegerunaryforms": {Name: "sveintegerunaryforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{`"target-features"="+sve,+sve2"`, "@llvm.aarch64.sve.abs.nxv", "@llvm.aarch64.sve.cnt.nxv", "@llvm.aarch64.sve.rbit.nxv", "@llvm.aarch64.sve.sqabs.nxv", "@llvm.aarch64.sve.sxtb.nxv", "@llvm.aarch64.sve.urecpe.nxv", "@llvm.vector.reverse.nxv"} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE integer unary lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-integer-unary.ll", "arm64-sve-integer-unary.o", ll)
		})
	}
}

func TestTranslateARM64SVEIntegerUnaryRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZABS Z1.S, P0, Z2.S",
		"ZCNT Z1.S, P8.M, Z2.S",
		"ZNEG Z1.S, P0.M, Z2.D",
		"ZREVB Z1.B, P0.M, Z2.B",
		"ZREVH Z1.H, P0.M, Z2.H",
		"ZREVW Z1.S, P0.M, Z2.S",
		"ZSXTB Z1.B, P0.M, Z2.B",
		"ZUXTH Z1.H, P0.M, Z2.H",
		"ZSXTW Z1.S, P0.M, Z2.S",
		"ZURECPE Z1.H, P0.M, Z2.H",
		"ZURSQRTE Z1.D, P0.M, Z2.D",
		"ZREV Z1.S, P0.M, Z2.S",
		"ZREV Z1.S, Z2.D",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsveintegerunary(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsveintegerunary": {Name: "badsveintegerunary", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE integer unary forms", instruction)
			}
		})
	}
}
