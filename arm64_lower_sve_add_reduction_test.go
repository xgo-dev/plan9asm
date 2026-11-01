package plan9asm

import (
	"strings"
	"testing"
)

func arm64SVEAddReductionCompleteForms() string {
	var source strings.Builder
	source.WriteString("TEXT sveaddreduceforms(SB),$0-0\n")
	for _, opcodeWidth := range []string{"H", "S", "D"} {
		for predicate, sourceWidth := range []string{"H", "S", "D"} {
			// The generated FADDA/FADDV encoders use a generic H/S/D source.
			// As with the integer reductions, Go ORs its size bits into the
			// mnemonic's fixed bits, so every 3x3 combination is legal.
			source.WriteString("\tZFADDA" + opcodeWidth + " Z1." + sourceWidth + ", V2, P" + string(rune('0'+predicate)) + ", V2\n")
			source.WriteString("\tZFADDV" + opcodeWidth + " Z3." + sourceWidth + ", P" + string(rune('3'+predicate)) + ", V4\n")
		}
	}
	for predicate, width := range []string{"H", "S", "D"} {
		arrangement := map[string]string{"H": "H8", "S": "S4", "D": "D2"}[width]
		source.WriteString("\tZFADDQV Z5." + width + ", P" + string(rune('0'+predicate)) + ", V6." + arrangement + "\n")
	}
	for predicate, width := range []string{"B", "H", "S"} {
		source.WriteString("\tZSADDVD Z7." + width + ", P" + string(rune('4'+predicate)) + ", V8\n")
	}
	for predicate, width := range []string{"B", "H", "S", "D"} {
		source.WriteString("\tZUADDVD Z9." + width + ", P" + string(rune('0'+predicate)) + ", V10\n")
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64SVEAddReductionCompleteGo127Family(t *testing.T) {
	source := arm64SVEAddReductionCompleteForms()
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"sveaddreduceforms": {Name: "sveaddreduceforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve,+sve2p1"`,
				"@llvm.aarch64.sve.fadda.nxv8f16",
				"@llvm.aarch64.sve.fadda.nxv4f32",
				"@llvm.aarch64.sve.fadda.nxv2f64",
				"@llvm.aarch64.sve.faddv.nxv8f16",
				"@llvm.aarch64.sve.faddqv.v4f32.nxv4f32",
				"@llvm.aarch64.sve.saddv.nxv16i8",
				"@llvm.aarch64.sve.uaddv.nxv2i64",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE add reduction lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-add-reduction.ll", "arm64-sve-add-reduction.o", ll)
		})
	}
}

func TestTranslateARM64SVEAddReductionRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZFADDAH Z1.H, V2, P0, V3",
		"ZFADDAS Z1.B, V2, P0, V2",
		"ZFADDAD Z1.D, V2, P0.M, V2",
		"ZFADDVH Z1.B, P0, V2",
		"ZFADDVS Z1.S, P0.M, V2",
		"ZFADDVD Z1.D, P0, V2.D2",
		"ZFADDQV Z1.S, P0, V2.H8",
		"ZFADDQV Z1.D, P0, V2",
		"ZSADDVD Z1.D, P0, V2",
		"ZSADDVD Z1.S, P0.M, V2",
		"ZUADDVD Z1.Q, P0, V2",
		"ZUADDVD.Z Z1.D, P0, V2",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsveaddreduce(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsveaddreduce": {Name: "badsveaddreduce", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE add reduction forms", instruction)
			}
		})
	}
}
