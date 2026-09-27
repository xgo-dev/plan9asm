package plan9asm

import (
	"strings"
	"testing"
)

func arm64SVEClampCompleteForms() string {
	var source strings.Builder
	source.WriteString("TEXT sveclampforms(SB),$0-0\n")
	for _, op := range []string{"ZSCLAMP", "ZUCLAMP"} {
		for _, width := range []string{"B", "H", "S", "D"} {
			source.WriteString("\t" + op + " Z1." + width + ", Z2." + width + ", Z3." + width + "\n")
		}
	}
	for _, width := range []string{"H", "S", "D"} {
		source.WriteString("\tZFCLAMP Z1." + width + ", Z2." + width + ", Z3." + width + "\n")
	}
	source.WriteString("\tZBFCLAMP Z1.H, Z2.H, Z3.H\n")
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64SVEClampCompleteGo127Family(t *testing.T) {
	source := arm64SVEClampCompleteForms()
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"sveclampforms": {Name: "sveclampforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve,+sve-b16b16,+sve2p1"`,
				"@llvm.aarch64.sve.sclamp.nxv16i8",
				"@llvm.aarch64.sve.uclamp.nxv2i64",
				"@llvm.aarch64.sve.fclamp.nxv8f16",
				"@llvm.aarch64.sve.fclamp.nxv4f32",
				"@llvm.aarch64.sve.fclamp.nxv2f64",
				"@llvm.aarch64.sve.fclamp.nxv8bf16",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE clamp lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-clamp.ll", "arm64-sve-clamp.o", ll)
		})
	}
}

func TestTranslateARM64SVEClampRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZSCLAMP Z1.B, Z2.H, Z3.B",
		"ZUCLAMP Z1.Q, Z2.Q, Z3.Q",
		"ZFCLAMP Z1.B, Z2.B, Z3.B",
		"ZBFCLAMP Z1.S, Z2.S, Z3.S",
		"ZFCLAMP Z1.S, Z2.S",
		"ZSCLAMP.Z Z1.D, Z2.D, Z3.D",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsveclamp(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsveclamp": {Name: "badsveclamp", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE clamp forms", instruction)
			}
		})
	}
}
