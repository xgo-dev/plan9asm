package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64SVEBFDOTCompleteGo127Family(t *testing.T) {
	source := "TEXT svebfdotforms(SB),$0-0\n" +
		"\tZBFDOT Z1.H, Z2.H, Z3.S\n" +
		"\tZBFDOT Z0.H[0], Z2.H, Z3.S\n" +
		"\tZBFDOT Z7.H[3], Z2.H, Z3.S\n" +
		"\tRET\n"
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svebfdotforms": {Name: "svebfdotforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"\"target-features\"=\"+bf16,+sve\"",
				"@llvm.aarch64.sve.bfdot(",
				"@llvm.aarch64.sve.bfdot.lane.v2(",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE BFDOT lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-bfdot.ll", "arm64-sve-bfdot.o", ll)
		})
	}
}

func TestTranslateARM64SVEBFDOTRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZBFDOT Z1.B, Z2.B, Z3.S",
		"ZBFDOT Z1.H, Z2.H, Z3.H",
		"ZBFDOT Z1.H[0], Z2.S, Z3.S",
		"ZBFDOT Z8.H[0], Z2.H, Z3.S",
		"ZBFDOT Z7.H[4], Z2.H, Z3.S",
		"ZBFDOT Z1.H, Z2.H",
		"ZBFDOT.Z Z1.H, Z2.H, Z3.S",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvebfdot(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvebfdot": {Name: "badsvebfdot", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE BFDOT forms", instruction)
			}
		})
	}
}
