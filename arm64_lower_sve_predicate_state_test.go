package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64SVEPredicateStateCompleteGo127Family(t *testing.T) {
	const source = "TEXT svepredicatestateforms(SB),$0-0\n\tPPFALSE P15.B\n\tPPTEST P14.B, P13\n\tPRDFFR P14.Z, P0.B\n\tPRDFFR P13.B\n\tPRDFFRS P12.Z, P1.B\n\tPWRFFR P11.B\n\tSETFFR\n\tRET\n"
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svepredicatestateforms": {Name: "svepredicatestateforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve"`,
				"store <vscale x 16 x i1> zeroinitializer",
				"@llvm.aarch64.sve.ptest.any.nxv16i1",
				"@llvm.aarch64.sve.ptest.first.nxv16i1",
				"@llvm.aarch64.sve.ptest.last.nxv16i1",
				"@llvm.aarch64.sve.rdffr()",
				"@llvm.aarch64.sve.rdffr.z(",
				"@llvm.aarch64.sve.wrffr(",
				"@llvm.aarch64.sve.setffr()",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE predicate state lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-predicate-state.ll", "arm64-sve-predicate-state.o", ll)
		})
	}
}

func TestTranslateARM64SVEPredicateStateRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"PPFALSE P1.H",
		"PPFALSE P16.B",
		"PPTEST P1.H, P2",
		"PPTEST P1.B, P2.Z",
		"PPTEST P1.B, P16",
		"PPTEST P1.B",
		"PRDFFR P1.H",
		"PRDFFR P1.M, P2.B",
		"PRDFFRS P1.B",
		"PWRFFR P1.H",
		"SETFFR R1",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvepredicatestate(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvepredicatestate": {Name: "badsvepredicatestate", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE predicate state forms", instruction)
			}
		})
	}
}
