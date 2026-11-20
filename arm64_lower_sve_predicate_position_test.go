package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func arm64SVEPredicatePositionCompleteForms() string {
	var source strings.Builder
	source.WriteString("TEXT svepredicatepositionforms(SB),$0-0\n")
	for index, width := range []string{"B", "H", "S", "D"} {
		fmt.Fprintf(&source, "\tPFIRSTP P%d.%s, P%d, R%d\n", 15-index, width, 11-index, index)
		fmt.Fprintf(&source, "\tPLASTP P%d.%s, P%d, R%d\n", 7-index, width, 3-index, 4+index)
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64SVEPredicatePositionCompleteGo127Family(t *testing.T) {
	source := arm64SVEPredicatePositionCompleteForms()
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svepredicatepositionforms": {Name: "svepredicatepositionforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve,+sve2p2"`,
				"@llvm.aarch64.sve.firstp.nxv16i1",
				"@llvm.aarch64.sve.firstp.nxv8i1",
				"@llvm.aarch64.sve.lastp.nxv4i1",
				"@llvm.aarch64.sve.lastp.nxv2i1",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE predicate position lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-predicate-position.ll", "arm64-sve-predicate-position.o", ll)
		})
	}
}

func TestTranslateARM64SVEPredicatePositionRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"PFIRSTP P1.Q, P2, R3",
		"PFIRSTP P1.B, P2.Z, R3",
		"PFIRSTP P16.B, P2, R3",
		"PLASTP P1.B, P16, R3",
		"PLASTP P1.B, P2, R31",
		"PLASTP P1.B, P2",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvepredicateposition(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvepredicateposition": {Name: "badsvepredicateposition", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE predicate position forms", instruction)
			}
		})
	}
}
