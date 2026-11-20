package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func arm64SVEPredicateCounterCompleteForms() string {
	var source strings.Builder
	source.WriteString("TEXT svepredicatecountertrueforms(SB),$0-0\n")
	for index, width := range []string{"B", "H", "S", "D"} {
		fmt.Fprintf(&source, "\tPPTRUE PN%d.%s\n", 8+index, width)
		fmt.Fprintf(&source, "\tPCNTP P%d.%s, P%d, R%d\n", 15-index, width, 11-index, index)
		fmt.Fprintf(&source, "\tPCNTP VLx2, PN%d.%s, R%d\n", index, width, 4+index)
		fmt.Fprintf(&source, "\tPCNTP VLx4, PN%d.%s, R%d\n", 12+index, width, 8+index)
		fmt.Fprintf(&source, "\tPPEXT PN%d[%d], P%d.%s\n", 8+index, index, index, width)
		fmt.Fprintf(&source, "\tPPEXT PN%d[%d], [P%d.%s, P%d.%s]\n", 12+index, index%2, 2*index, width, 2*index+1, width)
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64SVEPredicateCounterCompleteGo127Family(t *testing.T) {
	source := arm64SVEPredicateCounterCompleteForms()
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svepredicatecountertrueforms": {Name: "svepredicatecountertrueforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve,+sve2p1"`,
				"@llvm.aarch64.sve.ptrue.c8",
				"@llvm.aarch64.sve.ptrue.c16",
				"@llvm.aarch64.sve.ptrue.c32",
				"@llvm.aarch64.sve.ptrue.c64",
				"@llvm.aarch64.sve.cntp.nxv16i1",
				"@llvm.aarch64.sve.cntp.nxv2i1",
				"@llvm.aarch64.sve.cntp.c8",
				"@llvm.aarch64.sve.cntp.c64",
				"@llvm.aarch64.sve.pext.nxv16i1",
				"@llvm.aarch64.sve.pext.nxv2i1",
				"@llvm.aarch64.sve.pext.x2.nxv8i1",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE predicate-as-counter true lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-predicate-counter.ll", "arm64-sve-predicate-counter.o", ll)
		})
	}
}

func TestTranslateARM64SVEPredicateCounterRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"PPTRUE P8.B",
		"PPTRUE PN7.B",
		"PPTRUE PN16.B",
		"PPTRUE PN8.Q",
		"PPTRUE PN8.B, PN9.B",
		"PCNTP P1.B, P2.Z, R3",
		"PCNTP VLx3, PN8.B, R3",
		"PCNTP VLx2, PN16.B, R3",
		"PCNTP VLx2, PN8.Q, R3",
		"PCNTP VLx2, PN8.B, R31",
		"PPEXT PN7[0], P1.B",
		"PPEXT PN8[4], P1.B",
		"PPEXT PN8[2], [P1.B, P2.B]",
		"PPEXT PN8[0], [P1.B, P3.B]",
		"PPEXT PN8[0], [P1.B, P2.H]",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvepredicatecounter(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvepredicatecounter": {Name: "badsvepredicatecounter", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's predicate-as-counter true forms", instruction)
			}
		})
	}
}
