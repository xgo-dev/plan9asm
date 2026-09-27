package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func arm64SVEPredicateIterateCompleteForms() string {
	var source strings.Builder
	source.WriteString("TEXT svepredicateiterateforms(SB),$0-0\n")
	source.WriteString("\tPPFIRST P15.B, P14, P15.B\n")
	for index, width := range []string{"B", "H", "S", "D"} {
		fmt.Fprintf(&source, "\tPPNEXT P%d.%s, P%d, P%d.%s\n", 13-index, width, 9-index, 13-index, width)
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64SVEPredicateIterateCompleteGo127Family(t *testing.T) {
	source := arm64SVEPredicateIterateCompleteForms()
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svepredicateiterateforms": {Name: "svepredicateiterateforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve"`,
				"@llvm.aarch64.sve.pfirst.nxv16i1",
				"@llvm.aarch64.sve.pnext.nxv16i1",
				"@llvm.aarch64.sve.pnext.nxv8i1",
				"@llvm.aarch64.sve.pnext.nxv4i1",
				"@llvm.aarch64.sve.pnext.nxv2i1",
				"@llvm.aarch64.sve.ptest.any.nxv16i1",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE predicate iterate lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-predicate-iterate.ll", "arm64-sve-predicate-iterate.o", ll)
		})
	}
}

func TestTranslateARM64SVEPredicateIterateRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"PPFIRST P1.H, P2, P1.H",
		"PPFIRST P1.B, P2.Z, P1.B",
		"PPFIRST P1.B, P2, P3.B",
		"PPNEXT P1.B, P2.Z, P1.B",
		"PPNEXT P1.B, P2, P3.B",
		"PPNEXT P1.B, P2",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvepredicateiterate(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvepredicateiterate": {Name: "badsvepredicateiterate", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE predicate iterate forms", instruction)
			}
		})
	}
}
