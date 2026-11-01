package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func arm64SVEPredicatePermuteCompleteForms() string {
	var source strings.Builder
	source.WriteString("TEXT svepredicatepermuteforms(SB),$0-0\n")
	for _, width := range []string{"B", "H", "S", "D"} {
		fmt.Fprintf(&source, "\tPREV P15.%s, P14.%s\n", width, width)
		for _, op := range []string{"PTRN1", "PTRN2", "PUZP1", "PUZP2", "PZIP1", "PZIP2"} {
			fmt.Fprintf(&source, "\t%s P13.%s, P12.%s, P11.%s\n", op, width, width, width)
		}
	}
	source.WriteString("\tPPUNPKHI P10.B, P9.H\n")
	source.WriteString("\tPPUNPKLO P8.B, P7.H\n")
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64SVEPredicatePermuteCompleteGo127Family(t *testing.T) {
	source := arm64SVEPredicatePermuteCompleteForms()
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svepredicatepermuteforms": {Name: "svepredicatepermuteforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve"`,
				"@llvm.vector.reverse.nxv16i1",
				"@llvm.aarch64.sve.rev.b16",
				"@llvm.aarch64.sve.trn1.nxv16i1",
				"@llvm.aarch64.sve.trn2.b64",
				"@llvm.aarch64.sve.uzp1.b32",
				"@llvm.aarch64.sve.zip2.b16",
				"@llvm.aarch64.sve.punpkhi.nxv16i1",
				"@llvm.aarch64.sve.punpklo.nxv16i1",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE predicate permute lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-predicate-permute.ll", "arm64-sve-predicate-permute.o", ll)
		})
	}
}

func TestTranslateARM64SVEPredicatePermuteRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"PREV P1.B, P2.H",
		"PTRN1 P1.B, P2.H, P3.B",
		"PUZP2 P1.B, P2.B, P16.B",
		"PZIP1 P1.B, P2.B",
		"PPUNPKHI P1.H, P2.H",
		"PPUNPKLO P1.B, P2.S",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvepredicatepermute(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvepredicatepermute": {Name: "badsvepredicatepermute", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE predicate permute forms", instruction)
			}
		})
	}
}
