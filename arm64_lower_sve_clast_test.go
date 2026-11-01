package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func arm64SVECLastCompleteForms() string {
	var source strings.Builder
	source.WriteString("TEXT sveclastforms(SB),$0-0\n")
	for _, selector := range []string{"A", "B"} {
		for _, width := range []string{"B", "H", "S", "D"} {
			fmt.Fprintf(&source, "\tZCLAST%s Z1.%s, Z2.%s, P0, Z2.%s\n", selector, width, width, width)
			fmt.Fprintf(&source, "\tZCLAST%s Z3.%s, R4, P1, R4\n", selector, width)
			fmt.Fprintf(&source, "\tZCLAST%sW Z5.%s, R6, P2, R6\n", selector, width)
			fmt.Fprintf(&source, "\tZCLAST%sB Z7.%s, V8, P3, V8\n", selector, width)
			fmt.Fprintf(&source, "\tZCLAST%sH Z9.%s, V10, P4, V10\n", selector, width)
			fmt.Fprintf(&source, "\tZCLAST%sS Z11.%s, V12, P5, V12\n", selector, width)
			fmt.Fprintf(&source, "\tZCLAST%sD Z13.%s, V14, P7, V14\n", selector, width)
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64SVECLastCompleteGo127Family(t *testing.T) {
	source := arm64SVECLastCompleteForms()
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"sveclastforms": {Name: "sveclastforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"\"target-features\"=\"+sve\"",
				"@llvm.aarch64.sve.clasta.nxv16i8",
				"@llvm.aarch64.sve.clasta.n.nxv8i16",
				"@llvm.aarch64.sve.clastb.nxv4i32",
				"@llvm.aarch64.sve.clastb.n.nxv2i64",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE CLAST lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-clast.ll", "arm64-sve-clast.o", ll)
		})
	}
}

func TestTranslateARM64SVECLastRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZCLASTA Z0.D, Z1.D, P0, Z2.D",
		"ZCLASTB Z0.D, R1, P0, R2",
		"ZCLASTAW Z0.S, V1, P0, V1",
		"ZCLASTBW Z0.S, RSP, P0, RSP",
		"ZCLASTAB Z0.B, R1, P0, R1",
		"ZCLASTBH Z0.H, V1, P8, V1",
		"ZCLASTAS Z0.S, V1, P0.M, V1",
		"ZCLASTBD Z0.Q, V1, P0, V1",
		"ZCLASTA.Z Z0.D, R1, P0, R1",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsveclast(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsveclast": {Name: "badsveclast", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE CLAST forms", instruction)
			}
		})
	}
}
