package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64SVEMultiplyHighCompleteGo127Family(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT svemulhighforms(SB),$0-0\n")
	for _, op := range []string{"ZSMULH", "ZUMULH"} {
		for index, width := range []string{"B", "H", "S", "D"} {
			fmt.Fprintf(&source, "\t%s Z1.%s, Z2.%s, P%d.M, Z2.%s\n", op, width, width, index, width)
			fmt.Fprintf(&source, "\t%s Z3.%s, Z4.%s, Z5.%s\n", op, width, width, width)
		}
	}
	source.WriteString("\tRET\n")
	requireARM64SVEGoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svemulhighforms": {Name: "svemulhighforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"\"target-features\"=\"+sve,+sve2\"",
				"@llvm.aarch64.sve.smulh.nxv",
				"@llvm.aarch64.sve.smulh.u.nxv",
				"@llvm.aarch64.sve.umulh.nxv",
				"@llvm.aarch64.sve.umulh.u.nxv",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE multiply-high lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-mul-high.ll", "arm64-sve-mul-high.o", ll)
		})
	}
}

func TestTranslateARM64SVEMultiplyHighRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZSMULH Z1.S, Z2.S, P0, Z2.S",
		"ZUMULH Z1.S, Z2.S, P8.M, Z2.S",
		"ZSMULH Z1.S, Z2.S, P0.M, Z3.S",
		"ZUMULH Z1.H, Z2.S, Z3.S",
		"ZSMULH Z1.S, Z2.S",
		"ZUMULH.Z Z1.S, Z2.S, Z3.S",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvemulhigh(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvemulhigh": {Name: "badsvemulhigh", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE multiply-high forms", instruction)
			}
		})
	}
}
