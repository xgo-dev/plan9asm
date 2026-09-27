package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64SVEDupWCompleteGo127Family(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT svedupw(SB),$0-0\n")
	for index, width := range []string{"B", "H", "S", "D"} {
		sourceReg := fmt.Sprintf("R%d", index+4)
		if width == "D" {
			sourceReg = "RSP"
		}
		fmt.Fprintf(&source, "\tZDUPW %s, Z%d.%s\n", sourceReg, index+16, width)
	}
	source.WriteString("\tRET\n")
	requireARM64SVEGoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svedupw": {Name: "svedupw", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve"`,
				"shufflevector <vscale x 16 x i8>",
				"shufflevector <vscale x 8 x i16>",
				"shufflevector <vscale x 4 x i32>",
				"shufflevector <vscale x 2 x i64>",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s ZDUPW lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-dupw.ll", "arm64-sve-dupw.o", ll)
		})
	}
}

func TestTranslateARM64SVEDupWRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZDUPW ZR, Z1.B",
		"ZDUPW R31, Z1.H",
		"ZDUPW R1, Z32.S",
		"ZDUPW R1, Z2.Q",
		"ZDUPW Z1.S, Z2.S",
		"ZDUPW.Z R1, Z2.D",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvedupw(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvedupw": {Name: "badsvedupw", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's ZDUPW forms", instruction)
			}
		})
	}
}
