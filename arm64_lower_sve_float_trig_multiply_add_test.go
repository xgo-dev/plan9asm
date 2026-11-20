package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64SVEFloatTrigMultiplyAddCompleteGo127Family(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT svefloattrigmultiplyaddforms(SB),$0-0\n")
	for _, width := range []string{"H", "S", "D"} {
		for _, immediate := range []int{0, 7} {
			fmt.Fprintf(&source, "\tZFTMAD $%d, Z1.%s, Z2.%s, Z2.%s\n", immediate, width, width, width)
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
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svefloattrigmultiplyaddforms": {Name: "svefloattrigmultiplyaddforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"\"target-features\"=\"+sve\"",
				"@llvm.aarch64.sve.ftmad.x.nxv8f16",
				"@llvm.aarch64.sve.ftmad.x.nxv4f32",
				"@llvm.aarch64.sve.ftmad.x.nxv2f64",
				"i32 0",
				"i32 7",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE floating trigonometric multiply-add lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-float-trig-multiply-add.ll", "arm64-sve-float-trig-multiply-add.o", ll)
		})
	}
}

func TestTranslateARM64SVEFloatTrigMultiplyAddRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZFTMAD $-1, Z1.S, Z2.S, Z2.S",
		"ZFTMAD $8, Z1.S, Z2.S, Z2.S",
		"ZFTMAD $0, Z1.B, Z2.B, Z2.B",
		"ZFTMAD $0, Z1.H, Z2.S, Z2.S",
		"ZFTMAD $0, Z1.S, Z2.S, Z3.S",
		"ZFTMAD.Z $0, Z1.S, Z2.S, Z2.S",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvefloattrigmultiplyadd(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvefloattrigmultiplyadd": {Name: "badsvefloattrigmultiplyadd", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's ZFTMAD forms", instruction)
			}
		})
	}
}
