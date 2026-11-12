package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64SVEMixedSaturatingAddCompleteGo127Family(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT svemixedsatadd(SB),$0-0\n")
	for opIndex, op := range []string{"ZSUQADD", "ZUSQADD"} {
		for widthIndex, width := range []string{"B", "H", "S", "D"} {
			destination := opIndex*4 + widthIndex
			fmt.Fprintf(&source, "\t%s Z%d.%s, Z%d.%s, P%d.M, Z%d.%s\n", op, destination+16, width, destination, width, widthIndex*2, destination, width)
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
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svemixedsatadd": {Name: "svemixedsatadd", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve,+sve2"`,
				"@llvm.aarch64.sve.suqadd.nxv16i8",
				"@llvm.aarch64.sve.suqadd.nxv2i64",
				"@llvm.aarch64.sve.usqadd.nxv16i8",
				"@llvm.aarch64.sve.usqadd.nxv2i64",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE mixed saturating add lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-mixed-saturating-add.ll", "arm64-sve-mixed-saturating-add.o", ll)
		})
	}
}

func TestTranslateARM64SVEMixedSaturatingAddRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZSUQADD Z1.B, Z2.H, P0.M, Z2.H",
		"ZSUQADD Z1.S, Z2.S, P8.M, Z2.S",
		"ZSUQADD Z1.S, Z2.S, P0.Z, Z2.S",
		"ZUSQADD Z1.D, Z2.D, P0.M, Z3.D",
		"ZUSQADD Z1.S, Z2.S, Z3.S",
		"ZUSQADD.Z Z1.D, Z2.D, P0.M, Z2.D",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvemixedsatadd(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvemixedsatadd": {Name: "badsvemixedsatadd", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's mixed saturating add forms", instruction)
			}
		})
	}
}
