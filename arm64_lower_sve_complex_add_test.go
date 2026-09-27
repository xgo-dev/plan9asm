package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64SVEComplexAddCompleteGo127Family(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT svecomplexadd(SB),$0-0\n")
	for opIndex, op := range []string{"ZCADD", "ZSQCADD"} {
		for widthIndex, width := range []string{"B", "H", "S", "D"} {
			for rotationIndex, rotation := range []int{90, 270} {
				destination := opIndex*8 + widthIndex*2 + rotationIndex
				fmt.Fprintf(&source, "\t%s $%d, Z%d.%s, Z%d.%s, Z%d.%s\n", op, rotation, (destination+1)%32, width, destination, width, destination, width)
			}
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
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svecomplexadd": {Name: "svecomplexadd", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve,+sve2"`,
				"@llvm.aarch64.sve.cadd.x.nxv16i8",
				"@llvm.aarch64.sve.cadd.x.nxv2i64",
				"@llvm.aarch64.sve.sqcadd.x.nxv8i16",
				"@llvm.aarch64.sve.sqcadd.x.nxv4i32",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE complex-add lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-complex-add.ll", "arm64-sve-complex-add.o", ll)
		})
	}
}

func TestTranslateARM64SVEComplexAddRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZCADD $0, Z1.B, Z2.B, Z2.B",
		"ZCADD $180, Z1.H, Z2.H, Z2.H",
		"ZSQCADD $91, Z1.S, Z2.S, Z2.S",
		"ZSQCADD $270, Z1.D, Z2.S, Z2.S",
		"ZCADD $90, Z1.S, Z2.S, Z3.S",
		"ZSQCADD.Z $270, Z1.D, Z2.D, Z2.D",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvecomplexadd(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvecomplexadd": {Name: "badsvecomplexadd", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's complex-add forms", instruction)
			}
		})
	}
}
