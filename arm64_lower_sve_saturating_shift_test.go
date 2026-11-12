package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64SVESaturatingShiftCompleteGo127Family(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT svesaturatingshiftforms(SB),$0-0\n")
	for _, op := range []string{"ZSQSHL", "ZUQSHL"} {
		for index, width := range []string{"B", "H", "S", "D"} {
			maximum := []int{7, 15, 31, 63}[index]
			fmt.Fprintf(&source, "\t%s Z1.%s, Z2.%s, P%d.M, Z2.%s\n", op, width, width, index, width)
			fmt.Fprintf(&source, "\t%s $0, Z3.%s, P%d.M, Z3.%s\n", op, width, index, width)
			fmt.Fprintf(&source, "\t%s $%d, Z4.%s, P%d.M, Z4.%s\n", op, maximum, width, index, width)
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
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svesaturatingshiftforms": {Name: "svesaturatingshiftforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"\"target-features\"=\"+sve,+sve2\"",
				"@llvm.aarch64.sve.sqshl.nxv",
				"@llvm.aarch64.sve.uqshl.nxv",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE saturating-shift lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-saturating-shift.ll", "arm64-sve-saturating-shift.o", ll)
		})
	}
}

func TestTranslateARM64SVESaturatingShiftRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZSQSHL $-1, Z1.B, P0.M, Z1.B",
		"ZUQSHL $8, Z1.B, P0.M, Z1.B",
		"ZSQSHL $16, Z1.H, P0.M, Z1.H",
		"ZUQSHL Z1.S, Z2.H, P0.M, Z2.H",
		"ZSQSHL Z1.S, Z2.S, P0, Z2.S",
		"ZUQSHL Z1.S, Z2.S, P8.M, Z2.S",
		"ZSQSHL Z1.S, Z2.S, P0.M, Z3.S",
		"ZUQSHL.Z Z1.S, Z2.S, P0.M, Z2.S",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvesaturatingshift(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvesaturatingshift": {Name: "badsvesaturatingshift", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE saturating-shift forms", instruction)
			}
		})
	}
}
