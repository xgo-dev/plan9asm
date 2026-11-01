package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64SVESaturatingRoundingMultiplyAccumulateHighCompleteGo127Family(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT svesaturatingroundingmultiplyaccumulatehighforms(SB),$0-0\n")
	for _, op := range []string{"ZSQRDMLAH", "ZSQRDMLSH"} {
		for _, width := range []string{"B", "H", "S", "D"} {
			fmt.Fprintf(&source, "\t%s Z1.%s, Z2.%s, Z3.%s\n", op, width, width, width)
		}
		for index, width := range []string{"H", "S", "D"} {
			maximumVector := []int{7, 7, 15}[index]
			maximumLane := []int{7, 3, 1}[index]
			fmt.Fprintf(&source, "\t%s Z%d.%s[%d], Z4.%s, Z5.%s\n", op, maximumVector, width, maximumLane, width, width)
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
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svesaturatingroundingmultiplyaccumulatehighforms": {Name: "svesaturatingroundingmultiplyaccumulatehighforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"\"target-features\"=\"+sve,+sve2\"",
				"@llvm.aarch64.sve.sqrdmlah.nxv16i8",
				"@llvm.aarch64.sve.sqrdmlah.lane.nxv8i16",
				"@llvm.aarch64.sve.sqrdmlsh.nxv2i64",
				"@llvm.aarch64.sve.sqrdmlsh.lane.nxv4i32",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE saturating rounding multiply-accumulate-high lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-saturating-rounding-multiply-accumulate-high.ll", "arm64-sve-saturating-rounding-multiply-accumulate-high.o", ll)
		})
	}
}

func TestTranslateARM64SVESaturatingRoundingMultiplyAccumulateHighRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZSQRDMLAH Z1.B, Z2.H, Z3.H",
		"ZSQRDMLSH Z1.B[0], Z2.B, Z3.B",
		"ZSQRDMLAH Z8.H[0], Z2.H, Z3.H",
		"ZSQRDMLSH Z7.H[8], Z2.H, Z3.H",
		"ZSQRDMLAH Z7.S[3], Z2.D, Z3.D",
		"ZSQRDMLSH.Z Z1.S, Z2.S, Z3.S",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvesaturatingroundingmultiplyaccumulatehigh(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvesaturatingroundingmultiplyaccumulatehigh": {Name: "badsvesaturatingroundingmultiplyaccumulatehigh", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE saturating rounding multiply-accumulate-high forms", instruction)
			}
		})
	}
}
