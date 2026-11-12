package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64SVEMultiplyAccumulateCompleteGo127Family(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT svemultiplyaccumulateforms(SB),$0-0\n")
	for _, op := range []string{"ZMLA", "ZMLS"} {
		for index, width := range []string{"B", "H", "S", "D"} {
			fmt.Fprintf(&source, "\t%s Z1.%s, Z2.%s, P%d.M, Z3.%s\n", op, width, width, index, width)
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
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svemultiplyaccumulateforms": {Name: "svemultiplyaccumulateforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"\"target-features\"=\"+sve,+sve2\"",
				"@llvm.aarch64.sve.mla.nxv16i8",
				"@llvm.aarch64.sve.mla.lane.nxv8i16",
				"@llvm.aarch64.sve.mls.nxv2i64",
				"@llvm.aarch64.sve.mls.lane.nxv4i32",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE multiply-accumulate lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-multiply-accumulate.ll", "arm64-sve-multiply-accumulate.o", ll)
		})
	}
}

func TestTranslateARM64SVEMultiplyAccumulateRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZMLA Z1.B, Z2.H, P0.M, Z3.H",
		"ZMLS Z1.S, Z2.S, P0, Z3.S",
		"ZMLA Z1.D, Z2.D, P8.M, Z3.D",
		"ZMLS Z1.B[0], Z2.B, Z3.B",
		"ZMLA Z8.H[0], Z2.H, Z3.H",
		"ZMLS Z7.H[8], Z2.H, Z3.H",
		"ZMLA Z7.S[3], Z2.D, Z3.D",
		"ZMLS.Z Z1.S, Z2.S, P0.M, Z3.S",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvemultiplyaccumulate(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvemultiplyaccumulate": {Name: "badsvemultiplyaccumulate", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE multiply-accumulate forms", instruction)
			}
		})
	}
}
