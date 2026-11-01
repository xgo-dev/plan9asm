package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64SVEFloatComplexMultiplyAccumulateCompleteGo127Family(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT svefloatcomplexmultiplyaccumulateforms(SB),$0-0\n")
	for _, rotation := range []int{0, 90, 180, 270} {
		for _, width := range []string{"H", "S", "D"} {
			fmt.Fprintf(&source, "\tZFCMLA $%d, Z31.%s, Z2.%s, P7.M, Z3.%s\n", rotation, width, width, width)
		}
		fmt.Fprintf(&source, "\tZFCMLA $%d, Z7.H[3], Z4.H, Z5.H\n", rotation)
		fmt.Fprintf(&source, "\tZFCMLA $%d, Z15.S[1], Z6.S, Z7.S\n", rotation)
	}
	source.WriteString("\tRET\n")
	requireARM64SVEGoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svefloatcomplexmultiplyaccumulateforms": {Name: "svefloatcomplexmultiplyaccumulateforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"\"target-features\"=\"+sve\"",
				"@llvm.aarch64.sve.fcmla.nxv8f16",
				"@llvm.aarch64.sve.fcmla.nxv2f64",
				"@llvm.aarch64.sve.fcmla.lane.nxv8f16",
				"@llvm.aarch64.sve.fcmla.lane.nxv4f32",
				"i32 0",
				"i32 270",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE floating complex multiply-accumulate lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-float-complex-multiply-accumulate.ll", "arm64-sve-float-complex-multiply-accumulate.o", ll)
		})
	}
}

func TestTranslateARM64SVEFloatComplexMultiplyAccumulateRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZFCMLA $45, Z1.S, Z2.S, P0.M, Z3.S",
		"ZFCMLA $0, Z1.B, Z2.B, P0.M, Z3.B",
		"ZFCMLA $0, Z1.H, Z2.S, P0.M, Z3.S",
		"ZFCMLA $0, Z1.S, Z2.S, P8.M, Z3.S",
		"ZFCMLA $0, Z8.H[0], Z2.H, Z3.H",
		"ZFCMLA $0, Z7.H[4], Z2.H, Z3.H",
		"ZFCMLA $0, Z16.S[0], Z2.S, Z3.S",
		"ZFCMLA $0, Z15.S[2], Z2.S, Z3.S",
		"ZFCMLA $0, Z1.D[0], Z2.D, Z3.D",
		"ZFCMLA.Z $0, Z1.S, Z2.S, P0.M, Z3.S",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvefloatcomplexmultiplyaccumulate(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvefloatcomplexmultiplyaccumulate": {Name: "badsvefloatcomplexmultiplyaccumulate", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's ZFCMLA forms", instruction)
			}
		})
	}
}
