package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64SVEComplexMultiplyAccumulateCompleteGo127Family(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT svecomplexmultiplyaccumulateforms(SB),$0-0\n")
	for _, op := range []string{"ZCMLA", "ZSQRDCMLAH"} {
		for _, rotation := range []int{0, 90, 180, 270} {
			for _, width := range []string{"B", "H", "S", "D"} {
				fmt.Fprintf(&source, "\t%s $%d, Z31.%s, Z2.%s, Z3.%s\n", op, rotation, width, width, width)
			}
			fmt.Fprintf(&source, "\t%s $%d, Z7.H[3], Z4.H, Z5.H\n", op, rotation)
			fmt.Fprintf(&source, "\t%s $%d, Z15.S[1], Z6.S, Z7.S\n", op, rotation)
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
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svecomplexmultiplyaccumulateforms": {Name: "svecomplexmultiplyaccumulateforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"\"target-features\"=\"+sve,+sve2\"",
				"@llvm.aarch64.sve.cmla.x.nxv16i8",
				"@llvm.aarch64.sve.cmla.lane.x.nxv8i16",
				"@llvm.aarch64.sve.sqrdcmlah.x.nxv2i64",
				"@llvm.aarch64.sve.sqrdcmlah.lane.x.nxv4i32",
				"i32 0",
				"i32 270",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE complex multiply-accumulate lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-complex-multiply-accumulate.ll", "arm64-sve-complex-multiply-accumulate.o", ll)
		})
	}
}

func TestTranslateARM64SVEComplexMultiplyAccumulateRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZCMLA $45, Z1.S, Z2.S, Z3.S",
		"ZSQRDCMLAH $0, Z1.H, Z2.S, Z3.S",
		"ZCMLA $0, Z8.H[0], Z2.H, Z3.H",
		"ZSQRDCMLAH $0, Z7.H[4], Z2.H, Z3.H",
		"ZCMLA $0, Z16.S[0], Z2.S, Z3.S",
		"ZSQRDCMLAH $0, Z15.S[2], Z2.S, Z3.S",
		"ZCMLA $0, Z1.D[0], Z2.D, Z3.D",
		"ZSQRDCMLAH.Z $0, Z1.S, Z2.S, Z3.S",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvecomplexmultiplyaccumulate(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvecomplexmultiplyaccumulate": {Name: "badsvecomplexmultiplyaccumulate", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE complex multiply-accumulate forms", instruction)
			}
		})
	}
}
