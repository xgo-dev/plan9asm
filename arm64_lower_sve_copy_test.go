package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func arm64SVECopyCompleteForms() string {
	var source strings.Builder
	source.WriteString("TEXT svecopyforms(SB),$0-0\n")
	register := 0
	for _, mode := range []string{"M", "Z"} {
		for _, width := range []string{"B", "H", "S", "D"} {
			for _, immediate := range []int{-128, 127, -32768, 32512} {
				fmt.Fprintf(&source, "\tZCPY $%d, P15.%s, Z%d.%s\n", immediate, mode, register%32, width)
				register++
			}
		}
	}
	for _, op := range []string{"ZCPY", "ZCPYW"} {
		for widthIndex, width := range []string{"B", "H", "S", "D"} {
			sourceReg := "R20"
			if widthIndex%2 != 0 {
				sourceReg = "RSP"
			}
			fmt.Fprintf(&source, "\t%s %s, P7.M, Z%d.%s\n", op, sourceReg, register%32, width)
			register++
		}
	}
	for _, op := range []string{"ZCPYB", "ZCPYH", "ZCPYS", "ZCPYD"} {
		for _, width := range []string{"B", "H", "S", "D"} {
			fmt.Fprintf(&source, "\t%s V%d, P7.M, Z%d.%s\n", op, register%32, register%32, width)
			register++
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64SVECopyCompleteGo127Family(t *testing.T) {
	source := arm64SVECopyCompleteForms()
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svecopyforms": {Name: "svecopyforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"\"target-features\"=\"+sve\"",
				"insertelement <vscale x 16 x i8>",
				"insertelement <vscale x 8 x i16>",
				"insertelement <vscale x 4 x i32>",
				"insertelement <vscale x 2 x i64>",
				"select <vscale x 16 x i1>",
				"select <vscale x 8 x i1>",
				"select <vscale x 4 x i1>",
				"select <vscale x 2 x i1>",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE CPY lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-copy.ll", "arm64-sve-copy.o", ll)
		})
	}
}

func TestTranslateARM64SVECopyRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZCPY $-33024, P0.M, Z0.B",
		"ZCPY $-129, P0.M, Z0.B",
		"ZCPY $128, P0.M, Z0.B",
		"ZCPY $32768, P0.M, Z0.B",
		"ZCPY $1, P0, Z0.B",
		"ZCPY $1, P16.M, Z0.B",
		"ZCPY $1, P0.M, Z0.Q",
		"ZCPY R0, P8.M, Z0.D",
		"ZCPY ZR, P0.M, Z0.D",
		"ZCPYW ZR, P0.M, Z0.S",
		"ZCPYB V0, P8.M, Z0.B",
		"ZCPYB R0, P0.M, Z0.B",
		"ZCPYD V0, P0.Z, Z0.D",
		"ZCPY.Z $1, P0.M, Z0.B",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvecopy(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvecopy": {Name: "badsvecopy", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE CPY forms", instruction)
			}
		})
	}
}
