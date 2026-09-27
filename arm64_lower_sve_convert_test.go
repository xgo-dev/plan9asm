package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func arm64SVEConvertCompleteForms() string {
	forms := map[string][][2]string{
		"ZFCVT": {
			{"H", "S"}, {"H", "D"}, {"S", "H"}, {"S", "D"}, {"D", "H"}, {"D", "S"},
		},
		"ZFCVTZS": {
			{"H", "H"}, {"H", "S"}, {"H", "D"}, {"S", "S"}, {"S", "D"}, {"D", "S"}, {"D", "D"},
		},
		"ZFCVTZU": {
			{"H", "H"}, {"H", "S"}, {"H", "D"}, {"S", "S"}, {"S", "D"}, {"D", "S"}, {"D", "D"},
		},
		"ZSCVTF": {
			{"H", "H"}, {"S", "H"}, {"S", "S"}, {"S", "D"}, {"D", "H"}, {"D", "S"}, {"D", "D"},
		},
		"ZUCVTF": {
			{"H", "H"}, {"S", "H"}, {"S", "S"}, {"S", "D"}, {"D", "H"}, {"D", "S"}, {"D", "D"},
		},
		"ZFCVTLT":  {{"H", "S"}, {"S", "D"}},
		"ZFCVTX":   {{"D", "S"}},
		"ZFCVTXNT": {{"D", "S"}},
	}
	var source strings.Builder
	source.WriteString("TEXT sveconvertforms(SB),$0-0\n")
	register := 0
	for _, op := range []string{"ZFCVT", "ZFCVTZS", "ZFCVTZU", "ZSCVTF", "ZUCVTF", "ZFCVTLT", "ZFCVTX", "ZFCVTXNT"} {
		for _, widths := range forms[op] {
			for _, mode := range []string{"M", "Z"} {
				fmt.Fprintf(&source, "\t%s Z%d.%s, P7.%s, Z%d.%s\n", op, register%32, widths[0], mode, (register+1)%32, widths[1])
				register += 2
			}
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64SVEConvertCompleteGo127Family(t *testing.T) {
	source := arm64SVEConvertCompleteForms()
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"sveconvertforms": {Name: "sveconvertforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"\"target-features\"=\"+sve,+sve2p2\"",
				"@llvm.aarch64.sve.fcvt.f16f32",
				"@llvm.aarch64.sve.fcvt.f64f16",
				"@llvm.aarch64.sve.fcvtzs.i32f64",
				"@llvm.aarch64.sve.fcvtzu.i64f16",
				"@llvm.aarch64.sve.scvtf.f16i64",
				"@llvm.aarch64.sve.ucvtf.f64i32",
				"@llvm.aarch64.sve.fcvtlt.f32f16",
				"@llvm.aarch64.sve.fcvtx.f32f64",
				"@llvm.aarch64.sve.fcvtxnt.f32f64",
				"@llvm.aarch64.sve.fcvtxnt.z.f32f64",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE conversion lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-convert.ll", "arm64-sve-convert.o", ll)
		})
	}
}

func TestTranslateARM64SVEConvertRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZFCVT Z0.H, P0.M, Z1.H",
		"ZFCVT Z0.S, P0.M, Z1.S",
		"ZFCVT Z0.D, P0.M, Z1.D",
		"ZFCVTZS Z0.D, P0.M, Z1.H",
		"ZFCVTZU Z0.S, P0.M, Z1.H",
		"ZSCVTF Z0.H, P0.M, Z1.S",
		"ZUCVTF Z0.H, P0.M, Z1.D",
		"ZFCVTLT Z0.D, P0.M, Z1.S",
		"ZFCVTX Z0.S, P0.M, Z1.H",
		"ZFCVTXNT Z0.S, P0.M, Z1.D",
		"ZFCVT Z0.H, P8.M, Z1.S",
		"ZFCVT Z0.H, P0, Z1.S",
		"ZFCVT.Z Z0.H, P0.M, Z1.S",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsveconvert(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsveconvert": {Name: "badsveconvert", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE conversion forms", instruction)
			}
		})
	}
}
