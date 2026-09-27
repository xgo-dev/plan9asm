package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

const arm64ScalarFloatCompareForms = `
TEXT scalarfloatcompareforms(SB),$0-0
	FCMPS F3, F17
	FCMPS $(1.0), F8
	FCMPD F11, F27
	FCMPD $(0.0), F25
	FCMPES F16, F30
	FCMPES $(0.0), F29
	FCMPED F13, F10
	FCMPED $(0.0), F25
	RET
`

func TestTranslateARM64ScalarFloatCompareCompleteGoAssemblerForms(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64ScalarFloatCompareForms, true)
	file, err := Parse(ArchARM64, arm64ScalarFloatCompareForms)
	if err != nil {
		t.Fatal(err)
	}
	foundFloatImmediate := false
	for _, ins := range file.Funcs[0].Instrs {
		if ins.Op == "FCMPS" && len(ins.Args) == 2 && ins.Args[0].Kind == OpImm {
			foundFloatImmediate = ins.Args[0].ImmIsFloat
		}
	}
	if !foundFloatImmediate {
		t.Fatal("FCMP floating immediate was not preserved as C_FCON")
	}
	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"scalarfloatcompareforms": {Name: "scalarfloatcompareforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"fcmp oeq float", "fcmp uno float", "fcmp oeq double", "fcmp uno double"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("scalar floating compare lowering omitted %q:\n%s", want, ir)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-scalar-float-compare.ll", "arm64-scalar-float-compare.o", ir)
		})
	}
}

func TestTranslateARM64ScalarFloatCompareRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"FCMPS F0",
		"FCMPS R0, F1",
		"FCMPS F0, R1",
		"FCMPS $1, F1",
		"FCMPS $(1), F1",
		"FCMPD F0, F1, F2",
		"FCMPED.P F0, F1",
	} {
		t.Run(strings.NewReplacer(" ", "_", ",", "", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badscalarfloatcompare(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64GoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu",
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"badscalarfloatcompare": {Name: "badscalarfloatcompare", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's FCMP forms", instruction)
			}
		})
	}
}

func TestARM64ScalarFloatCompareRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT scalarfloatcompare(SB),$0-16
	FMOVS a+0(FP), F0
	FMOVS b+4(FP), F1
	MOVD out+8(FP), R2
	FCMPS F0, F1
	CSET MI, R3
	MOVD R3, 0(R2)
	CSET EQ, R3
	MOVD R3, 8(R2)
	CSET CS, R3
	MOVD R3, 16(R2)
	CSET VS, R3
	MOVD R3, 24(R2)
	FCMPES $(0.0), F1
	CSET MI, R3
	MOVD R3, 32(R2)
	CSET EQ, R3
	MOVD R3, 40(R2)
	CSET CS, R3
	MOVD R3, 48(R2)
	CSET VS, R3
	MOVD R3, 56(R2)
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ir, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       "arm64",
		Sigs: map[string]FuncSig{
			"scalarfloatcompare": {
				Name: "scalarfloatcompare", Args: []LLVMType{"float", "float", Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: "float", Index: 0, Field: -1},
					{Offset: 4, Type: "float", Index: 1, Field: -1},
					{Offset: 8, Type: Ptr, Index: 2, Field: -1},
				}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void scalarfloatcompare(float, float, uint64_t *);
int main(void) {
  uint64_t got[8] = {0};
  scalarfloatcompare(2.0f, 1.0f, got);
  const uint64_t want[8] = {1,0,0,0, 0,0,1,0};
  for (int i = 0; i < 8; i++) if (got[i] != want[i]) return i + 1;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_scalar_float_compare", triple, ir, mainC, nil)
}
