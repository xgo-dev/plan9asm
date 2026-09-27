package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

func TestTranslateARM64FloatConditionalCompareCompleteGo127Forms(t *testing.T) {
	const source = `TEXT floatConditionalCompareForms(SB), $0-0
	CMP R0, R0
	FCCMPS LE, F17, F12, $14
	FCCMPD HI, F11, F15, $15
	FCCMPES EQ, F1, F2, $0
	FCCMPED NE, F3, F4, $9
	FCCMPS AL, F31, F5, $5
	FCCMPD AL, F0, F9, $0
	FCCMPES AL, F7, F14, $1
	FCCMPED AL, F0, F14, $11
	FCCMPS NV, F6, F8, $3
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
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
					"floatConditionalCompareForms": {Name: "floatConditionalCompareForms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"fcmp oeq float", "fcmp uno float", "fcmp oeq double", "fcmp uno double", "select i1"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("floating conditional compare lowering omitted %q:\n%s", want, ir)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-float-conditional-compare.ll", "arm64-float-conditional-compare.o", ir)
		})
	}
}

func TestTranslateARM64FloatConditionalCompareRejectsFormsOutsideGo127Optab(t *testing.T) {
	for _, instruction := range []string{
		"FCCMPD EQ, F0, F1",
		"FCCMPD BAD, F0, F1, $0",
		"FCCMPD EQ, R0, F1, $0",
		"FCCMPD EQ, F0, R1, $0",
		"FCCMPD EQ, F0, F1, $16",
		"FCCMPD EQ, F0, F1, R0",
		"FCCMPD.P EQ, F0, F1, $0",
	} {
		t.Run(strings.NewReplacer(" ", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badFloatConditionalCompare(SB), $0-0\n\tCMP R0, R0\n\t" + instruction + "\n\tRET\n"
			requireARM64GoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu",
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"badFloatConditionalCompare": {Name: "badFloatConditionalCompare", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's FCCMP optab", instruction)
			}
		})
	}
}

func TestARM64FloatConditionalCompareRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT floatConditionalCompareRuntime(SB), $0-24
	FMOVD a+0(FP), F0
	FMOVD b+8(FP), F1
	MOVD out+16(FP), R2
	CMP R0, R0
	FCCMPD EQ, F0, F1, $0
	CSET MI, R3
	MOVD R3, 0(R2)
	CSET EQ, R3
	MOVD R3, 8(R2)
	CSET CS, R3
	MOVD R3, 16(R2)
	CSET VS, R3
	MOVD R3, 24(R2)
	CMP R0, R0
	FCCMPED NE, F0, F1, $10
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
			"floatConditionalCompareRuntime": {
				Name: "floatConditionalCompareRuntime", Args: []LLVMType{"double", "double", Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: "double", Index: 0, Field: -1},
					{Offset: 8, Type: "double", Index: 1, Field: -1},
					{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void floatConditionalCompareRuntime(double, double, uint64_t *);
int main(void) {
  uint64_t got[8] = {0};
  floatConditionalCompareRuntime(2.0, 1.0, got);
  const uint64_t want[8] = {1, 0, 0, 0, 1, 0, 1, 0};
  for (int i = 0; i < 8; i++) if (got[i] != want[i]) return i + 1;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_float_conditional_compare", triple, ir, mainC, nil)
}
