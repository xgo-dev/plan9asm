package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

const arm64ScalarFloatToIntegerForms = `
TEXT scalarfloattointegerforms(SB),$0-0
	FCVTZSD F0, R0
	FCVTZSDW F1, R1
	FCVTZSS F2, R2
	FCVTZSSW F3, R3
	FCVTZUD F4, R4
	FCVTZUDW F5, R5
	FCVTZUS F6, R6
	FCVTZUSW F7, ZR
	RET
`

func TestTranslateARM64ScalarFloatToIntegerCompleteGoAssemblerForms(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64ScalarFloatToIntegerForms, true)
	file, err := Parse(ArchARM64, arm64ScalarFloatToIntegerForms)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"scalarfloattointegerforms": {Name: "scalarfloattointegerforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"@llvm.fptosi.sat.i64.f64", "@llvm.fptosi.sat.i32.f64",
				"@llvm.fptosi.sat.i64.f32", "@llvm.fptosi.sat.i32.f32",
				"@llvm.fptoui.sat.i64.f64", "@llvm.fptoui.sat.i32.f64",
				"@llvm.fptoui.sat.i64.f32", "@llvm.fptoui.sat.i32.f32",
			} {
				if !strings.Contains(ir, want) {
					t.Fatalf("scalar float-to-integer lowering for %s omitted %s:\n%s", triple, want, ir)
				}
			}
			compileLLVMToObject(t, llc, triple, "scalar-float-to-integer.ll", "scalar-float-to-integer.o", ir)
		})
	}
}

func TestTranslateARM64ScalarFloatToIntegerRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, instruction := range []string{
		"FCVTZSS F0",
		"FCVTZSS F0, R1, R2",
		"FCVTZSS R0, R1",
		"FCVTZSS F0, F1",
		"FCVTZSS F0, RSP",
		"FCVTZUSW.P F0, R1",
	} {
		source := "TEXT badscalarfloattointeger(SB),$0-0\n\t" + instruction + "\n\tRET\n"
		requireARM64GoAssemblerResult(t, source, false)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			continue
		}
		if _, err := Translate(file, Options{
			TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64",
			Sigs: map[string]FuncSig{"badscalarfloattointeger": {Name: "badscalarfloattointeger", Ret: Void}},
		}); err == nil {
			t.Fatalf("Translate accepted %q outside Go 1.27's scalar float-to-integer family", instruction)
		}
	}
}

func TestARM64ScalarFloatToIntegerRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT scalarfloattointeger(SB),$0-24
	MOVD singles+0(FP), R0
	MOVD doubles+8(FP), R1
	MOVD output+16(FP), R2
	FMOVS 0(R0), F0
	FMOVS 4(R0), F1
	FMOVD 0(R1), F2
	FMOVD 8(R1), F3
	FCVTZSS F0, R3
	FCVTZSSW F1, R4
	FCVTZUS F1, R5
	FCVTZUSW F0, R6
	FCVTZSD F2, R7
	FCVTZSDW F3, R8
	FCVTZUD F3, R9
	FCVTZUDW F2, R10
	MOVD R3, 0(R2)
	MOVD R4, 8(R2)
	MOVD R5, 16(R2)
	MOVD R6, 24(R2)
	MOVD R7, 32(R2)
	MOVD R8, 40(R2)
	MOVD R9, 48(R2)
	MOVD R10, 56(R2)
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ir, err := Translate(file, Options{
		TargetTriple: triple, Goarch: "arm64",
		Sigs: map[string]FuncSig{"scalarfloattointeger": {
			Name: "scalarfloattointeger", Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void scalarfloattointeger(const float *, const double *, uint64_t *);
int main(void) {
  const float singles[2] = {7.75f, -3.75f};
  const double doubles[2] = {-9.5, 11.5};
  uint64_t got[8] = {0};
  const uint64_t want[8] = {7, UINT32_MAX - 2, 0, 7, UINT64_MAX - 8, 11, 11, 0};
  scalarfloattointeger(singles, doubles, got);
  for (int i = 0; i < 8; i++) if (got[i] != want[i]) return i + 1;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_scalar_float_to_integer", triple, ir, mainC, nil)
}
