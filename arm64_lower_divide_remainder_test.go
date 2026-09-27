package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

const arm64DivideRemainderForms = `
TEXT divideremainderforms(SB),$0-0
	SDIV R0, R1
	SDIV R2, R3, R4
	SDIVW R5, R6
	SDIVW R7, R8, R9
	UDIV R10, R11
	UDIV R12, R13, R14
	UDIVW R15, R16
	UDIVW R17, R19, R20
	REM R21, R22
	REM R23, R24, R25
	REMW R26, R27
	REMW R10, R11, R12
	UREM R0, R1
	UREM R2, R3, R4
	UREMW R5, R6
	UREMW R7, R8, ZR
	RET
`

func TestTranslateARM64DivideRemainderCompleteGoAssemblerForms(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64DivideRemainderForms, true)
	file, err := Parse(ArchARM64, arm64DivideRemainderForms)
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
				TargetTriple: triple, Goarch: "arm64",
				Sigs: map[string]FuncSig{"divideremainderforms": {Name: "divideremainderforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"sdiv i64", "sdiv i32", "udiv i64", "udiv i32", "srem i64", "srem i32", "urem i64", "urem i32"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("divide/remainder family for %s omitted %q:\n%s", triple, want, ir)
				}
			}
			compileLLVMToObject(t, llc, triple, "arm64-divide-remainder.ll", "arm64-divide-remainder.o", ir)
		})
	}
}

func TestTranslateARM64DivideRemainderRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, instruction := range []string{
		"SDIV R0",
		"SDIV R0, R1, R2, R3",
		"SDIV $2, R0",
		"UDIV (R0), R1",
		"REM R0, RSP",
		"UREMW.P R0, R1",
	} {
		source := "TEXT baddivideremainder(SB),$0-0\n\t" + instruction + "\n\tRET\n"
		requireARM64GoAssemblerResult(t, source, false)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			continue
		}
		if _, err := Translate(file, Options{
			TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64",
			Sigs: map[string]FuncSig{"baddivideremainder": {Name: "baddivideremainder", Ret: Void}},
		}); err == nil {
			t.Fatalf("Translate accepted %q outside Go 1.27's divide/remainder optab", instruction)
		}
	}
}

func TestARM64DivideRemainderRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT divideremainder(SB),$0-16
	MOVD input+0(FP), R10
	MOVD output+8(FP), R11
	MOVD 0(R10), R0
	MOVD 8(R10), R1
	MOVD 16(R10), R2
	MOVD 24(R10), R3
	MOVD 32(R10), R4
	MOVD 40(R10), R5
	MOVD 48(R10), R23
	SDIV R1, R0, R6
	SDIVW R1, R0, R7
	UDIV R3, R2, R8
	UDIVW R3, R2, R9
	REM R1, R0, R12
	REMW R1, R0, R13
	UREM R3, R2, R14
	UREMW R3, R2, R15
	SDIV ZR, R0, R16
	UDIV ZR, R2, R17
	REM ZR, R0, R19
	UREM ZR, R2, R20
	SDIV R5, R4, R21
	SDIVW R5, R23, R22
	MOVD R6, 0(R11)
	MOVD R7, 8(R11)
	MOVD R8, 16(R11)
	MOVD R9, 24(R11)
	MOVD R12, 32(R11)
	MOVD R13, 40(R11)
	MOVD R14, 48(R11)
	MOVD R15, 56(R11)
	MOVD R16, 64(R11)
	MOVD R17, 72(R11)
	MOVD R19, 80(R11)
	MOVD R20, 88(R11)
	MOVD R21, 96(R11)
	MOVD R22, 104(R11)
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
		Sigs: map[string]FuncSig{"divideremainder": {
			Name: "divideremainder", Args: []LLVMType{Ptr, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
#include <limits.h>
extern void divideremainder(const uint64_t *, uint64_t *);
int main(void) {
  const uint64_t input[7] = {
    (uint64_t)-9, 2, 9, 2,
    UINT64_C(0x8000000000000000), UINT64_MAX, UINT64_C(0x80000000)
  };
  const uint64_t want[14] = {
    (uint64_t)-4, UINT32_C(0xfffffffc), 4, 4,
    UINT64_MAX, UINT32_MAX, 1, 1,
    0, 0, (uint64_t)-9, 9,
    UINT64_C(0x8000000000000000), UINT32_C(0x80000000)
  };
  uint64_t got[14] = {0};
  divideremainder(input, got);
  for (int i = 0; i < 14; i++) if (got[i] != want[i]) return i + 1;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_divide_remainder", triple, ir, mainC, nil)
}
