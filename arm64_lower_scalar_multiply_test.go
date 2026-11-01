package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

func TestTranslateARM64ScalarMultiplyCompleteGo127Forms(t *testing.T) {
	const source = `TEXT scalarMultiplyForms(SB), $0-0
	MNEG R0, R1
	MNEG R0, R1, R2
	MNEGW R3, R4
	MNEGW R3, R4, R5
	SMULL R6, R7
	SMULL R6, R7, R8
	UMULL R9, R10
	UMULL R9, R10, R11
	SMNEGL R12, R13
	SMNEGL R12, R13, R14
	UMNEGL R15, R16
	UMNEGL R15, R16, R17
	SMULH R17, R19
	SMULH R17, R19, R20
	UMULH R21, R22
	UMULH R21, R22, R23
	SMADDL R0, R1, R2, R3
	SMSUBL R4, R5, R6, R7
	UMADDL R8, R9, R10, R11
	UMSUBL R12, R13, R14, R15
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"scalarMultiplyForms": {Name: "scalarMultiplyForms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"sext i32", "zext i32", "sext i64", "zext i64", "mul i128", "lshr i128", "sub i64", "add i64"} {
				if !strings.Contains(ll, want) {
					t.Fatalf("scalar multiply lowering for %s omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-scalar-multiply.ll", "arm64-scalar-multiply.o", ll)
		})
	}
}

func TestTranslateARM64ScalarMultiplyRejectsFormsOutsideGo127Optab(t *testing.T) {
	for _, instruction := range []string{
		"UMULL R0",
		"UMULL $1, R0",
		"SMULL R0, R1, R2, R3",
		"SMULH R0, (R1)",
		"UMULH.P R0, R1, R2",
		"SMADDL R0, R1, R2",
		"UMSUBL R0, R1, R2, (R3)",
		"MNEG R0",
		"MNEGW $1, R0",
	} {
		t.Run(strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			source := "TEXT badScalarMultiply(SB), $0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64GoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu",
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"badScalarMultiply": {Name: "badScalarMultiply", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's scalar multiply optab", instruction)
			}
		})
	}
}

func TestARM64ScalarMultiplyRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT scalarMultiplyRuntime(SB), $0-32
	MOVD a+0(FP), R0
	MOVD b+8(FP), R1
	MOVD add+16(FP), R2
	MOVD out+24(FP), R3
	UMULL R0, R1, R4
	MOVD R4, 0(R3)
	SMULL R0, R1, R4
	MOVD R4, 8(R3)
	UMNEGL R0, R1, R4
	MOVD R4, 16(R3)
	SMNEGL R0, R1, R4
	MOVD R4, 24(R3)
	UMULH R0, R1, R4
	MOVD R4, 32(R3)
	SMULH R0, R1, R4
	MOVD R4, 40(R3)
	UMADDL R0, R2, R1, R4
	MOVD R4, 48(R3)
	UMSUBL R0, R2, R1, R4
	MOVD R4, 56(R3)
	SMADDL R0, R2, R1, R4
	MOVD R4, 64(R3)
	SMSUBL R0, R2, R1, R4
	MOVD R4, 72(R3)
	MNEG R0, R1, R4
	MOVD R4, 80(R3)
	MNEGW R0, R1, R4
	MOVD R4, 88(R3)
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ll, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       "arm64",
		Sigs: map[string]FuncSig{
			"scalarMultiplyRuntime": {
				Name: "scalarMultiplyRuntime", Args: []LLVMType{I64, I64, I64, Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: I64, Index: 0, Field: -1},
					{Offset: 8, Type: I64, Index: 1, Field: -1},
					{Offset: 16, Type: I64, Index: 2, Field: -1},
					{Offset: 24, Type: Ptr, Index: 3, Field: -1},
				}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void scalarMultiplyRuntime(uint64_t, uint64_t, uint64_t, uint64_t *);
int main(void) {
  const uint64_t a = UINT64_C(0xffffffff80000003);
  const uint64_t b = UINT64_C(0x8000000000000005);
  const uint64_t add = UINT64_C(0x1020304050607080);
  uint64_t got[12] = {0};
  scalarMultiplyRuntime(a, b, add, got);
  const uint64_t up = (uint64_t)(uint32_t)a * (uint64_t)(uint32_t)b;
  const int64_t sp = (int64_t)(int32_t)a * (int64_t)(int32_t)b;
  const unsigned __int128 uw = (unsigned __int128)a * (unsigned __int128)b;
  const __int128 sw = (__int128)(int64_t)a * (__int128)(int64_t)b;
  const uint64_t want[12] = {
    up, (uint64_t)sp, 0-up, 0-(uint64_t)sp,
    (uint64_t)(uw >> 64), (uint64_t)((unsigned __int128)sw >> 64),
    add+up, add-up, add+(uint64_t)sp, add-(uint64_t)sp,
    0-(a*b), (uint64_t)(uint32_t)(0-((uint32_t)a*(uint32_t)b)),
  };
  for (int i = 0; i < 12; i++) if (got[i] != want[i]) return i + 1;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_scalar_multiply", triple, ll, mainC, nil)
}
