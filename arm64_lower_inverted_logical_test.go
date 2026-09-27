package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

const arm64InvertedLogicalForms = `
TEXT invertedlogicalforms(SB),$0-0
	ORN R0, R1
	ORN R2, R3, R4
	ORN R5>>7, R6, R7
	ORN $255, R8, R9
	ORN $255, R9, RSP
	ORNW R10, R11
	ORNW R12->3, R13, R14
	ORNW $255, R15, R16
	EON R17, R19
	EON R20<<12, R21, R22
	EON $255, R23, R24
	EONW R24, R25
	EONW R26@>15, R27, R29
	EONW $255, R30, R0
	RET
`

func TestTranslateARM64InvertedLogicalCompleteGoAssemblerForms(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64InvertedLogicalForms, true)
	file, err := Parse(ArchARM64, arm64InvertedLogicalForms)
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
				Sigs: map[string]FuncSig{"invertedlogicalforms": {Name: "invertedlogicalforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"xor i64", "or i64", "xor i32", "or i32"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("inverted-logical family for %s omitted %q:\n%s", triple, want, ir)
				}
			}
			compileLLVMToObject(t, llc, triple, "arm64-inverted-logical.ll", "arm64-inverted-logical.o", ir)
		})
	}
}

func TestTranslateARM64InvertedLogicalRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, instruction := range []string{
		"ORN R0",
		"ORN R0, R1, R2, R3",
		"ORN (R0), R1",
		"ORN R0.UXTB, R1",
		"ORN RSP, R1",
		"ORNW R0<<32, R1",
		"EON R0, RSP",
		"EONW.P R0, R1",
	} {
		source := "TEXT badinvertedlogical(SB),$0-0\n\t" + instruction + "\n\tRET\n"
		requireARM64GoAssemblerResult(t, source, false)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			continue
		}
		if _, err := Translate(file, Options{
			TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64",
			Sigs: map[string]FuncSig{"badinvertedlogical": {Name: "badinvertedlogical", Ret: Void}},
		}); err == nil {
			t.Fatalf("Translate accepted %q outside Go 1.27's inverted-logical optab", instruction)
		}
	}
}

func TestARM64InvertedLogicalRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT invertedlogical(SB),$0-24
	MOVD first+0(FP), R0
	MOVD second+8(FP), R1
	MOVD output+16(FP), R2
	ORN R0, R1, R3
	EON R0, R1, R4
	ORNW R0, R1, R5
	EONW R0, R1, R6
	ORN R0>>8, R1, R7
	EONW $255, R1, R8
	MOVD R3, 0(R2)
	MOVD R4, 8(R2)
	MOVD R5, 16(R2)
	MOVD R6, 24(R2)
	MOVD R7, 32(R2)
	MOVD R8, 40(R2)
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
		Sigs: map[string]FuncSig{"invertedlogical": {
			Name: "invertedlogical", Args: []LLVMType{I64, I64, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: I64, Index: 0, Field: -1},
				{Offset: 8, Type: I64, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void invertedlogical(uint64_t, uint64_t, uint64_t *);
int main(void) {
  const uint64_t first = UINT64_C(0x00ff00ff8000000f);
  const uint64_t second = UINT64_C(0xf000aaa055aa1234);
  uint64_t got[6] = {0};
  invertedlogical(first, second, got);
  const uint64_t want[6] = {
    second | ~first,
    second ^ ~first,
    (uint32_t)second | ~(uint32_t)first,
    (uint32_t)second ^ ~(uint32_t)first,
    second | ~(first >> 8),
    (uint32_t)second ^ ~(uint32_t)255
  };
  for (int i = 0; i < 6; i++) if (got[i] != want[i]) return i + 1;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_inverted_logical", triple, ir, mainC, nil)
}
