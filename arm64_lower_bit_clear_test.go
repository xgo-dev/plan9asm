package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

func TestTranslateARM64BitClearCompleteGo127Forms(t *testing.T) {
	const source = `TEXT bitClearForms(SB), $0-0
	BIC R0, R1
	BIC R2, R3, R4
	BIC R5>>7, R6, R7
	BIC $255, R8, R9
	BIC $255, R9, RSP
	BICW R10, R11
	BICW R12->3, R13, R14
	BICW $255, R15, R16
	BICS R17, R19
	BICS R20->12, R21, R22
	BICS $255, R23, R24
	BICSW R24, R25
	BICSW R26@>15, R27, R29
	BICSW $255, R30, R0
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
					"bitClearForms": {Name: "bitClearForms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"xor i64", "and i64", "xor i32", "and i32", "icmp slt i64", "icmp slt i32"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("bit-clear lowering omitted %q:\n%s", want, ir)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-bit-clear.ll", "arm64-bit-clear.o", ir)
		})
	}
}

func TestTranslateARM64BitClearRejectsFormsOutsideGo127Optab(t *testing.T) {
	for _, instruction := range []string{
		"BIC R0",
		"BIC R0, R1, R2, R3",
		"BIC (R0), R1",
		"BIC R0.UXTB, R1",
		"BIC RSP, R1",
		"BICW R0<<32, R1",
		"BICS R0, RSP",
		"BICSW.P R0, R1",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badBitClear(SB), $0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64GoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu",
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"badBitClear": {Name: "badBitClear", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's BIC optab", instruction)
			}
		})
	}
}

func TestARM64BitClearRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT bitClearRuntime(SB), $0-24
	MOVD mask+0(FP), R0
	MOVD value+8(FP), R1
	MOVD out+16(FP), R2
	BIC R0, R1, R3
	MOVD R3, 0(R2)
	BICS R0, R1, R3
	MOVD R3, 8(R2)
	CSET MI, R4
	MOVD R4, 16(R2)
	CSET EQ, R4
	MOVD R4, 24(R2)
	CSET CS, R4
	MOVD R4, 32(R2)
	CSET VS, R4
	MOVD R4, 40(R2)
	BICSW R0, R1, R3
	MOVD R3, 48(R2)
	CSET MI, R4
	MOVD R4, 56(R2)
	CSET EQ, R4
	MOVD R4, 64(R2)
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
			"bitClearRuntime": {
				Name: "bitClearRuntime", Args: []LLVMType{I64, I64, Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: I64, Index: 0, Field: -1},
					{Offset: 8, Type: I64, Index: 1, Field: -1},
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
extern void bitClearRuntime(uint64_t, uint64_t, uint64_t *);
int main(void) {
  const uint64_t mask = UINT64_C(0x00ff00ff00ff00ff);
  const uint64_t value = UINT64_C(0xf0f00000f0f00000);
  uint64_t got[9] = {0};
  bitClearRuntime(mask, value, got);
  const uint64_t result = value & ~mask;
  const uint32_t word = (uint32_t)value & ~(uint32_t)mask;
  const uint64_t want[9] = {result, result, result >> 63, result == 0, 0, 0, word, word >> 31, word == 0};
  for (int i = 0; i < 9; i++) if (got[i] != want[i]) return i + 1;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_bit_clear", triple, ir, mainC, nil)
}
