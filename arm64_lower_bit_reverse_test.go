package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

func TestTranslateARM64BitReverseCompleteGo127Forms(t *testing.T) {
	const source = `TEXT bitReverseForms(SB), $0-0
	RBIT R0, R1
	RBITW R2, R3
	RBIT ZR, ZR
	RBITW ZR, ZR
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
					"bitReverseForms": {Name: "bitReverseForms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"@llvm.bitreverse.i64", "@llvm.bitreverse.i32", "zext i32"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("bit-reverse lowering omitted %q:\n%s", want, ir)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-bit-reverse.ll", "arm64-bit-reverse.o", ir)
		})
	}
}

func TestTranslateARM64BitReverseRejectsFormsOutsideGo127Optab(t *testing.T) {
	for _, instruction := range []string{
		"RBIT R0",
		"RBIT $1, R0",
		"RBIT R0, R1, R2",
		"RBIT R0, (R1)",
		"RBIT RSP, R0",
		"RBIT V0, R0",
		"RBITW.P R0, R1",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badBitReverse(SB), $0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64GoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu",
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"badBitReverse": {Name: "badBitReverse", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's RBIT optab", instruction)
			}
		})
	}
}

func TestARM64BitReverseRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT bitReverseRuntime(SB), $0-16
	MOVD value+0(FP), R0
	MOVD out+8(FP), R1
	RBIT R0, R2
	MOVD R2, 0(R1)
	RBITW R0, R2
	MOVD R2, 8(R1)
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
			"bitReverseRuntime": {
				Name: "bitReverseRuntime", Args: []LLVMType{I64, Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: I64, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void bitReverseRuntime(uint64_t, uint64_t *);
static uint64_t reverse64(uint64_t value, int bits) {
  uint64_t result = 0;
  for (int i = 0; i < bits; i++) result = (result << 1) | ((value >> i) & 1);
  return result;
}
int main(void) {
  const uint64_t value = UINT64_C(0x0123456789abcdef);
  uint64_t got[2] = {0, 0};
  bitReverseRuntime(value, got);
  return got[0] != reverse64(value, 64) || got[1] != reverse64((uint32_t)value, 32);
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_bit_reverse", triple, ir, mainC, nil)
}
