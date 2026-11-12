package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

func TestTranslateARM64CountLeadingCompleteGo127Forms(t *testing.T) {
	const source = `TEXT countLeadingForms(SB), $0-0
	CLZ R0, R1
	CLZW R2, R3
	CLS R4, R5
	CLSW R6, R7
	CLZ ZR, ZR
	CLZW ZR, ZR
	CLS ZR, ZR
	CLSW ZR, ZR
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
					"countLeadingForms": {Name: "countLeadingForms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"@llvm.ctlz.i64", "@llvm.ctlz.i32", "ashr i64", "ashr i32", "sub i64", "sub i32"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("count-leading lowering omitted %q:\n%s", want, ir)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-count-leading.ll", "arm64-count-leading.o", ir)
		})
	}
}

func TestTranslateARM64CountLeadingRejectsFormsOutsideGo127Optab(t *testing.T) {
	for _, instruction := range []string{
		"CLZ R0",
		"CLZW $1, R0",
		"CLS R0, R1, R2",
		"CLSW R0, (R1)",
		"CLZ RSP, R0",
		"CLS V0, R0",
		"CLZW.P R0, R1",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badCountLeading(SB), $0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64GoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu",
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"badCountLeading": {Name: "badCountLeading", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's count-leading optab", instruction)
			}
		})
	}
}

func TestARM64CountLeadingRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT countLeadingRuntime(SB), $0-16
	MOVD value+0(FP), R0
	MOVD out+8(FP), R1
	CLZ R0, R2
	MOVD R2, 0(R1)
	CLZW R0, R2
	MOVD R2, 8(R1)
	CLS R0, R2
	MOVD R2, 16(R1)
	CLSW R0, R2
	MOVD R2, 24(R1)
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
			"countLeadingRuntime": {
				Name: "countLeadingRuntime", Args: []LLVMType{I64, Ptr}, Ret: Void,
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
extern void countLeadingRuntime(uint64_t, uint64_t *);
static uint64_t clz64(uint64_t value) { return value ? __builtin_clzll(value) : 64; }
static uint64_t clz32(uint32_t value) { return value ? __builtin_clz(value) : 32; }
int main(void) {
  const uint64_t value = UINT64_C(0xf123456789abcdef);
  const uint32_t word = (uint32_t)value;
  uint64_t got[4] = {0, 0, 0, 0};
  countLeadingRuntime(value, got);
  const uint64_t sign64 = (uint64_t)((int64_t)value >> 63);
  const uint32_t sign32 = (uint32_t)((int32_t)word >> 31);
  const uint64_t want[4] = {clz64(value), clz32(word), clz64(value ^ sign64) - 1, clz32(word ^ sign32) - 1};
  for (int i = 0; i < 4; i++) if (got[i] != want[i]) return i + 1;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_count_leading", triple, ir, mainC, nil)
}
