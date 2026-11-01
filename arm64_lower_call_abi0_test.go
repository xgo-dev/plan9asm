package plan9asm

import (
	"errors"
	"runtime"
	"strings"
	"testing"
)

func TestARM64ABI0CallUsesOutgoingStackFrameRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	source := `
TEXT ·arm64ABI0Callee(SB), $0-32
	MOVD a+0(FP), R0
	MOVD b+8(FP), R1
	EOR R1, R0
	MOVD c+16(FP), R1
	EOR R1, R0
	MOVD R0, ret+24(FP)
	RET

TEXT ·arm64ABI0Caller(SB), $40-32
	MOVD a+0(FP), R10
	ADD $1, R10
	MOVD R10, 8(RSP)
	MOVD b+8(FP), R10
	ADD $2, R10
	MOVD R10, 16(RSP)
	MOVD c+16(FP), R10
	ADD $4, R10
	MOVD R10, 24(RSP)
	BL ·arm64ABI0Callee(SB)
	MOVD 32(RSP), R0
	MOVD R0, ret+24(FP)
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(sym string) string { return strings.TrimPrefix(sym, "·") }
	frame := FrameLayout{
		Params: []FrameSlot{
			{Offset: 0, Type: I64, Index: 0, Field: -1, Name: "a"},
			{Offset: 8, Type: I64, Index: 1, Field: -1, Name: "b"},
			{Offset: 16, Type: I64, Index: 2, Field: -1, Name: "c"},
		},
		Results: []FrameSlot{{Offset: 24, Type: I64, Index: 0, Field: -1, Name: "ret"}},
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ll, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       "arm64",
		ResolveSym:   resolve,
		Sigs: map[string]FuncSig{
			"arm64ABI0Callee": {Name: "arm64ABI0Callee", Args: []LLVMType{I64, I64, I64}, Ret: I64, Frame: frame},
			"arm64ABI0Caller": {Name: "arm64ABI0Caller", Args: []LLVMType{I64, I64, I64}, Ret: I64, Frame: frame},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	mainC := `
#include <stdint.h>
extern uint64_t arm64ABI0Caller(uint64_t a, uint64_t b, uint64_t c);
int main(void) {
  uint64_t got = arm64ABI0Caller(10, 20, 30);
  uint64_t want = (10 + 1) ^ (20 + 2) ^ (30 + 4);
  return got == want ? 0 : 1;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_abi0_call", triple, ll, mainC, nil)
}

func TestARM64ABI0FramedStackTailRequiresNativeStackContract(t *testing.T) {
	source := arm64StackTailOriginalSource()
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	args := make([]LLVMType, 17)
	params := make([]FrameSlot, 17)
	for index := range args {
		args[index] = I64
		params[index] = FrameSlot{Offset: int64(index * 8), Type: I64, Index: index, Field: -1}
	}
	resolve := func(sym string) string { return strings.TrimPrefix(sym, "·") }
	for _, triple := range []string{
		"aarch64-apple-darwin", "aarch64-unknown-linux-gnu",
		"aarch64-unknown-freebsd", "aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			_, err := Translate(file, Options{
				TargetTriple: triple, Goarch: "arm64", ResolveSym: resolve,
				Sigs: map[string]FuncSig{
					"arm64ABI0StackTail":  {Name: "arm64ABI0StackTail", Ret: I64},
					"arm64ABI0TailTarget": {Name: "arm64ABI0TailTarget", Args: args, Ret: I64, Frame: FrameLayout{Params: params}},
				},
			})
			if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "symbol branch has no implicit Go frame epilogue") {
				t.Fatalf("framed JMP must not synthesize a Go epilogue: %v", err)
			}
		})
	}
}

func TestARM64ABIInternalCallUsesIndependentRegisterBanks(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	source := `
TEXT ·arm64ABIRegisterForward(SB), $0-0
	BL ·arm64ABIRegisterCallee(SB)
	RET

TEXT ·arm64ABIFloatForward(SB), $0-0
	BL ·arm64ABIFloatCallee(SB)
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(sym string) string { return strings.TrimPrefix(sym, "·") }
	args := []LLVMType{I64, LLVMType("float"), LLVMType("double"), I64}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ll, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       "arm64",
		ResolveSym:   resolve,
		Sigs: map[string]FuncSig{
			"arm64ABIRegisterForward": {Name: "arm64ABIRegisterForward", Args: args, Ret: I64},
			"arm64ABIRegisterCallee":  {Name: "arm64ABIRegisterCallee", Args: args, Ret: I64},
			"arm64ABIFloatForward":    {Name: "arm64ABIFloatForward", Args: []LLVMType{LLVMType("float")}, Ret: LLVMType("float")},
			"arm64ABIFloatCallee":     {Name: "arm64ABIFloatCallee", Args: []LLVMType{LLVMType("float")}, Ret: LLVMType("float")},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	mainC := `
#include <stdint.h>
#include <string.h>
extern uint64_t arm64ABIRegisterForward(uint64_t first, float single, double dbl, uint64_t second);
extern float arm64ABIFloatForward(float value);
uint64_t arm64ABIRegisterCallee(uint64_t first, float single, double dbl, uint64_t second) {
  uint32_t single_bits;
  uint64_t double_bits;
  memcpy(&single_bits, &single, sizeof(single_bits));
  memcpy(&double_bits, &dbl, sizeof(double_bits));
  return first ^ single_bits ^ double_bits ^ second;
}
float arm64ABIFloatCallee(float value) { return value * 2.0f; }
int main(void) {
  const uint64_t first = UINT64_C(0x123456789abcdef0);
  const uint64_t second = UINT64_C(0xfedcba9876543210);
  const float single = -13.25f;
  const double dbl = 91.5;
  uint32_t single_bits;
  uint64_t double_bits;
  memcpy(&single_bits, &single, sizeof(single_bits));
  memcpy(&double_bits, &dbl, sizeof(double_bits));
  uint64_t want = first ^ single_bits ^ double_bits ^ second;
  if (arm64ABIRegisterForward(first, single, dbl, second) != want) return 1;
  if (arm64ABIFloatForward(1.25f) != 2.5f) return 2;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_abi_register_call", triple, ll, mainC, nil)
}
