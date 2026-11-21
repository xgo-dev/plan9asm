package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestARM64ABI0TrailingResultStoreObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, row := range []struct {
		store, result string
		frameBytes    int
	}{
		{"MOVH", "uint8", 9},
		{"MOVW", "uint8", 9},
		{"MOVW", "uint16", 10},
		{"MOVD", "uint8", 9},
		{"MOVD", "uint16", 10},
		{"MOVD", "uint32", 12},
	} {
		t.Run(row.store+"_"+row.result, func(t *testing.T) {
			declaration := "func Slots(value uint64) (result " + row.result + ")"
			source := fmt.Sprintf(`TEXT ·Slots(SB),516,$0-%d
	MOVD value+0(FP),R4
	%s R4,result+8(FP)
	RET
`, row.frameBytes, row.store)
			requireARM64GoAssemblerResult(t, source, true)
			for _, triple := range []string{"aarch64-unknown-linux-gnu", "aarch64-apple-darwin", "aarch64-pc-windows-msvc"} {
				for _, api := range []string{"text", "module", "GoModule"} {
					t.Run(triple+"/"+api, func(t *testing.T) {
						ir, err := arm64ABI0TailResultTranslate(t, source, declaration, triple, api, nil)
						if err != nil {
							t.Fatal(err)
						}
						compileLLVMToObject(t, llc, triple, "trailing-result.ll", "trailing-result.o", ir)
					})
				}
			}
		})
	}
}

func TestARM64ABI0TrailingResultDoesNotExposePadding(t *testing.T) {
	const declaration = "func Slots(value uint64) (result uint32)"
	const source = `TEXT ·Slots(SB),516,$0-12
	MOVD value+0(FP),R4
	MOVD R4,result+8(FP)
	RET
`
	const triple = "aarch64-unknown-linux-gnu"
	for _, row := range []struct {
		name, declaration, source string
		edit                      func(*FuncSig)
	}{
		{"untyped", declaration, source, func(sig *FuncSig) { sig.arm64ABI0Declaration = nil }},
		{"wrong-text-extent", declaration, strings.Replace(source, "$0-12", "$0-16", 1), nil},
		{"interior-result", "func Slots(value uint64) (result, second uint16)", source, nil},
		{"frame-address", declaration, strings.Replace(source, "RET", "MOVD $result+8(FP),R5\n\tRET", 1), nil},
		{"physical-stack", declaration, strings.Replace(source, "RET", "MOVWU 20(RSP),R5\n\tRET", 1), nil},
		{"padding-read", declaration, strings.Replace(source, "RET", "MOVWU gap+12(FP),R5\n\tRET", 1), nil},
		{"crosses-alignment", declaration, strings.Replace(source, "result+8(FP)", "result+10(FP)", 1), nil},
	} {
		t.Run(row.name, func(t *testing.T) {
			requireARM64GoAssemblerResult(t, row.source, true)
			_, err := arm64ABI0TailResultTranslate(t, row.source, row.declaration, triple, "GoModule", row.edit)
			if err == nil || !strings.Contains(err.Error(), "FP frame range") {
				t.Fatalf("unproved result width or padding access, got %v", err)
			}
		})
	}
}

func TestCrossLinuxRuntimeMatrixARM64ABI0TrailingResultStore(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	const declaration = "func Slots(value uint64) (result uint32)"
	const source = `TEXT ·Slots(SB),516,$0-12
	MOVD value+0(FP),R4
	MOVD R4,result+8(FP)
	RET
`
	t.Run("original Go", func(t *testing.T) {
		// This independent ABI0 caller initializes the word after the
		// rounded outgoing area and reads the entire physical result word.
		const caller = `TEXT ·RawWithCanary(SB),4,$32-24
	MOVD value+0(FP),R0
	MOVD R0,8(RSP)
	MOVD $0x76decafe1badc0de,R1
	MOVD R1,24(RSP)
	BL ·Slots(SB)
	MOVD 16(RSP),R2
	MOVD 24(RSP),R3
	MOVD R2,word+8(FP)
	MOVD R3,canary+16(FP)
	RET
`
		const program = "package main\n" + declaration + `
func RawWithCanary(value uint64) (word, canary uint64)
func main() {
	for _, value := range [...]uint64{0, 0xdecafbad00000000, 0x87654321fedcba98, ^uint64(0)} {
		if Slots(value) != uint32(value) {
			panic("typed ABI0 result")
		}
		if got, canary := RawWithCanary(value); got != value || canary != 0x76decafe1badc0de {
			panic("physical ABI0 result or next stack word")
		}
	}
}
`
		runARM64LocalRegisterGoOracle(t, source+caller, program, len(runner) != 0)
	})
	ir, err := arm64ABI0TailResultTranslate(t, source, declaration, triple, "GoModule", nil)
	if err != nil {
		t.Fatal(err)
	}
	const main = `#include <stdint.h>
extern uint32_t Slots(uint64_t);
int main(void) {
	const uint64_t values[] = {0, UINT64_C(0xdecafbad00000000), UINT64_C(0x87654321fedcba98), UINT64_MAX};
	for (unsigned i = 0; i < sizeof values / sizeof values[0]; i++) {
		volatile uint32_t out[] = {0x12345678, 0x99999999, 0xdefabc01};
		out[1] = Slots(values[i]);
		if (out[1] != (uint32_t)values[i]) return 1;
		if (out[0] != 0x12345678 || out[2] != 0xdefabc01) return 2;
	}
	return 0;
}
`
	for _, level := range []int{0, 2} {
		t.Run(fmt.Sprintf("LLVM/O%d", level), func(t *testing.T) {
			compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "abi0_trailing_result", triple, ir, main, runner, level)
		})
	}
}
