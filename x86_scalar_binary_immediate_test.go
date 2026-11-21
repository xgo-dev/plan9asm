package plan9asm

import (
	"bytes"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestX86ScalarLogicalQwordImmediateSignExtension(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc and clang are required")
	}
	var source, declarations strings.Builder
	for _, row := range []struct {
		mnemonic, function string
		accumulatorByte    byte
	}{
		{"ANDQ", "bitAnd", 0x25},
		{"ORQ", "bitOr", 0x0d},
		{"XORQ", "bitXor", 0x35},
	} {
		instruction := row.mnemonic + " $0x80000000,AX"
		original := x86PackedShiftActualGoBytes(t, "amd64", "TEXT f(SB),4,$0-0\n"+instruction+"\nRET\n")
		want := []byte{0x48, row.accumulatorByte, 0, 0, 0, 0x80, 0xc3}
		if !bytes.Equal(original, want) {
			t.Fatalf("Go encoded %s as %x, want %x", instruction, original, want)
		}
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-16\nMOVQ v+0(FP),AX\n%s\nMOVQ AX,ret+8(FP)\nRET\n", row.function, instruction)
		fmt.Fprintf(&declarations, "func %s(v uint64) uint64\n", row.function)
	}
	const reference = `
#include <stdint.h>

extern uint64_t bitAnd(uint64_t value);
extern uint64_t bitOr(uint64_t value);
extern uint64_t bitXor(uint64_t value);

int main(void) {
    const uint64_t mask = UINT64_C(0xffffffff80000000);
    const uint64_t inputs[] = {
        0, 1, UINT64_MAX, UINT64_C(0x7fffffff), UINT64_C(0x80000000),
        UINT64_C(0x123456789abcdeff), UINT64_C(0x8000000000000000)
    };
    for (unsigned i = 0; i < sizeof inputs / sizeof inputs[0]; ++i) {
        uint64_t value = inputs[i];
        if (bitAnd(value) != (value & mask)) return 1;
        if (bitOr(value) != (value | mask)) return 2;
        if (bitXor(value) != (value ^ mask)) return 3;
    }
    return 0;
}
`
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, level := range []int{0, 2} {
				compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "logical-immediate", triple, ir, reference, nil, level)
			}
		})
	}
}
