package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

const arm64BorrowedSlotsDeclaration = "func Slots(dst *uint64, value uint64) (result uint64)"
const arm64BorrowedSlotsAssembly = `TEXT ·Slots(SB),4,$0-24
	MOVD $7,R5
	JMP body<>(SB)
TEXT body<>(SB),516,$0
	MOVD dst+0(FP),R4
	MOVD value+8(FP),R8
	ADDS R5,R8,R9
	ADC $0,ZR,R10
	STP.P (R9,R10),16(R4)
	MOVD R10,result+16(FP)
	RET
`

func TestARM64ABI0TailBorrowedSlots(t *testing.T) {
	const assembly = arm64BorrowedSlotsAssembly
	const triple = "aarch64-unknown-linux-gnu"
	for _, tc := range []struct {
		name, source string
		needsContext bool
	}{
		{"bound", assembly, false},
		{"missing-register", strings.Replace(assembly, "MOVD $7,R5", "NOP", 1), true},
		{"missing-frame-slot", strings.Replace(assembly, "value+8(FP)", "value+80(FP)", 1), true},
		{"read-into-result", strings.Replace(assembly, "value+8(FP)", "value+12(FP)", 1), true},
		{"missing-result", strings.Replace(assembly, "MOVD R10,result+16(FP)", "NOP", 1), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireARM64GoAssemblerResult(t, tc.source, true)
			for _, api := range []string{"text", "module", "GoModule"} {
				t.Run(api, func(t *testing.T) {
					ir, err := arm64ABI0TailResultTranslate(t, tc.source, arm64BorrowedSlotsDeclaration, triple, api, nil)
					if tc.needsContext {
						if !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatalf("want context error for unbound input or result, got %v", err)
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					llc := findLLVM22Tool("llc")
					if llc == "" {
						t.Fatal("LLVM 22 llc not found")
					}
					compileLLVMToObject(t, llc, triple, "borrowed-tail.ll", "borrowed-tail.o", ir)
				})
			}
		})
	}
}

func TestCrossLinuxRuntimeMatrixARM64ABI0TailBorrowedSlots(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	t.Run("original Go", func(t *testing.T) {
		const program = "package main\n" + arm64BorrowedSlotsDeclaration + `
func main() {
	for _, value := range [...]uint64{0, 42, 1<<63, ^uint64(0)-7, ^uint64(0)-6, ^uint64(0)} {
		sum := value+7
		var carry uint64
		if sum < value { carry = 1 }
		out := [4]uint64{11, 12, 13, 14}
		if Slots(&out[1], value) != carry || out != [4]uint64{11, sum, carry, 14} {
			panic("borrowed ABI0 frame results, pair store or canaries")
		}
	}
}
`
		runARM64LocalRegisterGoOracle(t, arm64BorrowedSlotsAssembly, program, len(runner) != 0)
	})
	const main = `#include <stdint.h>
extern uint64_t Slots(uint64_t*, uint64_t);
int main(void) {
	const uint64_t values[] = {0, 42, UINT64_C(1)<<63, UINT64_MAX-7, UINT64_MAX-6, UINT64_MAX};
	for (unsigned i = 0; i < sizeof values / sizeof values[0]; i++) {
		const uint64_t value = values[i];
		const uint64_t sum = value+7;
		const uint64_t carry = sum < value;
		uint64_t out[] = {11, 12, 13, 14};
		if (Slots(out+1, value) != carry || out[1] != sum || out[2] != carry) return 1;
		if (out[0] != 11 || out[3] != 14) return 2;
	}
	return 0;
}
`
	for _, api := range []string{"text", "module", "GoModule"} {
		for _, opt := range []int{0, 2} {
			t.Run(fmt.Sprintf("%s/O%d", api, opt), func(t *testing.T) {
				ir, err := arm64ABI0TailResultTranslate(t, arm64BorrowedSlotsAssembly, arm64BorrowedSlotsDeclaration, triple, api, nil)
				if err != nil {
					t.Fatal(err)
				}
				compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "abi0_borrowed_slots", triple, ir, main, runner, opt)
			})
		}
	}
}
