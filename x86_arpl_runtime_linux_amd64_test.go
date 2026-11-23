//go:build linux && amd64

package plan9asm

import (
	"os/exec"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86ARPL386(t *testing.T) {
	llc := findLLVM22Tool("llc")
	compiler, err := exec.LookPath("i686-linux-gnu-gcc")
	if llc == "" || err != nil {
		t.Fatalf("required LLVM 22/i386 runtime tools: llc=%q compiler=%v", llc, err)
	}
	execution := x86FloatCompareExecution{
		llc: llc, triple: "i386-unknown-linux-gnu",
		compiler: []string{compiler, "-static", "-no-pie"},
	}
	// The original bytes independently check all selector pairs, preserved
	// flags, upper register bits and memory outside the two-byte operand.
	const driver = `#include <stdint.h>
#include <stdio.h>
extern uint64_t AdjustReg(uint32_t, uint32_t);
extern uint32_t AdjustMem(uint32_t, uint16_t *);
int main(void) {
    for (uint32_t src = 0; src < 4; src++) {
        for (uint32_t dst = 0; dst < 4; dst++) {
            const uint32_t input = 0xa5a54210 | src;
            const uint32_t initial = 0xdead8fe0 | dst;
            uint32_t reference = initial, flags;
            asm volatile("pushl $0x8d7; popfl; .byte 0x63, 0xc3; pushfl; popl %0"
                         : "=r"(flags), "+b"(reference) : "a"(input) : "cc", "memory");
            flags &= 0x9ff;
            flags = (flags & 0xff) | ((flags >> 3) & 0x100);
            uint64_t got = AdjustReg(input, initial);
            uint16_t words[] = {0xf00d, (uint16_t)initial, 0x1234};
            uint32_t memoryFlags = AdjustMem(input, &words[1]);
            if ((uint32_t)got != reference || (got >> 32) != flags ||
                words[0] != 0xf00d || words[1] != (uint16_t)reference ||
                words[2] != 0x1234 || memoryFlags != flags) {
                fprintf(stderr, "ARPL src=%u dst=%u register=%llx memory=%x flags=%x expected=%x/%x\n",
                        src, dst, (unsigned long long)got, words[1], memoryFlags, reference, flags);
                return 1;
            }
        }
    }
    puts("32 original ARPL comparisons");
    return 0;
}
`
	for _, raw := range []bool{false, true} {
		ir, err := x86ScalarFPBitViewAPI(t, x86ARPLRuntimeSource(raw), x86ARPLRuntimeDecl, "386", execution.triple, "Go")
		if err != nil {
			t.Fatalf("raw=%t: %v", raw, err)
		}
		for _, level := range []string{"-O0", "-O2"} {
			output := execution.compileAndRunLLVM(t, "arpl", ir, driver, level)
			if strings.TrimSpace(string(output)) != "32 original ARPL comparisons" {
				t.Fatalf("raw=%t %s: %s", raw, level, output)
			}
		}
	}
}
