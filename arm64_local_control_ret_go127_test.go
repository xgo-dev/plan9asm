//go:build go1.27

package plan9asm

import (
	"strings"
	"testing"
)

// Preserve the current Go pseudo-RET fixture independently of the stable
// hardware RET program. Legacy Go accepts these spellings but rewrites the
// target to R30; the untagged selected-encoder witness tests that difference.
func TestCrossLinuxRuntimeMatrixARM64CurrentGoRETRegisterAliases(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	const source = `TEXT ·ReturnAlias(SB),516,$0-16
MOVD a+0(FP),R0
MOVD R30,R19
CALL helper
ADD $2,R0
MOVD R0,ret+8(FP)
RET R19
helper:
ADD $5,R0
MOVD R30,R20
RET 8(R20)
`
	requireARM64GoAssemblerResult(t, source, true)
	runARM64LocalRegisterGoOracle(t, source, `package main
func ReturnAlias(uint64) uint64
func main() {
    for _, x := range []uint64{0, 1, 123, 0x8000000000000000, ^uint64(0)} {
        if got := ReturnAlias(x); got != x+7 {
            println(got)
            panic("current Go pseudo-RET alias mismatch")
        }
    }
}
`, len(runner) != 0)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	options := Options{Goarch: "arm64", TargetTriple: triple,
		Sigs:       map[string]FuncSig{"ReturnAlias": arm64LocalRegisterBranchSig("ReturnAlias")},
		ResolveSym: func(symbol string) string { return strings.TrimPrefix(symbol, "·") }}
	ir, err := Translate(file, options)
	if err != nil {
		t.Fatal(err)
	}
	const main = `#include <stdint.h>
extern uint64_t ReturnAlias(uint64_t);
int main(void) {
    const uint64_t inputs[] = {0, 1, 123, UINT64_C(0x8000000000000000), UINT64_MAX};
    const volatile uint64_t canary = UINT64_C(0x8718369423719654);
    for (unsigned i = 0; i < 5; i++) {
        if (ReturnAlias(inputs[i]) != inputs[i]+7) return 1;
    }
    return canary != UINT64_C(0x8718369423719654);
}
`
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "current_go_ret_alias", triple, ir, main, runner)
}
