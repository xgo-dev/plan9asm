package plan9asm

import (
	"errors"
	"fmt"
	"testing"
)

func TestX86ResultCallerAddressDifferenceOriginalFPSources(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word, typ, move, lea, sub := 8, "uint64", "MOVQ", "LEAQ", "SUBQ"
		if target.arch == "386" {
			word, typ, move, lea, sub = 4, "uint32", "MOVL", "LEAL", "SUBL"
		}
		for _, offset := range []int{0, word} {
			t.Run(fmt.Sprintf("%s/slot%d", target.triple, offset), func(t *testing.T) {
				pointer, declaration := "p", "func Value(p,q *byte,n "+typ+") "+typ
				if offset != 0 {
					pointer = "q"
				}
				body := fmt.Sprintf("%s %s+%d(FP),SI\n%s n+%d(FP),AX\n%s -16(SI)(AX*1),DI\n%s %s+%d(FP),DI\n%s DI,ret+%d(FP)\nRET",
					move, pointer, offset, move, 2*word, lea, sub, pointer, offset, move, 3*word)
				_, file, sig, source := x86ResultInitializationFixture(t, target.arch, declaration, body)
				goAssemblerOracleOutput(t, target.arch, source, "", true)
				for _, ins := range file.Funcs[0].Instrs {
					if ins.Op == Op(sub) && !x86ResultCallerAddressDifferenceNeedsProof(ins, sig, target.arch) {
						t.Fatal("direct FP pointer subtraction bypasses the whole-source obligation")
					}
				}
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
						if err != nil || ir == "" {
							t.Fatal("same typed origin did not cancel its original FP operand", err)
						}
						llc := findLLVM22Tool("llc")
						if llc == "" {
							t.Fatal("LLVM22 llc required")
						}
						compileLLVMToObject(t, llc, target.triple, "pointer-difference.ll", "pointer-difference.o", ir)
					})
				}
			})
		}
	}
}

func TestX86ResultCallerAddressDifferenceFPBoundary(t *testing.T) {
	for name, body := range map[string]string{
		"different pointer":       "SUBQ q+8(FP),SI",
		"numerical field":         "SUBQ n+16(FP),SI",
		"partial pointer field":   "SUBQ p+1(FP),SI",
		"unbound field":           "SUBQ absent+32(FP),SI",
		"partial destination":     "MOVB $0,SI\nSUBQ p+0(FP),SI",
		"result is not a pointer": "SUBQ p+0(FP),SI\nMOVQ (SI),SI",
		"origin is consumed":      "SUBQ p+0(FP),SI\nSUBQ p+0(FP),SI",
	} {
		t.Run(name, func(t *testing.T) {
			declaration := "func Value(p,q *byte,n uint64) uint64"
			body = "MOVQ p+0(FP),SI\nLEAQ 8(SI),SI\n" + body + "\nMOVQ SI,ret+24(FP)\nRET"
			_, _, _, source := x86ResultInitializationFixture(t, "amd64", declaration, body)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("FP subtraction borrowed an unrelated value or memory role", api, err)
				}
			}
		})
	}
}

func TestX86ResultCallerAddressDifferenceFPPortableExecution(t *testing.T) {
	execution := x86ScalarCountHostExecution(t)
	declaration := "func Value(p *byte,n uint64) uint64"
	body := "MOVQ p+0(FP),SI\nMOVQ n+8(FP),AX\nLEAQ -16(SI)(AX*1),SI\nSUBQ p+0(FP),SI\nMOVQ SI,ret+16(FP)\nRET"
	_, _, _, source := x86ResultInitializationFixture(t, "amd64", declaration, body)
	const driver = `#include <stdint.h>
extern uint64_t Value(uint8_t*, uint64_t);
int main(void) {
    uint8_t storage[64] = {0};
    const uint64_t offsets[] = {0, 1, 15, 16, 17, 31, 48, UINT64_MAX};
    for (unsigned i = 0; i < sizeof(offsets)/sizeof(offsets[0]); ++i) {
        if (Value(storage, offsets[i]) != offsets[i]-16) return 1;
    }
    return 0;
}
`
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", execution.triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, input := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
				execution.compileAndRunLLVM(t, "pointer-difference", input, driver, "-O2")
			}
		})
	}
}
