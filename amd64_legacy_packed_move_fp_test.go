package plan9asm

import (
	"errors"
	"fmt"
	"testing"
)

func TestX86LegacyPackedMoveLogicalFPAlignment(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, row := range []struct {
			opcode  string
			aligned bool
		}{
			{"MOVOU", false}, {"MOVUPS", false}, {"MOVUPD", false},
			{"MOVO", true}, {"MOVOA", true}, {"MOVAPS", true}, {"MOVAPD", true},
		} {
			for _, direction := range []struct{ name, operands, declaration string }{
				{"load", "a+0(FP),X1", "func F(a,b,c,d float32)\n"},
				{"store", "X1,a+0(FP)", "func F() (a,b uint64)\n"},
			} {
				t.Run(target.triple+"/"+row.opcode+"/"+direction.name, func(t *testing.T) {
					source := fmt.Sprintf("TEXT ·F(SB),4,$0-16\nPXOR X1,X1\n%s %s\nRET\n", row.opcode, direction.operands)
					x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source,
								direction.declaration, target.arch, target.triple, api)
							if row.aligned {
								if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
									t.Fatal("logical FP fields supplied native alignment without its backing", err)
								}
							} else if err != nil || ir == "" {
								t.Fatal("unaligned logical FP byte transport failed", err)
							}
						})
					}
				})
			}
		}
	}
}

func TestX86LegacyPackedMoveNativeMemoryThreeAPIFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		for _, opcode := range []string{"MOVOU", "MOVUPS", "MOVUPD", "MOVO", "MOVOA", "MOVAPS", "MOVAPD"} {
			t.Run(target.triple+"/"+opcode, func(t *testing.T) {
				move, word := "MOVQ", 8
				if target.arch == "386" {
					move, word = "MOVL", 4
				}
				source := fmt.Sprintf("TEXT ·F(SB),4,$0-%d\n%s p+0(FP),AX\n%s (AX),X1\n%s X1,(AX)\nRET\n",
					word, move, opcode, opcode)
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func F(p *[16]byte)\n",
							target.arch, target.triple, api)
						if err != nil {
							t.Fatal(err)
						}
						compileLLVMToObject(t, llc, target.triple, "packed-native.ll", "packed-native.o", ir)
					})
				}
			})
		}
	}
}

func TestCrossLinuxRuntimeMatrixX86LegacyPackedMoveFPResults(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	for _, opcode := range []string{"MOVOU", "MOVUPS", "MOVUPD"} {
		t.Run(opcode, func(t *testing.T) {
			source := fmt.Sprintf("TEXT ·F(SB),4,$0-32\n%s a+0(FP),X1\n%s X1,r0+16(FP)\nRET\n", opcode, opcode)
			goAssemblerOracleOutput(t, "amd64", source, "", true)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source,
						"func F(a,b uint64) (r0,r1,r2,r3 uint32)\n", "amd64", execution.triple, api)
					if err != nil {
						t.Fatal(err)
					}
					// An LLVM wrapper observes each tuple field without assuming
					// that a C struct and a raw LLVM aggregate share a return ABI.
					ir += `
define void @observe(ptr %out) {
  %value = call { i32, i32, i32, i32 } @F(i64 8589934593, i64 17179869187)
  store { i32, i32, i32, i32 } %value, ptr %out, align 4
  ret void
}
`
					const main = `#include <stdint.h>
#include <stdio.h>
extern void observe(uint32_t*);
int main(void) {
    uint32_t out[6] = {77,0,0,0,0,88};
    observe(out+1);
    for(unsigned i=1;i<=4;i++) if(out[i]!=i) {
        fprintf(stderr,"result field %u: got %u, want %u\n",i-1,out[i],i);
        return 1;
    }
    return out[0]!=77 || out[5]!=88;
}
`
					for _, level := range []string{"-O0", "-O2"} {
						t.Run(level, func(t *testing.T) {
							execution.compileAndRunLLVM(t, "packed-fp-results", ir, main, level)
						})
					}
				})
			}
		})
	}
}
