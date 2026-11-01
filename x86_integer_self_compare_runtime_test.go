package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86IntegerSelfComparePortableValuesFlagsAndCanaries(t *testing.T) {
	execution := x86ScalarCountHostExecution(t)
	rows := x86IntegerSelfCompareCases("amd64")
	for start := 0; start < len(rows); start += 64 {
		end := start + 64
		if end > len(rows) {
			end = len(rows)
		}
		t.Run(fmt.Sprintf("batch-%d", start/64), func(t *testing.T) {
			var source, declarations, prototypes, kernels strings.Builder
			for index, row := range rows[start:end] {
				name := fmt.Sprintf("SelfCompare%d", start+index)
				ins := x86ScalarLaneInstruction(t, row.row)
				destination := string(ins.Args[len(ins.Args)-1].Reg)
				fmt.Fprintf(&declarations, "func %s(out *byte, mask uint64)\n", name)
				fmt.Fprintf(&prototypes, "extern void %s(uint8_t*,uint64_t);\n", name)
				fmt.Fprintf(&source, "TEXT %s(SB),4,$0-16\nMOVQ out+0(FP),DI\nMOVQ mask+8(FP),AX\nKMOVQ AX,K1\n", name)
				source.WriteString("MOVL $0x7fffffff,DX\nADDL $1,DX\nSTC\n" + row.row + "\n")
				bits := row.width
				selected := strings.Contains(string(ins.Op), "EQ")
				if row.maskResult {
					lane := map[byte]int{'B': 8, 'W': 16, 'L': 32, 'D': 32, 'Q': 64}[ins.Op[len(ins.Op)-1]]
					bits = row.width * 8 / lane
					if ins.Args[0].Kind == OpImm {
						// Intel's eight integer predicates on x,x: EQ, LT,
						// LE, false, NE, NLT, NLE, true. High five bits are ignored.
						selected = [8]bool{true, false, true, false, false, true, false, true}[ins.Args[0].Imm&7]
					}
					fmt.Fprintf(&source, "KMOVQ %s,AX\nMOVQ AX,0(DI)\n", destination)
				} else if row.legacy {
					// Legacy MOVOU retains a native x86 memory opcode. Extract
					// both halves instead, so the observer is also portable.
					for lane := 0; lane < 2; lane++ {
						fmt.Fprintf(&source, "PEXTRQ $%d,%s,AX\nMOVQ AX,%d(DI)\n", lane, destination, lane*8)
					}
				} else {
					fmt.Fprintf(&source, "VMOVUPS %s,0(DI)\n", destination)
				}
				source.WriteString("SETCS 64(DI)\nSETOS 65(DI)\nSETEQ 66(DI)\nSETMI 67(DI)\nRET\n")
				fmt.Fprintf(&kernels, "{%s,%d,%t,%t,%t},\n", name, bits, selected, row.masked, row.maskResult)
			}
			x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source.String())
			driver := strings.ReplaceAll(x86IntegerSelfCompareValueDriver, "PROTOTYPES", prototypes.String())
			driver = strings.ReplaceAll(driver, "KERNELS", kernels.String())
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", execution.triple, api)
				if err != nil {
					t.Fatal("complete self-initializing programs", api, err)
				}
				for _, text := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
					for _, level := range []string{"-O0", "-O2"} {
						execution.compileAndRunLLVM(t, "integer-self-compare", text, driver, level)
					}
				}
			}
		})
	}
	t.Log("all24 names, legacy/VEX/EVEX views, masks/aliases, eight predicates and high control bits; actual-host portable, not native AVX512")
}

const x86IntegerSelfCompareValueDriver = `
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
PROTOTYPES
struct kernel {
    void (*run)(uint8_t*,uint64_t);
    unsigned bits;
    _Bool selected, masked, maskResult;
};
static const struct kernel kernels[] = { KERNELS };
int main(void) {
    const uint64_t masks[] = {0,1,UINT64_C(0x55aa55aa55aa55aa),UINT64_MAX};
    const uint8_t flags[] = {1,1,0,1};
    for (unsigned k=0;k<sizeof(kernels)/sizeof(kernels[0]);++k) {
        const struct kernel *kernel=&kernels[k];
        for (unsigned m=0;m<sizeof(masks)/sizeof(masks[0]);++m) {
            uint8_t output[96];
            memset(output,0xa7,sizeof(output));
            kernel->run(output+1,masks[m]);
            unsigned size=kernel->maskResult ? 8 : kernel->bits;
            if (kernel->maskResult) {
                uint64_t got, want=0;
                memcpy(&got,output+1,8);
                if (kernel->selected) {
                    want=kernel->bits==64 ? UINT64_MAX : (UINT64_C(1)<<kernel->bits)-1;
                }
                if (kernel->masked) want&=masks[m];
                if (got!=want) {
                    fprintf(stderr,"self-compare kernel=%u mask=%u got=%llx want=%llx\n",
                        k,m,(unsigned long long)got,(unsigned long long)want);
                    return 1;
                }
            } else {
                for (unsigned b=0;b<size;++b) {
                    uint8_t want=kernel->selected ? 0xff : 0;
                    if (output[1+b]!=want) {
                        fprintf(stderr,"self-compare kernel=%u mask=%u byte=%u got=%x want=%x\n",
                            k,m,b,output[1+b],want);
                        return 1;
                    }
                }
            }
            if (memcmp(output+65,flags,4) || output[0]!=0xa7) {
                fprintf(stderr,"self-compare kernel=%u mask=%u status/canary\n",k,m);
                return 1;
            }
            for (unsigned i=1;i<sizeof(output);++i) {
                if (i<=size || (i>=65 && i<69)) continue;
                if (output[i]!=0xa7) {
                    fprintf(stderr,"self-compare kernel=%u mask=%u canary=%u\n",k,m,i);
                    return 2;
                }
            }
        }
    }
    return 0;
}
`
