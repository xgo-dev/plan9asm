package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// This factored portable-value owner covers all six previously unclosed
// members, both widths and every mask mode. It is not native AVX acceptance.
func TestX86PermutationShuffleWholeValuesAndUpperAliases(t *testing.T) {
	execution := x86ScalarCountHostExecution(t)
	var source, declarations, prototypes, metadata strings.Builder
	count := 0
	for _, op := range []string{"VPERMD", "VPERMPS", "VSHUFF32X4", "VSHUFF64X2", "VSHUFI32X4", "VSHUFI64X2"} {
		selectors := []int{0}
		if strings.HasPrefix(op, "VSHUF") {
			selectors = []int{0, 3, 108, 147}
		}
		for _, selector := range selectors {
			for _, bank := range []string{"Y", "Z"} {
				for mode := 0; mode < 3; mode++ {
					name := fmt.Sprint("PermutationValue", count)
					width, bits := 32, 32
					if bank == "Z" {
						width = 64
					}
					if strings.HasSuffix(op, "64X2") {
						bits = 64
					}
					variable := op == "VPERMD" || op == "VPERMPS"
					fmt.Fprintf(&declarations, "func %s(out *[72]byte,a,b *[64]byte,mask uint64)\n", name)
					fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-32\nMOVQ out+0(FP),DI\nMOVQ a+8(FP),BX\nMOVQ b+16(FP),CX\nVMOVUPS (CX),%s1\n", name, bank)
					first, suffix := bank+"0", ""
					if mode == 0 {
						fmt.Fprintf(&source, "VMOVUPS (BX),%s0\n", bank)
					} else {
						first = "(BX)"
						source.WriteString("KMOVQ mask+24(FP),K1\n")
					}
					if mode != 2 {
						source.WriteString("VMOVUPS (DI),Z2\n")
					} else {
						suffix = ".BCST.Z" // No old destination initialization.
					}
					args := first + "," + bank + "1"
					if !variable {
						args = fmt.Sprintf("$%d,", selector) + args
					}
					if mode != 0 {
						args += ",K1"
					}
					seed := count % 3
					left, right := []int64{1, -2147483648, 5}[seed], []int64{3, 1, 5}[seed]
					fmt.Fprintf(&source, "MOVL $%d,DX\nCMPL DX,$%d\n%s%s %s,%s2\nVMOVUPS Z2,(DI)\nSETCS 64(DI)\nSETOS 65(DI)\nSETEQ 66(DI)\nRET\n", left, right, op, suffix, args, bank)
					fmt.Fprintf(&prototypes, "extern void %s(uint8_t *,const uint8_t *,const uint8_t *,uint64_t);\n", name)
					fmt.Fprintf(&metadata, "{%s,%d,%d,%t,%d,%d,%d},\n", name, width, bits/8, variable, mode, selector, 1<<uint(seed))
					count++
				}
			}
		}
	}
	if count != 108 {
		t.Fatal("complete factored six-member value directory changed", count)
	}
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source.String())
	driver := `
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
` + prototypes.String() + `
struct row { void (*run)(uint8_t *,const uint8_t *,const uint8_t *,uint64_t); unsigned width,element; bool variable; unsigned mode,selector,flags; };
static const struct row rows[] = { ` + metadata.String() + ` };
int main(void) {
    const uint64_t masks[] = {0,1,0x55,0xaa,UINT64_MAX,UINT64_C(1)<<63};
    unsigned observations=0;
    for(unsigned r=0;r<sizeof(rows)/sizeof(rows[0]);++r) {
        const struct row *row=&rows[r];
        for(unsigned sample=0;sample<32;++sample) {
            uint8_t a[64],b[64],a_before[64],b_before[64],first[64];
            for(unsigned i=0;i<64;++i) { a[i]=(uint8_t)(i*17+sample*31+1); b[i]=(uint8_t)(i*13+sample*29+7); }
            memcpy(a_before,a,64); memcpy(b_before,b,64); memcpy(first,a,64);
            if(row->mode==2) for(unsigned i=0;i<64;++i) first[i]=a[i%row->element];
            for(unsigned m=0;m<sizeof(masks)/sizeof(masks[0]);++m) {
                uint8_t output[72],expected[72];
                for(unsigned i=0;i<72;++i) output[i]=(uint8_t)(i*19+sample*11+3);
                memcpy(expected,output,72);
                for(unsigned lane=0;lane<row->width/row->element;++lane) {
                    if(row->mode && !(masks[m]>>lane&1)) {
                        if(row->mode==2) memset(expected+lane*row->element,0,row->element);
                        continue;
                    }
                    if(row->variable) {
                        uint32_t selector; memcpy(&selector,b+lane*4,4);
                        memcpy(expected+lane*4,first+(selector&(row->width/4-1))*4,4);
                    } else {
                        unsigned byte=lane*row->element,block=byte/16,blocks=row->width/16;
                        unsigned selected=blocks==2 ? (row->selector>>block)&1 : (row->selector>>(block*2))&3;
                        const uint8_t *input=block<blocks/2 ? b : first;
                        memcpy(expected+byte,input+selected*16+byte%16,row->element);
                    }
                }
                memset(expected+row->width,0,64-row->width);
                expected[64]=(row->flags&1)!=0; expected[65]=(row->flags&2)!=0; expected[66]=(row->flags&4)!=0;
                row->run(output,a,b,masks[m]);
                if(memcmp(output,expected,72) || memcmp(a,a_before,64) || memcmp(b,b_before,64)) {
                    fprintf(stderr,"permutation row=%u sample=%u mask=%u value/upper/FLAGS/canary/input mismatch\n",r,sample,m);
                    return 1;
                }
                ++observations;
            }
        }
    }
    return observations==20736 ? 0 : 2;
}
`
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", execution.triple, api)
			if err != nil || ir == "" {
				t.Fatal("initialized whole-value continuation", err)
			}
			for _, pipeline := range []struct{ name, ir, level string }{
				{"backend_O0", ir, "-O0"}, {"backend_O2", ir, "-O2"},
				{"IR_O2_backend_O2", x86DwordProductIROptimize(t, ir), "-O2"},
			} {
				t.Run(pipeline.name, func(t *testing.T) {
					execution.compileAndRunLLVM(t, "permutation-shuffle-whole-values", pipeline.ir, driver, pipeline.level)
				})
			}
		})
	}
}
