package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// Execute the complete BIT numerical/native-memory LLVM model on the actual
// host. The original Go opcode execution remains owned by the unchanged Linux
// counterpart; Go object acceptance and portable execution are distinct claims.
func TestX86BitTestPortableNumericalAndAliases(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM22 llc/clang required")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var source, declarations, prototypes, pairs strings.Builder
	count := 0
	for _, op := range x86BitTestOracleNames("amd64") {
		width := map[byte]int{'W': 2, 'L': 4, 'Q': 8}[op[len(op)-1]]
		operation := map[string]int{"BT": 0, "BTC": 1, "BTR": 2, "BTS": 3}[op[:len(op)-1]]
		for _, memory := range []bool{false, true} {
			for _, index := range []string{"CX", "$-128", "$-1", "$0", "$15", "$16", "$31", "$32", "$63", "$64", "$127", "DX"} {
				if memory && index == "DX" {
					continue
				}
				name := fmt.Sprintf("portable%d", count)
				destination, after := "DX", "MOVQ DX,(DI)\n"
				memoryFlag, mode, immediate := 0, 0, 0
				if memory {
					destination, after, memoryFlag = "(DI)", "", 1
				}
				if strings.HasPrefix(index, "$") {
					mode = 1
					if _, err := fmt.Sscanf(index, "$%d", &immediate); err != nil {
						t.Fatal(err)
					}
				} else if index == "DX" {
					mode = 2
				}
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-32\nMOVQ p+0(FP),DI\nMOVQ index+8(FP),CX\nMOVQ value+16(FP),DX\nCMPQ DX,DX\n%s %s,%s\nPUSHFQ\nPOPQ AX\nANDQ $65,AX\n%sMOVQ AX,ret+24(FP)\nRET\n", name, op, index, destination, after)
				fmt.Fprintf(&declarations, "func %s(p *byte,index int64,value uint64) uint64\n", name)
				fmt.Fprintf(&prototypes, "extern uint64_t %s(uint8_t*,int64_t,uint64_t);\n", name)
				fmt.Fprintf(&pairs, "{%s,%d,%d,%d,%d,%d},\n", name, width, operation, memoryFlag, mode, immediate)
				count++
			}
		}
	}
	goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
	main := `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
` + prototypes.String() + `
typedef uint64_t (*program)(uint8_t*,int64_t,uint64_t);
static const struct { program translated; int width,op,memory,mode,immediate; } pairs[]={
` + pairs.String() + `};
int main(void) {
    const int64_t indexes[]={-255,-129,-128,-65,-64,-33,-32,-17,-16,-1,0,1,15,16,31,32,63,64,65,127,255};
    const uint64_t values[]={0,1,UINT64_MAX,UINT64_C(0x8000000000000000),
        UINT64_C(0x55aa0123cdef9876),UINT64_C(0x12345678ffffffff)};
    for(unsigned i=0;i<sizeof(pairs)/sizeof(*pairs);++i) {
        for(unsigned j=0;j<sizeof(indexes)/sizeof(*indexes);++j) {
            for(unsigned v=0;v<sizeof(values)/sizeof(*values);++v) {
                uint8_t translated[512],expected[512];
                for(unsigned b=0;b<sizeof(expected);++b) expected[b]=(uint8_t)(b*71+v*3);
                memcpy(translated,expected,sizeof(expected));
                int bits=8*pairs[i].width;
                uint64_t index=pairs[i].mode==1?(uint64_t)pairs[i].immediate:
                    pairs[i].mode==2?values[v]:(uint64_t)indexes[j];
                int64_t offset=0;
                if(pairs[i].memory && pairs[i].mode!=1) {
                    int64_t signedIndex=bits==16?(int16_t)index:bits==32?(int32_t)index:(int64_t)index;
                    offset=(signedIndex>=0?signedIndex/bits:-1-((-1-signedIndex)/bits))*pairs[i].width;
                }
                uint64_t old=values[v];
                if(pairs[i].memory) {
                    old=0;
                    memcpy(&old,expected+257+offset,pairs[i].width);
                }
                uint64_t selected=UINT64_C(1)<<(index&(bits-1));
                uint64_t flags=64|!!(old&selected),result=old;
                if(pairs[i].op==1) result^=selected;
                if(pairs[i].op==2) result&=~selected;
                if(pairs[i].op==3) result|=selected;
                if(pairs[i].memory) {
                    if(pairs[i].op) memcpy(expected+257+offset,&result,pairs[i].width);
                } else {
                    if(pairs[i].op && bits==32) result=(uint32_t)result;
                    memcpy(expected+257,&result,8);
                }
                uint64_t actual=pairs[i].translated(translated+257,indexes[j],values[v]);
                if(actual!=flags || memcmp(translated,expected,sizeof(expected))) {
                    fprintf(stderr,"portable bit test=%u index=%lld value=%llx expected flags=%llx LLVM=%llx\n",
                        i,(long long)indexes[j],(unsigned long long)values[v],(unsigned long long)flags,(unsigned long long)actual);
                    return 1;
                }
            }
        }
    }
    printf("%zu LLVM bit programs x 126 independent whole-memory, alias and CF/ZF checks\n",sizeof(pairs)/sizeof(*pairs));
    return 0;
}
`
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, optimized := range []bool{false, true} {
				for _, level := range []int{0, 2} {
					t.Run(fmt.Sprintf("IR-O2=%t/backend-O%d", optimized, level), func(t *testing.T) {
						objectIR := ir
						if optimized {
							objectIR = x86MulDivRoundOptimize(t, ir)
						}
						execution := x86FloatCompareExecution{llc: llc, triple: triple, compiler: []string{clang}}
						output := execution.compileAndRunLLVM(t, "portable-bit-test", objectIR, main, fmt.Sprintf("-O%d", level))
						want := fmt.Sprintf("%d LLVM bit programs x 126 independent whole-memory, alias and CF/ZF checks\n", count)
						if string(output) != want {
							t.Fatalf("missing portable numerical receipt: %s", output)
						}
					})
				}
			}
		})
	}
}
