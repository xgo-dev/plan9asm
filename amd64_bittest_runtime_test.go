package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// The original Go machine bytes and this independent whole-byte reference
// agree separately with LLVM. CF and preserved ZF are compared; the ISA's
// undefined OF/SF/AF/PF are deliberately not assigned invented expectations.
func TestCrossLinuxRuntimeMatrixX86BitTestNumericalAndAliases(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	var source, declarations, native, prototypes, pairs strings.Builder
	count := 0
	for _, op := range x86BitTestOracleNames("amd64") {
		width := map[byte]int{'W': 2, 'L': 4, 'Q': 8}[op[len(op)-1]]
		operation := map[string]int{"BT": 0, "BTC": 1, "BTR": 2, "BTS": 3}[op[:len(op)-1]]
		for _, memory := range []bool{false, true} {
			for _, index := range []string{"CX", "$-128", "$-1", "$0", "$15", "$16", "$31", "$32", "$63", "$64", "$127", "DX"} {
				if memory && index == "DX" {
					continue // DX/DX is the separate register alias axis.
				}
				name, original := fmt.Sprintf("numeric%d", count), fmt.Sprintf("original%d", count)
				destination, originalDestination, after := "DX", "DX", "MOVQ DX,(DI)\n"
				memoryFlag, mode, immediate := 0, 0, 0
				if memory {
					destination, originalDestination, after, memoryFlag = "(DI)", "(DI)", "", 1
				}
				if strings.HasPrefix(index, "$") {
					mode = 1
					if _, err := fmt.Sscanf(index, "$%d", &immediate); err != nil {
						t.Fatal(err)
					}
				} else if index == "DX" {
					mode = 2
				}
				body := op + " " + index + "," + destination
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-32\nMOVQ p+0(FP),DI\nMOVQ index+8(FP),CX\nMOVQ value+16(FP),DX\nCMPQ DX,DX\n%s\nPUSHFQ\nPOPQ AX\nANDQ $65,AX\n%sMOVQ AX,ret+24(FP)\nRET\n", name, body, after)
				fmt.Fprintf(&declarations, "func %s(p *byte,index int64,value uint64) uint64\n", name)
				code := x86PackedShiftActualGoBytes(t, "amd64", "TEXT f(SB),4,$0-0\nMOVQ SI,CX\nCMPQ DX,DX\n"+op+" "+index+","+originalDestination+"\nPUSHFQ\nPOPQ AX\nANDQ $65,AX\n"+after+"RET\n")
				var bytes []string
				for _, b := range code {
					bytes = append(bytes, fmt.Sprintf("0x%02x", b))
				}
				symbol := original
				if strings.Contains(execution.triple, "apple") {
					symbol = "_" + symbol
				}
				fmt.Fprintf(&native, "__asm__(%q);\n", ".text\n.globl "+symbol+"\n"+symbol+":\n.byte "+strings.Join(bytes, ",")+"\n")
				fmt.Fprintf(&prototypes, "extern uint64_t %s(uint8_t*,int64_t,uint64_t);\n", name)
				prototypes.WriteString(x86OriginalSysVDeclaration("uint64_t", original, "uint8_t*,int64_t,uint64_t"))
				fmt.Fprintf(&pairs, "{%s,%s,%d,%d,%d,%d,%d},\n", original, name, width, operation, memoryFlag, mode, immediate)
				count++
			}
		}
	}
	goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
	main := `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
` + prototypes.String() + native.String() +
		x86OriginalSysVPointer("uint64_t", "originalProgram", "uint8_t*,int64_t,uint64_t") + `
typedef uint64_t (*program)(uint8_t*,int64_t,uint64_t);
static const struct { originalProgram original; program translated; int width,op,memory,mode,immediate; } pairs[]={
` + pairs.String() + `};
int main(void) {
    const int64_t indexes[]={-255,-129,-128,-65,-64,-33,-32,-17,-16,-1,0,1,15,16,31,32,63,64,65,127,255};
    const uint64_t values[]={0,1,UINT64_MAX,UINT64_C(0x8000000000000000),
        UINT64_C(0x55aa0123cdef9876),UINT64_C(0x12345678ffffffff)};
    for(unsigned i=0;i<sizeof(pairs)/sizeof(*pairs);++i) {
        for(unsigned j=0;j<sizeof(indexes)/sizeof(*indexes);++j) {
            for(unsigned v=0;v<sizeof(values)/sizeof(*values);++v) {
                uint8_t original[512],translated[512],expected[512];
                for(unsigned b=0;b<sizeof(expected);++b) expected[b]=(uint8_t)(b*71+v*3);
                memcpy(original,expected,sizeof(expected));
                memcpy(translated,expected,sizeof(expected));
                int bits=8*pairs[i].width;
                uint64_t index=pairs[i].mode==1?(uint64_t)pairs[i].immediate:
                    pairs[i].mode==2?values[v]:(uint64_t)indexes[j];
                int64_t offset=0;
                if(pairs[i].memory && pairs[i].mode!=1) {
                    int64_t signedIndex=bits==16?(int16_t)index:bits==32?(int32_t)index:(int64_t)index;
                    /* Floor division, not C's truncation toward zero. */
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
                uint64_t a=pairs[i].original(original+257,indexes[j],values[v]);
                uint64_t b=pairs[i].translated(translated+257,indexes[j],values[v]);
                if(a!=flags || b!=flags || memcmp(original,expected,sizeof(expected)) || memcmp(translated,expected,sizeof(expected))) {
                    fprintf(stderr,"bit test=%u index=%lld value=%llx expected flags=%llx Go=%llx LLVM=%llx\n",
                        i,(long long)indexes[j],(unsigned long long)values[v],(unsigned long long)flags,(unsigned long long)a,(unsigned long long)b);
                    return 1;
                }
            }
        }
    }
    printf("%zu original Go/LLVM bit tests x 126 independent whole-memory, alias and CF/ZF checks\n",sizeof(pairs)/sizeof(*pairs));
    return 0;
}

`
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", execution.triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, pipeline := range []struct{ name, level, ir string }{
				{"backend_O0", "-O0", ir},
				{"IR_O2/backend_O2", "-O2", x86MulDivRoundOptimize(t, ir)},
			} {
				t.Run(pipeline.name, func(t *testing.T) {
					output := execution.compileAndRunLLVM(t, "bit-test-numerical", pipeline.ir, main, pipeline.level)
					want := fmt.Sprintf("%d original Go/LLVM bit tests x 126 independent whole-memory, alias and CF/ZF checks\n", count)
					if string(output) != want {
						t.Fatalf("missing independent original/LLVM numerical receipt: %s", output)
					}
				})
			}
		})
	}
}
