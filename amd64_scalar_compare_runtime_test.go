package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86ScalarCompareFlags(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	var source, declarations, native, prototypes, pairs strings.Builder
	count := 0
	for _, op := range x86ScalarCompareNames("amd64") {
		rows := []string{"(DX),CX", "CX,(DX)"}
		for _, immediate := range []string{"0", "127", "128", "255", "32768", "65535", "2147483648", "4294967295", "-2147483648"} {
			rows = append(rows, strings.TrimPrefix(x86ScalarCompareInstruction(op, "(DX)", "$"+immediate), op+" "))
		}
		if strings.HasSuffix(op, "B") {
			rows = append(rows, "CH,(DX)", "(DX),CH", "CL,CH", "CH,CL", "BH,R8B", "R8B,DH")
		}
		for _, row := range rows {
			name, original := fmt.Sprintf("compare%d", count), fmt.Sprintf("original%d", count)
			mask := 0x8d5 // CF, PF, AF, ZF, SF, OF only.
			if strings.HasPrefix(op, "TEST") {
				mask &^= 0x10 // TEST leaves AF undefined; never invent an oracle value.
			}
			body := op + " " + row
			setup, originalSetup := "", ""
			if strings.Contains(row, "R8B") {
				setup = "MOVQ x+8(FP),DI\nMOVQ x+8(FP),SI\nMOVQ x+8(FP),R8\nNOTQ R8\n"
				originalSetup = "MOVQ SI,DI\nMOVQ SI,R8\nNOTQ R8\n"
			}
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-24\nMOVQ p+0(FP),DX\nMOVQ x+8(FP),CX\n%s%s\nPUSHFQ\nPOPQ AX\nANDQ $%d,AX\nMOVQ AX,ret+16(FP)\nRET\n", name, setup, body, mask)
			fmt.Fprintf(&declarations, "func %s(p *byte,x uint64) uint64\n", name)
			originalBody := strings.ReplaceAll(body, "DX", "DI")
			code := x86PackedShiftActualGoBytes(t, "amd64", fmt.Sprintf("TEXT f(SB),4,$0-0\nMOVQ SI,CX\n%s%s\nPUSHFQ\nPOPQ AX\nANDQ $%d,AX\nRET\n", originalSetup, originalBody, mask))
			if len(code) < 9 || code[len(code)-1] != 0xc3 {
				t.Fatal("original Go flags program is incomplete", body, code)
			}
			var bytes []string
			for _, b := range code {
				bytes = append(bytes, fmt.Sprintf("0x%02x", b))
			}
			symbol := original
			if strings.Contains(execution.triple, "apple") {
				symbol = "_" + symbol
			}
			fmt.Fprintf(&native, "__asm__(%q);\n", ".text\n.globl "+symbol+"\n"+symbol+":\n.byte "+strings.Join(bytes, ",")+"\n")
			fmt.Fprintf(&prototypes, "extern uint64_t %s(uint8_t*,uint64_t);\n", name)
			prototypes.WriteString(x86OriginalSysVDeclaration("uint64_t", original, "uint8_t*,uint64_t"))
			fmt.Fprintf(&pairs, "{%s,%s},\n", original, name)
			count++
		}
	}
	goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
	main := `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
` + prototypes.String() + native.String() + x86OriginalSysVPointer("uint64_t", "original_program", "uint8_t*,uint64_t") + `
typedef uint64_t (*program)(uint8_t*,uint64_t);
static const struct { original_program original; program translated; } pairs[]={
` + pairs.String() + `};
int main(void) {
    const uint64_t patterns[]={0,1,15,16,127,128,255,256,32767,32768,65535,65536,
        UINT64_C(0x7fffffff),UINT64_C(0x80000000),UINT64_C(0xffffffff),
        UINT64_C(0x7fffffffffffffff),UINT64_C(0x8000000000000000),
        UINT64_C(0xffffffffffffffff),UINT64_C(0x55aa0123cdef9876)};
    for(unsigned i=0;i<sizeof(pairs)/sizeof(*pairs);++i) {
        for(unsigned a=0;a<sizeof(patterns)/sizeof(*patterns);++a) {
            uint8_t data[24]; memset(data,0xa5,sizeof(data));
            memcpy(data+3,&patterns[a],8);
            for(unsigned b=0;b<sizeof(patterns)/sizeof(*patterns);++b) {
                uint64_t x=pairs[i].original(data+3,patterns[b]);
                uint64_t y=pairs[i].translated(data+3,patterns[b]);
                if(x!=y || data[2]!=0xa5 || data[11]!=0xa5) {
                    fprintf(stderr,"compare=%u a=%u b=%u original=%llx llvm=%llx\n",
                        i,a,b,(unsigned long long)x,(unsigned long long)y);
                    return 1;
                }
            }
        }
    }
    printf("%zu original Go compare/test programs x 361 patterns\n",sizeof(pairs)/sizeof(*pairs));
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
					output := execution.compileAndRunLLVM(t, "scalar-compare-flags", pipeline.ir, main, pipeline.level)
					if string(output) != fmt.Sprintf("%d original Go compare/test programs x 361 patterns\n", count) {
						t.Fatalf("missing complete original/LLVM numerical receipt: %s", output)
					}
				})
			}
		})
	}
}
