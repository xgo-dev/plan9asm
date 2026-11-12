package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86BLSPortableCompleteFamilyAliasesFlagsAndDeadReads(t *testing.T) {
	execution := x86ScalarCountHostExecution(t)
	var source, declarations, prototypes, rows, faults strings.Builder
	for kind, family := range []string{"BLSI", "BLSMSK", "BLSR"} {
		for _, bits := range []int{32, 64} {
			suffix := "L"
			if bits == 64 {
				suffix = "Q"
			}
			op := family + suffix
			for ordinal, input := range []string{"AX", "BX", "(AX)"} {
				name := fmt.Sprintf("%sCase%d", op, ordinal)
				typ, cType, argument := "uint64", "uint64_t", "value"
				if ordinal == 2 {
					typ, cType, argument = "*uint64", "const uint64_t*", "&value"
				}
				fmt.Fprintf(&declarations, "func %s(source %s, out *[16]byte)\n", name, typ)
				fmt.Fprintf(&source, "TEXT %s(SB),4,$0-16\nMOVQ source+0(FP),AX\nMOVQ AX,BX\nMOVQ out+8(FP),DI\n", name)
				// Preset every defined status bit oppositely where possible.
				source.WriteString("MOVL $0x7fffffff,DX\nADDL $1,DX\nSTC\n")
				fmt.Fprintf(&source, "%s %s,AX\nMOVQ AX,0(DI)\nSETCS 8(DI)\nSETOS 9(DI)\nSETEQ 10(DI)\nSETMI 11(DI)\nRET\n", op, input)
				fmt.Fprintf(&prototypes, "extern void %s(%s,uint8_t*);\nstatic void call%s(uint64_t value,uint8_t *out) { %s(%s,out); }\n", name, cType, name, name, argument)
				fmt.Fprintf(&rows, "{call%s,%d,%d},\n", name, bits, kind)
			}
			name := "Dead" + op
			fmt.Fprintf(&declarations, "func %s(source *byte)\n", name)
			fmt.Fprintf(&source, "TEXT %s(SB),4,$0-8\nMOVQ source+0(FP),AX\n%s (AX),BX\nRET\n", name, op)
			fmt.Fprintf(&prototypes, "extern void %s(const uint8_t*);\nstatic int fault%s(const uint8_t *p) { %s(p); return 0; }\n", name, name, name)
			fmt.Fprintf(&faults, "{fault%s,%d,%d},\n", name, bits/8, bits/8-1)
		}
	}
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source.String())
	valueDriver := strings.ReplaceAll(x86BLSPortableValueDriver, "PROTOTYPES", prototypes.String())
	valueDriver = strings.ReplaceAll(valueDriver, "ROWS", rows.String())
	faultDriver := x86MemoryFaultDriver(prototypes.String(), faults.String())
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", execution.triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, optimize := range []bool{false, true} {
				text := ir
				if optimize {
					text = x86MulDivRoundOptimize(t, ir)
				}
				for _, level := range []string{"-O0", "-O2"} {
					t.Run(fmt.Sprintf("IR_O2=%t/backend%s", optimize, level), func(t *testing.T) {
						execution.compileAndRunLLVM(t, "bls-values", text, valueDriver, level)
						executable := execution.compileLLVM(t, "bls-dead-reads", text, faultDriver, level)
						x86CheckMemoryFaultMatrix(t, execution, executable, 6)
					})
				}
			}
		})
	}
	t.Log("six BLS names, independent values, aliases, defined flags, canaries and dead read faults; actual-host portable LLVM execution")
}

const x86BLSPortableValueDriver = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
PROTOTYPES
struct kernel {
    void (*run)(uint64_t,uint8_t*);
    unsigned bits, kind;
};
static const struct kernel kernels[] = { ROWS };

static uint64_t independent_bls(uint64_t source,unsigned bits,unsigned kind) {
    const uint64_t mask=bits==32 ? UINT64_C(0xffffffff) : UINT64_MAX;
    source&=mask;
    unsigned first=0;
    while (first<bits && !(source&(UINT64_C(1)<<first))) ++first;
    uint64_t result=0;
    for (unsigned bit=0;bit<bits;++bit) {
        const unsigned set=kind==0 ? bit==first :
            kind==1 ? bit<=first : bit!=first && ((source>>bit)&1);
        if (set) result|=UINT64_C(1)<<bit;
    }
    return result;
}

int main(void) {
    static const uint64_t edges[]={0,1,2,10,UINT64_MAX,
        UINT64_C(0x80000000),UINT64_C(0x8000000000000000)};
    for (unsigned k=0;k<sizeof(kernels)/sizeof(kernels[0]);++k) {
        uint64_t random=UINT64_C(0xa31d5f0986b7c4e2);
        for (unsigned sample=0;sample<1031;++sample) {
            random=random*UINT64_C(6364136223846793005)+1;
            const uint64_t input=sample<7 ? edges[sample] : random;
            const uint64_t source=kernels[k].bits==32 ? (uint32_t)input : input;
            const uint64_t value=independent_bls(source,kernels[k].bits,kernels[k].kind);
            uint8_t out[32],expected[32];
            memset(out,0xa5,sizeof(out));
            memcpy(expected,out,sizeof(out));
            memcpy(expected+8,&value,8);
            expected[16]=kernels[k].kind==0 ? source!=0 : source==0;
            expected[17]=0;
            expected[18]=value==0;
            expected[19]=(value>>(kernels[k].bits-1))&1;
            kernels[k].run(input,out+8);
            if (memcmp(out,expected,sizeof(out))) {
                fprintf(stderr,"BLS kernel=%u sample=%u\n",k,sample);
                return 1;
            }
        }
    }
    return 0;
}
`
