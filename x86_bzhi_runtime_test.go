package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86BZHIEveryIndexAliasesFlagsAndDeadReadFaults(t *testing.T) {
	execution := x86ScalarCountHostExecution(t)
	var source, declarations, prototypes, rows strings.Builder
	for _, op := range []string{"BZHIL", "BZHIQ"} {
		bits := 32
		if op == "BZHIQ" {
			bits = 64
		}
		for _, memory := range []bool{false, true} {
			for _, destination := range []string{"AX", "BX", "CX"} {
				name := fmt.Sprintf("ZeroHigh%d%t%s", bits, memory, destination)
				parameter, input, cType := "uint64", "BX", "uint64_t"
				if memory {
					parameter, input, cType = "*uint64", "(BX)", "const uint64_t*"
				}
				fmt.Fprintf(&declarations, "func %s(control uint64, source %s, out *[16]byte)\n", name, parameter)
				fmt.Fprintf(&source, "TEXT %s(SB),4,$0-24\nMOVQ control+0(FP),AX\nMOVQ source+8(FP),BX\nMOVQ out+16(FP),DI\n", name)
				source.WriteString("MOVL $0x7fffffff,DX\nADDL $1,DX\nSTC\n")
				fmt.Fprintf(&source, "%s AX,%s,%s\nMOVQ %s,0(DI)\nSETCS 8(DI)\nSETOS 9(DI)\nSETEQ 10(DI)\nSETMI 11(DI)\nRET\n", op, input, destination, destination)
				fmt.Fprintf(&prototypes, "extern void %s(uint64_t,%s,uint8_t*);\n", name, cType)
				argument := "value"
				if memory {
					argument = "&value"
				}
				fmt.Fprintf(&prototypes, "static void call%s(uint64_t control,uint64_t value,uint8_t *out) {\n", name)
				prototypes.WriteString("    uint64_t before=value;\n")
				fmt.Fprintf(&prototypes, "    %s(control,%s,out);\n", name, argument)
				prototypes.WriteString("    if (value!=before) abort();\n}\n")
				fmt.Fprintf(&rows, "{call%s,%d},\n", name, bits)
			}
		}
	}
	for _, width := range []struct {
		op    string
		bytes int
	}{{"BZHIL", 4}, {"BZHIQ", 8}} {
		// Even an index of zero and an unused result must retain the complete
		// native source read. No valid pointee or alignment is assumed.
		fmt.Fprintf(&source, "TEXT Dead%d(SB),4,$0-8\nMOVQ source+0(FP),BX\nMOVB $0,AL\n%s AX,(BX),CX\nRET\n", width.bytes, width.op)
		fmt.Fprintf(&declarations, "func Dead%d(source *byte)\n", width.bytes)
		fmt.Fprintf(&prototypes, "extern void Dead%d(const uint8_t*);\nstatic int fault%d(const uint8_t *p) { Dead%d(p); return 0; }\n", width.bytes, width.bytes, width.bytes)
	}
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source.String())
	valueDriver := strings.ReplaceAll(x86BZHIEveryIndexDriver, "PROTOTYPES", prototypes.String())
	valueDriver = strings.ReplaceAll(valueDriver, "ROWS", rows.String())
	faultDriver := x86MemoryFaultDriver(prototypes.String(), "{fault4,4,3},\n{fault8,8,7},\n")
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", execution.triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, optimized := range []bool{false, true} {
				text := ir
				if optimized {
					text = x86MulDivRoundOptimize(t, ir)
				}
				for _, level := range []string{"-O0", "-O2"} {
					t.Run(fmt.Sprintf("IR_O2=%t/backend%s", optimized, level), func(t *testing.T) {
						execution.compileAndRunLLVM(t, "bzhi-values", text, valueDriver, level)
						executable := execution.compileLLVM(t, "bzhi-faults", text, faultDriver, level)
						x86CheckMemoryFaultMatrix(t, execution, executable, 2)
					})
				}
			}
		})
	}
	t.Log("all256 indices, ignored high control bits, register/native sources, aliases, CF/OF/ZF/SF, canaries and dead read faults; actual-host portable, not native x86")
}

const x86BZHIEveryIndexDriver = `
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
PROTOTYPES
struct kernel {
    void (*run)(uint64_t,uint64_t,uint8_t*);
    unsigned bits;
};
static const struct kernel kernels[] = { ROWS };

static uint64_t independent_zero_high(uint64_t value,unsigned bits,unsigned index) {
    uint64_t result=0;
    for (unsigned bit=0;bit<bits && bit<index;++bit) {
        result|=((value>>bit)&1)<<bit;
    }
    return result;
}

int main(void) {
    static const uint64_t samples[] = {
        0,1,UINT64_MAX,UINT64_C(0x80000000),
        UINT64_C(0x8000000000000000),UINT64_C(0x0123456789abcdef)
    };
    static const uint64_t high[] = {
        0,UINT64_C(0x0123456789abcd00),UINT64_MAX-255
    };
    for (unsigned k=0;k<sizeof(kernels)/sizeof(kernels[0]);++k) {
        for (unsigned s=0;s<sizeof(samples)/sizeof(samples[0]);++s) {
            for (unsigned h=0;h<sizeof(high)/sizeof(high[0]);++h) {
                for (unsigned index=0;index<256;++index) {
                    uint8_t out[32],expected[32];
                    memset(out,0xa5,sizeof(out));
                    memset(expected,0xa5,sizeof(expected));
                    unsigned bits=kernels[k].bits;
                    uint64_t value=independent_zero_high(samples[s],bits,index);
                    memcpy(expected+8,&value,sizeof(value));
                    expected[16]=index>=bits;
                    expected[17]=0;
                    expected[18]=value==0;
                    expected[19]=(value>>(bits-1))&1;
                    kernels[k].run(high[h]|index,samples[s],out+8);
                    if (memcmp(out,expected,sizeof(out))) {
                        fprintf(stderr,"BZHI kernel=%u sample=%u high=%u index=%u mismatch\n",k,s,h,index);
                        return 1;
                    }
                }
            }
        }
    }
    return 0;
}
`
