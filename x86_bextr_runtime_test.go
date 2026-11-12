package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86BEXTROriginalProgramPortableAndObjects(t *testing.T) {
	execution := x86ScalarCountHostExecution(t)
	const declaration = "func bextrsemantics(out *[56]byte)"
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-macosx", "x86_64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "amd64", triple, "#include \"textflag.h\"\n"+x86BEXTROriginalRuntimeSource)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, x86BEXTROriginalRuntimeSource, declaration, "amd64", triple, api)
				if err != nil {
					t.Fatal("unchanged original CI source", api, err)
				}
				for _, text := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, execution.llc, triple, text, level)
					}
				}
			}
		})
	}
	for _, api := range []string{"text", "module", "Go"} {
		t.Run("portable/"+api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, x86BEXTROriginalRuntimeSource, declaration, "amd64", execution.triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, text := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
				for _, level := range []string{"-O0", "-O2"} {
					execution.compileAndRunLLVM(t, "original-bextr", text, x86BEXTROriginalRuntimeDriver, level)
				}
			}
		})
	}
	t.Log("original Go objects and three-target LLVM objects; actual-host portable values/FLAGS, not native x86 execution")
}

func TestX86BEXTRPortableCompleteControlsAliasesAndFaults(t *testing.T) {
	execution := x86ScalarCountHostExecution(t)
	var source, declarations, prototypes, rows strings.Builder
	for _, op := range []string{"BEXTRL", "BEXTRQ"} {
		bits := 32
		if op == "BEXTRQ" {
			bits = 64
		}
		for _, memory := range []bool{false, true} {
			for _, destination := range []string{"AX", "BX", "CX"} {
				name := fmt.Sprintf("Extract%d%t%s", bits, memory, destination)
				typ, input, cType := "uint64", "BX", "uint64_t"
				if memory {
					typ, input, cType = "*uint64", "(BX)", "const uint64_t*"
				}
				fmt.Fprintf(&declarations, "func %s(control uint16, source %s, out *[16]byte)\n", name, typ)
				fmt.Fprintf(&source, "TEXT %s(SB),4,$0-24\nMOVW control+0(FP),AX\nMOVQ source+8(FP),BX\nMOVQ out+16(FP),DI\n", name)
				source.WriteString("MOVL $0x7fffffff,DX\nADDL $1,DX\nSTC\n")
				fmt.Fprintf(&source, "%s AX,%s,%s\nMOVQ %s,0(DI)\nSETCS 8(DI)\nSETOS 9(DI)\nSETEQ 10(DI)\nRET\n", op, input, destination, destination)
				fmt.Fprintf(&prototypes, "extern void %s(uint16_t,%s,uint8_t*);\n", name, cType)
				// A uniform C wrapper keeps pointer/scalar call types distinct.
				argument := "value"
				if memory {
					argument = "&value"
				}
				fmt.Fprintf(&prototypes, "static void call%s(uint16_t control,uint64_t value,uint8_t *out) { %s(control,%s,out); }\n", name, name, argument)
				fmt.Fprintf(&rows, "{call%s,%d},\n", name, bits)
			}
		}
	}
	// A dead result and LEN=0 must still perform the entire source read.
	for _, width := range []struct {
		op    string
		bytes int
	}{{"BEXTRL", 4}, {"BEXTRQ", 8}} {
		fmt.Fprintf(&source, "TEXT Dead%d(SB),4,$0-8\nMOVQ source+0(FP),BX\nMOVW $0,AX\n%s AX,(BX),CX\nRET\n", width.bytes, width.op)
		fmt.Fprintf(&declarations, "func Dead%d(source *byte)\n", width.bytes)
		fmt.Fprintf(&prototypes, "extern void Dead%d(const uint8_t*);\nstatic int fault%d(const uint8_t *p) { Dead%d(p); return 0; }\n", width.bytes, width.bytes, width.bytes)
	}
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source.String())
	valueDriver := strings.ReplaceAll(x86BEXTRPortableValueDriver, "PROTOTYPES", prototypes.String())
	valueDriver = strings.ReplaceAll(valueDriver, "ROWS", rows.String())
	faultDriver := x86MemoryFaultDriver(prototypes.String(), "{fault4,4,3},\n{fault8,8,7},\n")
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
						execution.compileAndRunLLVM(t, "bextr-values", text, valueDriver, level)
						executable := execution.compileLLVM(t, "bextr-faults", text, faultDriver, level)
						x86CheckMemoryFaultMatrix(t, execution, executable, 2)
					})
				}
			}
		})
	}
	t.Log("all 65,536 START/LEN pairs, source edges, aliases, CF/OF/ZF, canaries and dead read faults; actual-host portable, not native x86")
}

const x86BEXTRPortableValueDriver = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
PROTOTYPES
struct kernel {
    void (*run)(uint16_t,uint64_t,uint8_t*);
    unsigned bits;
};
static const struct kernel kernels[] = { ROWS };

static uint64_t independent_extract(uint64_t value,unsigned bits,unsigned control) {
    const unsigned start=control&255, length=(control>>8)&255;
    uint64_t result=0;
    for (unsigned bit=0;bit<length && start+bit<bits;++bit) {
        result|=((value>>(start+bit))&1)<<bit;
    }
    return result;
}

int main(void) {
    static const uint64_t samples[] = {
        0,1,UINT64_MAX,UINT64_C(0x8000000000000000),
        UINT64_C(0x80000000),UINT64_C(0x0123456789abcdef)
    };
    for (unsigned k=0;k<sizeof(kernels)/sizeof(kernels[0]);++k) {
        for (unsigned sample=0;sample<sizeof(samples)/sizeof(samples[0]);++sample) {
            for (unsigned control=0;control<65536;++control) {
                uint8_t out[32],expected[32];
                memset(out,0xa5,sizeof(out));
                memcpy(expected,out,sizeof(out));
                const uint64_t value=independent_extract(samples[sample],kernels[k].bits,control);
                memcpy(expected+8,&value,8);
                expected[16]=0; expected[17]=0; expected[18]=value==0;
                kernels[k].run((uint16_t)control,samples[sample],out+8);
                if (memcmp(out,expected,sizeof(out))) {
                    fprintf(stderr,"BEXTR kernel=%u sample=%u control=%x\n",k,sample,control);
                    return 1;
                }
            }
        }
    }
    return 0;
}
`
