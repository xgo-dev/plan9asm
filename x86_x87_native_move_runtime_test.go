package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

func TestX86X87NativeFloatingMovesPortableValuesAndCanaries(t *testing.T) {
	execution := x86ScalarCountHostExecution(t)
	arch := "amd64"
	if strconv.IntSize == 32 {
		arch = "386"
	}
	var source, declarations strings.Builder
	for _, op := range []string{"FMOVF", "FMOVFP", "FMOVD", "FMOVDP"} {
		text, declaration := x86X87NativeMoveProgram(arch, op)
		source.WriteString(strings.ReplaceAll(text, "Value", op))
		declarations.WriteString(strings.ReplaceAll(declaration, "Value", op) + "\n")
	}
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86X87InitializedWordAPI(t, source.String(), declarations.String(), arch, execution.triple, api, X87Software)
			if err != nil || ir == "" {
				t.Fatal("portable original floating move program", err)
			}
			for _, text := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
				for _, level := range []string{"-O0", "-O2"} {
					execution.compileAndRunLLVM(t, "x87-floating-moves", text, x86X87NativeMoveValueDriver, level)
				}
			}
		})
	}
}

const x86X87NativeMoveValueDriver = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
extern uint32_t FMOVF(const uint8_t*,uint8_t*), FMOVFP(const uint8_t*,uint8_t*);
extern uint32_t FMOVD(const uint8_t*,uint8_t*), FMOVDP(const uint8_t*,uint8_t*);
int main(void) {
    const uint64_t values[]={0,UINT64_C(0x8000000000000000),1,
        UINT64_C(0x0010000000000000),UINT64_C(0x3ff0000000000000),
        UINT64_C(0xbff0000000000000),UINT64_C(0x7fefffffffffffff),
        UINT64_C(0x7ff0000000000000),UINT64_C(0xfff0000000000000)};
    uint32_t (*calls[])(const uint8_t*,uint8_t*)={FMOVF,FMOVFP,FMOVD,FMOVDP};
    for(unsigned op=0;op<4;++op) for(unsigned row=0;row<257;++row) {
        uint64_t bits=values[row%(sizeof(values)/sizeof(values[0]))];
        if(op<2) {
            const uint32_t small[]={0,0x80000000,1,0x00800000,0x3f800000,
                0xbf800000,0x7f7fffff,0x7f800000,0xff800000};
            bits=small[row%(sizeof(small)/sizeof(small[0]))];
        }
        const unsigned width=op<2 ? 4 : 8;
        uint8_t input[18],before[18],output[18],want[18];
        memset(input,0x5c,sizeof(input)); memset(output,0xa7,sizeof(output));
        memcpy(input+1,&bits,width); memcpy(before,input,sizeof(input));
        memcpy(want,output,sizeof(output)); memcpy(want+1,&bits,width);
        if(calls[op](input,output)!=7 || memcmp(input,before,sizeof(input)) ||
            memcmp(output,want,sizeof(output))) {
            fprintf(stderr,"floating native move op=%u row=%u\n",op,row); return 1;
        }
    }
    return 0;
}
`

func TestX86StackNativeReadWidthsRemainObservable(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word, move, suffix := 8, "MOVQ", "Q"
		if target.arch == "386" {
			word, move, suffix = 4, "MOVL", "L"
		}
		for _, width := range []string{"W", suffix} {
			source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s src+0(FP),SI\nPUSH%s 1(SI)\nPOP%s AX\nMOVL $7,AX\nMOVL AX,ret+%d(FP)\nRET\n", word+4, move, width, width, word)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+width+"/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(src *byte) uint32", target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("dead PUSH input", err)
					}
					bits := 16
					if width != "W" {
						bits = word * 8
					}
					for _, text := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
						if strings.Count(text, fmt.Sprintf("load volatile i%d,", bits)) != 1 {
							t.Fatal("discarded PUSH lost its exact native read width", width)
						}
					}
				})
			}
		}
	}
}

func TestX87DirectFlagCompareOriginalProgramPortable(t *testing.T) {
	execution := x86ScalarCountHostExecution(t)
	arch := "amd64"
	if strconv.IntSize == 32 {
		arch = "386"
	}
	requireX86GoAssemblerResult(t, arch, x87FlagCompareAssembly(arch), true)
	x87DirectFlagCompareRuntimeWithMode(t, arch, execution.triple, X87Software, func(t *testing.T, ir, main string) {
		for _, level := range []string{"-O0", "-O2"} {
			execution.compileAndRunLLVM(t, "original-x87-direct-flags", ir, main, level)
		}
	})
}

func TestX86X87AndStackNativeDeadAccessFaults(t *testing.T) {
	execution := x86ScalarCountHostExecution(t)
	arch, word, move, suffix := "amd64", 8, "MOVQ", "Q"
	if strconv.IntSize == 32 {
		arch, word, move, suffix = "386", 4, "MOVL", "L"
	}
	var source, declarations, prototypes, callbacks, rows strings.Builder
	add := func(body string, bytes int) {
		name := fmt.Sprintf("nativeDeadAccess%d", strings.Count(declarations.String(), "func "))
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s input+0(FP),SI\n%sMOVL $7,AX\nMOVL AX,ret+%d(FP)\nRET\n", name, word+4, move, body, word)
		fmt.Fprintf(&declarations, "func %s(input *byte) uint32\n", name)
		fmt.Fprintf(&prototypes, "extern uint32_t %s(const uint8_t*);\n", name)
		fmt.Fprintf(&callbacks, "static int run%s(const uint8_t *p) {return %s((const uint8_t*)((uintptr_t)p-1))==7 ? 0 : 91;}\n", name, name)
		fmt.Fprintf(&rows, "{run%s,%d,%d},\n", name, bytes, bytes-1)
	}
	for _, row := range []struct {
		op    string
		bytes int
	}{{"FMOVF", 4}, {"FMOVD", 8}} {
		add("FINIT\n"+row.op+" 1(SI),F0\nFINIT\n", row.bytes)
		for _, pop := range []string{"", "P"} {
			add("FINIT\nFLD1\n"+row.op+pop+" F0,1(SI)\nFINIT\n", row.bytes)
		}
	}
	add("PUSHW 1(SI)\nPOPW AX\n", 2)
	add("PUSH"+suffix+" 1(SI)\nPOP"+suffix+" AX\n", word)
	driver := x86MemoryFaultDriver(prototypes.String()+callbacks.String(), rows.String())
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86X87InitializedWordAPI(t, source.String(), declarations.String(), arch, execution.triple, api, X87Software)
			if err != nil || ir == "" {
				t.Fatal("native dead-access source", err)
			}
			for _, text := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
				for _, level := range []string{"-O0", "-O2"} {
					executable := execution.compileLLVM(t, "x87-stack-dead-faults", text, driver, level)
					x86CheckMemoryFaultMatrix(t, execution, executable, 8)
				}
			}
		})
	}
}
