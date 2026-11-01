package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// Portable LLVM values and access extents are independent of original AVX2/
// AVX512 execution. The original native conformance owners remain unchanged.
func TestX86QwordPermuteWholeVectorPortableValuesAndUpperAliases(t *testing.T) {
	execution := x86ScalarCountHostExecution(t)
	var source, declarations, prototypes, metadata strings.Builder
	rows := x86QwordPermuteOracleRows("amd64")
	for index, row := range rows {
		name := fmt.Sprint("Value", index)
		destination := 2
		if row.mode != "merge" {
			destination = index % 3
		}
		instruction := strings.TrimSuffix(row.instruction(), row.bank+"2") + fmt.Sprint(row.bank, destination)
		fmt.Fprintf(&declarations, "func %s(out *[68]byte,data,control *[64]byte,mask uint64)\n", name)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-32\nMOVQ out+0(FP),DI\nMOVQ data+8(FP),BX\nMOVQ control+16(FP),CX\n", name)
		if row.input == "register" {
			fmt.Fprintf(&source, "VMOVUPS (BX),%s0\n", row.bank)
		}
		if !row.immediate {
			fmt.Fprintf(&source, "VMOVUPS (CX),%s1\n", row.bank)
		}
		if row.mode == "merge" {
			source.WriteString("VMOVUPS (DI),Z2\n")
		}
		if row.mode != "plain" {
			source.WriteString("KMOVQ mask+24(FP),K1\n")
		}
		fmt.Fprintf(&source, "MOVL $5,DX\nCMPL DX,$3\n%s\nVMOVUPS Z%d,(DI)\nSETCS 64(DI)\nSETOS 65(DI)\nRET\n", instruction, destination)
		fmt.Fprintf(&prototypes, "extern void %s(uint8_t *,const uint8_t *,const uint8_t *,uint64_t);\n", name)
		fmt.Fprintf(&metadata, "{%s,%d,%t,%t,%d},\n", name, row.width()/8, row.immediate, row.input == "broadcast", map[string]int{"plain": 0, "merge": 1, "zero": 2}[row.mode])
	}
	if len(rows) != 72 {
		t.Fatal("portable full-family value directory changed", len(rows))
	}
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source.String())
	driver := `
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
` + prototypes.String() + `
struct row { void (*run)(uint8_t *,const uint8_t *,const uint8_t *,uint64_t); unsigned lanes; bool immediate,broadcast; unsigned mode; };
static const struct row rows[] = { ` + metadata.String() + ` };
int main(void) {
    const uint64_t masks[] = {0,1,0x55,0xaa,UINT64_MAX,UINT64_C(1)<<63};
    unsigned observations=0;
    for(unsigned r=0;r<sizeof(rows)/sizeof(rows[0]);++r) {
        const struct row *row=&rows[r];
        for(unsigned sample=0;sample<32;++sample) {
            uint64_t data[8],control[8],data_before[8],control_before[8];
            for(unsigned lane=0;lane<8;++lane) {
                data[lane]=UINT64_C(0x9e3779b97f4a7c15)*(1+lane+sample*8);
                control[lane]=(UINT64_C(0xfedcba9876543200)*(1+sample)) | ((lane*3+sample)&7);
            }
            memcpy(data_before,data,sizeof(data));
            memcpy(control_before,control,sizeof(control));
            for(unsigned m=0;m<sizeof(masks)/sizeof(masks[0]);++m) {
                uint8_t output[68],expected[68];
                for(unsigned byte=0;byte<sizeof(output);++byte) output[byte]=(uint8_t)(byte*13+sample*7+3);
                memcpy(expected,output,sizeof(output));
                for(unsigned lane=0;lane<row->lanes;++lane) {
                    if(row->mode && !(masks[m]>>lane&1)) {
                        if(row->mode==2) memset(expected+lane*8,0,8);
                    } else {
                        unsigned selected=row->broadcast ? 0 : row->immediate ?
                            lane/4*4+((216>>(2*(lane%4)))&3) : (unsigned)(control[lane]&(row->lanes-1));
                        memcpy(expected+lane*8,&data[selected],8);
                    }
                }
                memset(expected+row->lanes*8,0,64-row->lanes*8);
                expected[64]=expected[65]=0;
                row->run(output,(const uint8_t *)data,(const uint8_t *)control,masks[m]);
                if(memcmp(output,expected,sizeof(output)) || memcmp(data,data_before,sizeof(data)) || memcmp(control,control_before,sizeof(control))) {
                    fprintf(stderr,"qword permute row=%u sample=%u mask=%u whole64/FLAGS/canary/input mismatch\n",r,sample,m);
                    return 1;
                }
                ++observations;
            }
        }
    }
    return observations==13824 ? 0 : 2;
}
`
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", execution.triple, api)
			if err != nil || ir == "" {
				t.Fatal("initialized portable whole-vector program rejected", err)
			}
			for _, pipeline := range []struct{ name, ir, level string }{
				{"backend_O0", ir, "-O0"}, {"backend_O2", ir, "-O2"}, {"IR_O2_backend_O2", x86DwordProductIROptimize(t, ir), "-O2"},
			} {
				t.Run(pipeline.name, func(t *testing.T) {
					execution.compileAndRunLLVM(t, "qword-permute-whole-values", pipeline.ir, driver, pipeline.level)
				})
			}
		})
	}
}

func TestX86QwordPermuteDeadAndZeroMaskExactNativeAccessFaults(t *testing.T) {
	execution := x86ScalarCountHostExecution(t)
	var source, declarations, prototypes, callbacks, metadata strings.Builder
	count := 0
	for _, row := range x86QwordPermuteOracleRows("amd64") {
		if row.input == "register" || row.mode == "merge" {
			continue
		}
		for _, mask := range []int{0, -1} {
			if row.mode == "plain" && mask == -1 {
				continue
			}
			name := fmt.Sprint("Access", count)
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-8\nMOVQ data+0(FP),BX\nVPXORD Z1,Z1,Z1\nMOVL $%d,AX\nKMOVD AX,K1\n%s\nRET\n", name, mask, row.instruction())
			fmt.Fprintf(&declarations, "func %s(data *[64]byte)\n", name)
			fmt.Fprintf(&prototypes, "extern void %s(const uint8_t *);\n", name)
			fmt.Fprintf(&callbacks, "static int run%d(const uint8_t *p) { %s(p); return 0; }\n", count, name)
			bytes := row.width()
			if row.input == "broadcast" {
				bytes = 8
			}
			fmt.Fprintf(&metadata, "{run%d,%d,%d},\n", count, bytes, bytes-1)
			count++
		}
	}
	if count != 48 {
		t.Fatal("complete dead E4NF tuple/mask directory changed", count)
	}
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source.String())
	driver := x86MemoryFaultDriver(prototypes.String()+callbacks.String(), metadata.String())
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", execution.triple, api)
			if err != nil || ir == "" {
				t.Fatal("dead native read lacks its original input source", err)
			}
			for _, pipeline := range []struct{ name, ir, level string }{
				{"backend_O0", ir, "-O0"}, {"backend_O2", ir, "-O2"}, {"IR_O2_backend_O2", x86DwordProductIROptimize(t, ir), "-O2"},
			} {
				t.Run(pipeline.name, func(t *testing.T) {
					executable := execution.compileLLVM(t, "qword-permute-access", pipeline.ir, driver, pipeline.level)
					x86CheckMemoryFaultMatrix(t, execution, executable, count)
				})
			}
		})
	}
	// This is actual-host portable extent evidence, not original AVX512 execution.
}
