package plan9asm

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func x86AverageValueRuntimeProgram(arch string) (string, string, string, string) {
	return x86AverageValueRuntimeProgramWithResult(arch, false)
}

func x86AverageValueRuntimeProgramWithResult(arch string, discard bool) (string, string, string, string) {
	return x86FixedBinaryValueRuntimeProgram(arch, discard, "Average", x86AverageValueRows, func(op string) (int, int) {
		if strings.HasSuffix(op, "W") {
			return 16, 0
		}
		return 8, 0
	})
}

func x86FixedBinaryValueRuntimeProgram(arch string, discard bool, prefix string,
	inventory func(string) []struct{ op, bank, mode string }, reference func(string) (int, int)) (string, string, string, string) {
	word, move, maskMove, cWord := 8, "MOVQ", "KMOVQ", "uint64_t"
	if arch == "386" {
		word, move, maskMove, cWord = 4, "MOVL", "KMOVD", "uint32_t"
	}
	var source, declarations, prototypes, rows strings.Builder
	for index, row := range inventory(arch) {
		name := fmt.Sprintf("%s%d", prefix, index)
		instruction := row.op + " X0,X2"
		setup, width, mode, legacy := "VMOVUPS (AX),Z0\n", 16, 0, 1
		if strings.HasPrefix(row.op, "V") {
			op, mask := row.op, ""
			setup, legacy = "", 0
			if row.bank == "Y" {
				width = 32
			} else if row.bank == "Z" {
				width = 64
			}
			if row.mode != "plain" {
				mask, mode = "K1,", 1
			}
			if row.mode == "zero" {
				op, mode = op+".Z", 2
			}
			instruction = op + " (AX)," + row.bank + "1," + mask + row.bank + "2"
		}
		bits, operation := reference(row.op)
		finish := "VMOVUPS Z2,(SI)\n"
		if discard {
			finish = "" // Preserve every source read and CF observation, discard only the numerical result.
		}
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s a+0(FP),AX\n%s b+%d(FP),BX\n%s out+%d(FP),SI\n"+
			"%s mask+%d(FP),CX\n%s CX,K1\nVMOVUPS (BX),Z1\nVMOVUPS (BX),Z2\n%sSTC\n%s\n%sSETCS 64(SI)\nRET\n",
			name, 4*word, move, move, word, move, 2*word, move, 3*word, maskMove, setup, instruction, finish)
		fmt.Fprintf(&declarations, "func %s(a,b,out *[65]byte,mask uintptr)\n", name)
		fmt.Fprintf(&prototypes, "extern void %s(uint8_t*,uint8_t*,uint8_t*,%s);\n", name, cWord)
		fmt.Fprintf(&rows, "{%s,%d,%d,%d,%d,%d},\n", name, width, bits, mode, legacy, operation)
	}
	return source.String(), declarations.String(), prototypes.String(), rows.String()
}

func TestX86PackedAverageCompletePortableValuesAndCanaries(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc and clang required")
	}
	arch, cWord := "amd64", "uint64_t"
	if strconv.IntSize == 32 {
		arch, cWord = "386", "uint32_t"
	}
	source, declarations, prototypes, rows := x86AverageValueRuntimeProgram(arch)
	x86LEAActualTargetGoObject(t, arch, map[string]string{"amd64": "x86_64-unknown-linux-gnu", "386": "i386-unknown-linux-gnu"}[arch], source)
	driver := "#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n" + prototypes +
		"typedef " + cWord + " average_word;\n" + `
struct kernel {void (*fn)(uint8_t*,uint8_t*,uint8_t*,average_word);unsigned width,bits,mode,legacy,operation;};
static const struct kernel kernels[]={
` + rows + `};
int main(void) {
    const average_word masks[]={0,1,(average_word)0xa55a9c63f00fc33cULL,(average_word)-1};
    for(unsigned k=0;k<sizeof(kernels)/sizeof(kernels[0]);k++)for(unsigned sample=0;sample<257;sample++) {
        const struct kernel *p=&kernels[k];
        uint8_t a[67],b[67],a_before[67],b_before[67],out[67],want[64];
        for(unsigned i=0;i<67;i++){a[i]=(i*73+sample*29)^sample;b[i]=(i*47+sample*113)^(sample>>1);}
        memcpy(a_before,a,67);memcpy(b_before,b,67);
        for(unsigned m=0;m<sizeof(masks)/sizeof(masks[0]);m++) {
            memset(out,0xc3,67);
            memcpy(want,b+1,64);
            if(!p->legacy)memset(want+p->width,0,64-p->width);
            unsigned bytes=p->bits/8;
            for(unsigned lane=0;lane<p->width/bytes;lane++) {
                unsigned at=lane*bytes;
                if(p->mode && !(masks[m]>>lane&1)) {
                    if(p->mode==2)memset(want+at,0,bytes);
                    continue;
                }
                uint32_t left=a[at+1],right=b[at+1];
                if(bytes==2){left|=(uint32_t)a[at+2]<<8;right|=(uint32_t)b[at+2]<<8;}
                uint32_t average=(left+right+1)>>1;
                want[at]=average;
                if(bytes==2)want[at+1]=average>>8;
            }
            p->fn(a+1,b+1,out+1,masks[m]);
            if(memcmp(out+1,want,64)||out[65]!=1||out[0]!=0xc3||out[66]!=0xc3||
                memcmp(a,a_before,67)||memcmp(b,b_before,67)) {
                fprintf(stderr,"average row=%u sample=%u mask=%u width=%u mode=%u legacy=%u\n",k,sample,m,p->width,p->mode,p->legacy);
                return 1;
            }
        }
    }
    return 0;
}
`
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, triple, api)
			if err != nil {
				t.Fatal("complete initialized average execution source rejected", err)
			}
			for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
				for _, level := range []int{0, 2} {
					compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "average-values", triple, text, driver, nil, level)
				}
			}
		})
	}
	t.Log("complete byte/word averages, full 64-byte aliases, merge/zero masks, CF and canaries; portable LLVM, not native AVX512")
}
