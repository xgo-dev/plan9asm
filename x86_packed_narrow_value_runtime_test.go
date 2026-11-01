package plan9asm

import (
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func x86NarrowValueRuntimeProgram(arch string, discard bool) (string, string, string, string) {
	return x86FixedBinaryValueRuntimeProgram(arch, discard, "NarrowValue", x86NarrowValueRows, func(op string) (int, int) {
		bits, operation := 16, 0
		if strings.HasPrefix(op, "PACKUS") || strings.HasPrefix(op, "VPACKUS") {
			operation = 1
		}
		if strings.Contains(op, ".BCST") {
			operation |= 2
		}
		if strings.Contains(op, "DW") || op == "PACKSSLW" {
			bits = 32
		}
		return bits, operation
	})
}

func TestX86PackedNarrowCompletePortableValuesAndCanaries(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc and clang required")
	}
	arch, cWord := "amd64", "uint64_t"
	if strconv.IntSize == 32 {
		arch, cWord = "386", "uint32_t"
	}
	source, declarations, prototypes, rows := x86NarrowValueRuntimeProgram(arch, false)
	x86LEAActualTargetGoObject(t, arch, map[string]string{"amd64": "x86_64-unknown-linux-gnu", "386": "i386-unknown-linux-gnu"}[arch], source)
	driver := "#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n" + prototypes +
		"typedef " + cWord + " narrow_word;\n" + x86NarrowIndependentCReference + `
struct kernel {void (*fn)(uint8_t*,uint8_t*,uint8_t*,narrow_word);unsigned width,bits,mode,legacy,operation;};
static const struct kernel kernels[]={
` + rows + `};
int main(void) {
    const narrow_word masks[]={0,1,(narrow_word)0xa55a9c63f00fc33cULL,(narrow_word)-1};
    for(unsigned k=0;k<sizeof(kernels)/sizeof(kernels[0]);k++)for(unsigned sample=0;sample<257;sample++) {
        const struct kernel *p=&kernels[k];
        uint8_t a[67],b[67],before_a[67],before_b[67],out[67],want[64],packed[64];
        memset(a,0xa7,sizeof(a));memset(b,0x91,sizeof(b));
        fill(a+1,p->bits/8,sample,0);fill(b+1,p->bits/8,sample,13);
        memcpy(before_a,a,sizeof(a));memcpy(before_b,b,sizeof(b));
        independent_pack(packed,a+1,b+1,p->width,p->bits/8,p->operation&1,p->operation>>1);
        for(unsigned m=0;m<sizeof(masks)/sizeof(masks[0]);m++) {
            memset(out,0xc3,sizeof(out));memcpy(want,b+1,64);
            if(!p->legacy)memset(want+p->width,0,64-p->width);
            for(unsigned byte=0;byte<p->width;byte++) {
                unsigned lane=byte/(p->bits/16);
                if(!p->mode || (masks[m]>>lane&1))want[byte]=packed[byte];
                else if(p->mode==2)want[byte]=0;
            }
            p->fn(a+1,b+1,out+1,masks[m]);
            if(memcmp(out+1,want,64)||out[65]!=1||out[0]!=0xc3||out[66]!=0xc3||
                    memcmp(a,before_a,sizeof(a))||memcmp(b,before_b,sizeof(b))) {
                fprintf(stderr,"PACK row=%u sample=%u mask=%u width=%u mode=%u legacy=%u operation=%u\n",
                    k,sample,m,p->width,p->mode,p->legacy,p->operation);
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
				t.Fatal("complete initialized packed narrow source rejected", err)
			}
			for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
				for _, level := range []int{0, 2} {
					compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "narrow-values", triple, text, driver, nil, level)
				}
			}
		})
	}
	t.Log("complete signed/unsigned saturation, 64-byte aliases, broadcast, merge/zero masks, CF and canaries; portable LLVM, not native AVX512")
}
