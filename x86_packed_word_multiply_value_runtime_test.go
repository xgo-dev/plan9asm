package plan9asm

import (
	"fmt"
	"runtime"
	"strconv"
	"testing"
)

func x86WordMultiplyValueRuntimeProgram(arch string, discard bool) (string, string, string, string) {
	return x86FixedBinaryValueRuntimeProgram(arch, discard, "WordMultiplyValue", x86WordMultiplyValueRows, func(op string) (int, int) {
		return 16, x86WordMultiplyReferenceMode(op)
	})
}

// Mathematical integer reference, independent of the emitter and its spec map.
// Signed high uses floor division; rounded signed high wraps, never saturates.
const x86WordMultiplyPortableReference = `
static uint16_t product(uint16_t a,uint16_t b,unsigned operation) {
    if(operation==0)return (uint16_t)((uint32_t)a*b);
    if(operation==2)return (uint16_t)(((uint32_t)a*b)/65536);
    int64_t x=a<32768?a:(int64_t)a-65536,y=b<32768?b:(int64_t)b-65536;
    int64_t value=x*y,divisor=65536;
    if(operation==3){value+=16384;divisor=32768;}
    return (uint16_t)(value<0?-((-value+divisor-1)/divisor):value/divisor);
}
`

func TestX86PackedWordMultiplyCompletePortableValuesAndCanaries(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc and clang required")
	}
	arch, cWord, want := "amd64", "uint64_t", 40
	if strconv.IntSize == 32 {
		arch, cWord, want = "386", "uint32_t", 16
	}
	source, declarations, prototypes, rows := x86WordMultiplyValueRuntimeProgram(arch, false)
	x86LEAActualTargetGoObject(t, arch, map[string]string{"amd64": "x86_64-unknown-linux-gnu", "386": "i386-unknown-linux-gnu"}[arch], source)
	driver := "#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n" + prototypes +
		"typedef " + cWord + " source_word;\n" + x86WordMultiplyPortableReference + `
struct kernel {void (*fn)(uint8_t*,uint8_t*,uint8_t*,source_word);unsigned width,bits,mode,legacy,operation;};
static const struct kernel kernels[]={
` + rows + `};
int main(void) {
    const source_word masks[]={0,1,(source_word)0xa55a9c63f00fc33cULL,(source_word)-1};
    const uint16_t edges[]={0,1,2,0x3fff,0x4000,0x4001,0x7fff,0x8000,0x8001,0xbfff,0xc000,0xfffe,0xffff};
    if(sizeof(kernels)/sizeof(kernels[0])!=` + fmt.Sprint(want) + `)return 1;
    for(unsigned k=0;k<sizeof(kernels)/sizeof(kernels[0]);k++)for(unsigned sample=0;sample<257;sample++) {
        const struct kernel *p=&kernels[k];
        uint8_t a[67],b[67],a_before[67],b_before[67],out[67],want[64];
        memset(a,0xa7,sizeof(a));memset(b,0xb9,sizeof(b));
        for(unsigned i=0;i<64;i+=2) {
            uint16_t x=edges[(sample+i/2)%13],y=edges[(sample/13+i/2*3)%13];
            if(sample>169){x=(uint16_t)(sample*71+i*7919);y=(uint16_t)(sample*13+i*37);}
            a[i+1]=x;a[i+2]=x>>8;b[i+1]=y;b[i+2]=y>>8;
        }
        memcpy(a_before,a,67);memcpy(b_before,b,67);
        for(unsigned m=0;m<sizeof(masks)/sizeof(masks[0]);m++) {
            memset(out,0xc3,67);
            memcpy(want,b+1,64);
            if(!p->legacy)memset(want+p->width,0,64-p->width);
            for(unsigned lane=0;lane<p->width/2;lane++) {
                unsigned at=lane*2;
                if(p->mode && !(masks[m]>>lane&1)) {
                    if(p->mode==2)memset(want+at,0,2);
                    continue;
                }
                uint16_t left=(uint16_t)a[at+1]|(uint16_t)a[at+2]<<8;
                uint16_t right=(uint16_t)b[at+1]|(uint16_t)b[at+2]<<8;
                uint16_t value=product(left,right,p->operation);
                want[at]=value;want[at+1]=value>>8;
            }
            p->fn(a+1,b+1,out+1,masks[m]);
            if(memcmp(out+1,want,64)||out[65]!=1||out[0]!=0xc3||out[66]!=0xc3||
                memcmp(a,a_before,67)||memcmp(b,b_before,67)) {
                fprintf(stderr,"word multiply row=%u sample=%u mask=%u width=%u mode=%u legacy=%u\n",k,sample,m,p->width,p->mode,p->legacy);
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
				t.Fatal("complete word-multiply execution source rejected", err)
			}
			for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
				for _, level := range []int{0, 2} {
					compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "word-multiply-values", triple, text, driver, nil, level)
				}
			}
		})
	}
	t.Log("complete eight-member family: integer edges, upper aliases, merge/zero masks, CF and canaries; portable LLVM, not native AVX512")
}
