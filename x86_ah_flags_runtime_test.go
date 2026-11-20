package plan9asm

import (
	"runtime"
	"testing"
)

func TestX86AHFlagsPortableNumericalValues(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc and clang required")
	}
	source, declarations := x86AHFlagsCompleteSource("amd64")
	const driver = `#include <stdint.h>
#include <stdio.h>
extern uint32_t AHLoad(uint32_t,uint32_t);
extern uint32_t AHStoreAndLoad(uint16_t);
extern uint32_t AHPreserveOF(uint16_t,uint32_t,uint32_t);
extern uint32_t AHByteOnly(uint8_t);
static uint32_t low_flags(uint32_t a,uint32_t b) {
    uint32_t r=a-b,p=(uint8_t)r;
    p^=p>>4;p^=p>>2;p^=p>>1;
    return (a<b)|(((p&1)==0)<<2)|(((a^b^r)>>4&1)<<4)|((r==0)<<6)|((r>>31)<<7)|2;
}
int main(void) {
    const uint32_t edges[]={0,1,15,16,127,128,255,256,65535,65536,0x7fffffff,0x80000000,0xffffffff};
    for(unsigned seed=0;seed<256;seed++) {
        uint16_t flags=(uint16_t)(seed<<8)|(seed^255);
        uint32_t packed=(seed&0xd5)|2;
        if(AHStoreAndLoad(flags)!=packed||AHByteOnly(seed)!=packed)return 1;
        for(unsigned i=0;i<sizeof(edges)/sizeof(edges[0]);i++)for(unsigned j=0;j<sizeof(edges)/sizeof(edges[0]);j++) {
            uint32_t a=edges[i],b=edges[j],sum=a+b;
            uint32_t overflow=((~(a^b)&(a^sum))>>31)&1;
            uint32_t got=AHLoad(a,b),combined=AHPreserveOF(flags,a,b);
            if(got!=low_flags(a,b)||combined!=(packed|(overflow<<8))) {
                fprintf(stderr,"AH/FLAGS seed=%u a=%x b=%x load=%x expected=%x combined=%x\n",
                    seed,a,b,got,low_flags(a,b),combined);
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
			ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", triple, api)
			if err != nil {
				t.Fatal("complete portable AH/FLAGS program rejected", err)
			}
			for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
				for _, level := range []int{0, 2} {
					compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "ah-flags-values", triple, text, driver, nil, level)
				}
			}
		})
	}
}
