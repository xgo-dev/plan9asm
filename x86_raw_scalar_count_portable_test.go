package plan9asm

import (
	"fmt"
	"runtime"
	"testing"
)

// Execute the exact original raw-count source on the actual host. Numerical
// values, partial-register preservation, CF/ZF and memory canaries are distinct
// from required native x86 original-opcode and ISA-feature execution.
func TestX86RawScalarCountOriginalPortableExecution(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM22 llc/clang required")
	}
	const main = `#include <stdint.h>
#include <stdio.h>
#include <string.h>
extern void rawbitcountsemantics(uint8_t*);
int main(void) {
    uint8_t storage[74];
    memset(storage,0xc3,sizeof(storage));
    uint8_t *out=storage+1;
    rawbitcountsemantics(out);
    const struct { unsigned offset; uint64_t want; } values[]={
        {0,UINT64_C(0x12340010)},{16,0},{32,64},{48,0x100},{56,55}
    };
    for (unsigned row=0;row<sizeof(values)/sizeof(values[0]);row++) {
        uint64_t got;
        memcpy(&got,out+values[row].offset,8);
        if (got!=values[row].want) {
            fprintf(stderr,"raw count offset=%u got=%llx want=%llx\n",values[row].offset,
                    (unsigned long long)got,(unsigned long long)values[row].want);
            return 1;
        }
    }
    const unsigned flags[]={8,9,24,25,40,41,64,65};
    const uint8_t wantFlags[]={1,0,0,1,1,0,0,0};
    for (unsigned row=0;row<sizeof(flags)/sizeof(flags[0]);row++) {
        if (out[flags[row]]!=wantFlags[row]) {
            fprintf(stderr,"raw count flags offset=%u\n",flags[row]);
            return 1;
        }
    }
    for (unsigned byte=0;byte<72;byte++) {
        int written=byte<10 || (byte>=16 && byte<26) || (byte>=32 && byte<42) ||
                    (byte>=48 && byte<66);
        if (!written && out[byte]!=0xc3) return 1;
    }
    if (storage[0]!=0xc3 || storage[73]!=0xc3) return 1;
    return 0;
}
`
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, x86RawCountOriginalRuntimeSource,
				"func rawbitcountsemantics(out *[72]byte)", "amd64", triple, api)
			if err != nil {
				t.Fatal("original raw count source lost its native output continuation", err)
			}
			for index, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
				for _, level := range []string{"-O0", "-O2"} {
					compileAndRunRuntimeTestForTarget(t, llc, clang,
						fmt.Sprintf("raw-count-%s-ir%d-%s", api, index, level[1:]), triple, text, main, nil)
				}
			}
		})
	}
}
