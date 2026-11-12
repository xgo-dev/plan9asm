package plan9asm

import "testing"

func TestX86ScalarCountOriginalLZCNTProgramPortableAndObjects(t *testing.T) {
	execution := x86ScalarCountHostExecution(t)
	source := x86LZCNTOriginalRuntimeSource
	declaration := "func lzcntsemantics(out *[56]byte)"
	for _, target := range x86RawReturnTargets {
		if target.arch != "amd64" {
			continue // The unchanged original source contains LZCNTQ.
		}
		t.Run(target.triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "amd64", target.triple, "#include \"textflag.h\"\n"+source)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", target.triple, api)
				if err != nil {
					t.Fatal("complete original LZCNT runtime source", api, err)
				}
				for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, execution.llc, target.triple, text, level)
					}
				}
			}
		})
	}
	for _, api := range []string{"text", "module", "Go"} {
		t.Run("portable/"+api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", execution.triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
				for _, level := range []string{"-O0", "-O2"} {
					execution.compileAndRunLLVM(t, "original-lzcnt", text, x86LZCNTOriginalPortableDriver, level)
				}
			}
		})
	}
	t.Log("unchanged original source: Go objects, three-target LLVM objects and actual-host portable values/FLAGS/canaries; not original x86 execution")
}

const x86LZCNTOriginalPortableDriver = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
extern void lzcntsemantics(uint8_t *);
int main(void) {
    uint8_t out[72], expected[72];
    memset(out,0xa5,sizeof(out));
    memcpy(expected,out,sizeof(out));
    const uint64_t values[] = {UINT64_C(0xaabbccddeeff0010),0,1,63};
    const unsigned offsets[] = {0,16,32,40};
    for (unsigned i=0;i<4;++i) memcpy(expected+8+offsets[i],&values[i],8);
    expected[8+8]=1; expected[8+9]=0;
    expected[8+24]=0; expected[8+25]=1;
    expected[8+48]=0; expected[8+49]=0;
    lzcntsemantics(out+8);
    for (unsigned i=0;i<sizeof(out);++i) {
        if (out[i]!=expected[i]) {
            fprintf(stderr,"original LZCNT byte=%u got=%x want=%x\n",i,out[i],expected[i]);
            return 1;
        }
    }
    return 0;
}
`
