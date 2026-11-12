package plan9asm

import "testing"

// Execute the exact discovering Windows source on the actual host through its
// portable unaligned LLVM operations. This supplements, not skips or replaces,
// the unchanged original native-x86 runtime test.
func TestX86PackedLogicalParameterOriginalProgramPortable(t *testing.T) {
	execution := x86ScalarCountHostExecution(t)
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", x86VMOVDQUAggregateFPOriginalSource)
	const declaration = "func vmovAggregateFP(out *byte,key0,key1,key2,key3 uint32)"
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, x86VMOVDQUAggregateFPOriginalSource, declaration,
				"amd64", execution.triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, text := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
				for _, level := range []string{"-O0", "-O2"} {
					execution.compileAndRunLLVM(t, "packed-private-copy", text, x86PackedLogicalParameterValueDriver, level)
				}
			}
		})
	}
}

const x86PackedLogicalParameterValueDriver = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
extern void vmovAggregateFP(uint8_t*,uint32_t,uint32_t,uint32_t,uint32_t);
int main(void) {
    for (uint32_t row=0;row<257;++row) {
        const uint32_t input[]={row*UINT32_C(0x9e3779b9),~row,row<<24,UINT32_MAX-row};
        uint32_t original[4]; memcpy(original,input,sizeof(input));
        uint8_t output[34]; memset(output,0xa7,sizeof(output));
        vmovAggregateFP(output+1,input[0],input[1],input[2],input[3]);
        for (unsigned byte=0;byte<16;++byte) {
            uint8_t want=(uint8_t)(input[byte/4]>>(8*(byte%4)));
            if (output[1+byte]!=want || output[17+byte]!=0) {
                fprintf(stderr,"packed private copy row=%u byte=%u\n",row,byte);
                return 1;
            }
        }
        if (memcmp(input,original,sizeof(input)) || output[0]!=0xa7 || output[33]!=0xa7) {
            fprintf(stderr,"packed private copy row=%u input/canary\n",row);
            return 1;
        }
    }
    return 0;
}
`
