package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// Keep the discovering source unchanged. Actual-host LLVM execution supplements
// the native x86/MXCSR owner; portable value parity does not certify that axis.
func TestX86MaskVectorOriginalProgramsPortableCompleteBytes(t *testing.T) {
	execution := x86ScalarCountHostExecution(t)
	source, _, _ := x86MaskVectorRuntimeFixture(t)
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source)
	var declarations, prototypes, checks strings.Builder
	count := 0
	for _, row := range x86OfficialMaskVectorRows(t) {
		for range []string{"K0", "K7"} {
			name := fmt.Sprintf("maskvector%d", count)
			count++
			fmt.Fprintf(&declarations, "func %s(out,in *byte,mask uint64)\n", name)
			fmt.Fprintf(&prototypes, "extern void %s(uint8_t*,const uint8_t*,uint64_t);\n", name)
			width := 16
			if strings.Contains(row, "Y1") {
				width = 32
			} else if strings.Contains(row, "Z1") {
				width = 64
			}
			toVector := strings.HasPrefix(row, "VPMOVM2")
			lane := strings.TrimPrefix(strings.TrimSuffix(strings.Fields(row)[0], "2M"), "VPMOV")
			lane = strings.TrimPrefix(lane, "M2")
			laneBytes := map[string]int{"B": 1, "W": 2, "D": 4, "Q": 8}[lane]
			if laneBytes == 0 {
				t.Fatal("unmodeled independent runtime lane", row)
			}
			fmt.Fprintf(&checks, "if(check(%s,\"%s\",%d,%d,%t)) return 1;\n", name, name, width, laneBytes, toVector)
		}
	}
	if count != 48 {
		t.Fatal("incomplete original mask/vector program union", count)
	}
	driver := strings.NewReplacer("PROTOTYPES", prototypes.String(), "CHECKS", checks.String()).Replace(x86MaskVectorPortableDriver)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, declarations.String(), "amd64", execution.triple, api)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(ir, "define void @") != count {
				t.Fatal("translation omitted an original mask/vector function")
			}
			for _, text := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
				for _, level := range []string{"-O0", "-O2"} {
					execution.compileAndRunLLVM(t, "mask-vector-original-portable", text, driver, level)
				}
			}
		})
	}
}

const x86MaskVectorPortableDriver = `
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
PROTOTYPES
static int check(void (*program)(uint8_t*,const uint8_t*,uint64_t),
                 const char *name,unsigned width,unsigned lane,bool toVector) {
    const uint64_t masks[]={0,1,UINT64_MAX,UINT64_C(0x55aa55aa55aa55aa),UINT64_C(1)<<63};
    for (unsigned round=0;round<4;++round) for (unsigned m=0;m<5;++m) {
        uint8_t input[66],original[66],output[84];
        for (unsigned i=0;i<66;++i) input[i]=(uint8_t)(i*19+round*83+129);
        memcpy(original,input,sizeof(input));
        memset(output,0xc3,sizeof(output));
        program(output+1,input+1,masks[m]);
        uint64_t gotMask,otherMask,wantMask=masks[m];
        memcpy(&gotMask,output+65,8);
        memcpy(&otherMask,output+73,8);
        if (!toVector) {
            wantMask=0;
            for (unsigned element=0;element<width/lane;++element)
                wantMask|=(uint64_t)(input[1+element*lane+lane-1]>>7)<<element;
        }
        if (output[0]!=0xc3 || output[83]!=0xc3 || output[81]!=1 || output[82]!=0 ||
            gotMask!=wantMask || otherMask!=UINT64_C(0x8123456789abcdef) ||
            memcmp(input,original,sizeof(input))) {
            fprintf(stderr,"%s round=%u mask=%u mask/flags/input/canary failure\n",name,round,m);
            return 1;
        }
        for (unsigned i=0;i<64;++i) {
            uint8_t want=input[1+i];
            if (toVector) want=i>=width ? 0 : (masks[m]>>(i/lane)&1) ? 255 : 0;
            if (output[1+i]!=want) {
                fprintf(stderr,"%s round=%u mask=%u byte=%u got=%x want=%x\n",name,round,m,i,output[1+i],want);
                return 1;
            }
        }
    }
    return 0;
}
int main(void) {
CHECKS
    return 0;
}
`
