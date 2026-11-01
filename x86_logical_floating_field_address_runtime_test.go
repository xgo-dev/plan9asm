package plan9asm

import (
	"strconv"
	"strings"
	"testing"
)

func TestX86LogicalFloatingFieldAddressPortableExactBits(t *testing.T) {
	execution := x86ScalarCountHostExecution(t)
	arch := "amd64"
	if strconv.IntSize == 32 {
		arch = "386"
	}
	var source, declarations strings.Builder
	for _, kind := range []string{"float32", "float64"} {
		extent, move := 16, "MOVSS"
		if kind == "float64" {
			move = "MOVSD"
		} else if arch == "386" {
			extent = 8
		}
		for _, operation := range []string{"Copy", "Zero"} {
			body, declaration := x86LogicalFloatingFieldCopy(arch, kind, extent)
			if operation == "Zero" {
				body = strings.Replace(body, move+" (AX),X0", "PXOR X1,X1\n"+move+" X1,(AX)\n"+move+" (AX),X0", 1)
			}
			name := operation + kind
			source.WriteString(strings.ReplaceAll(body, "Value", name))
			declarations.WriteString(strings.ReplaceAll(declaration, "Value", name) + "\n")
		}
	}
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), arch, execution.triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, text := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
				for _, level := range []string{"-O0", "-O2"} {
					execution.compileAndRunLLVM(t, "logical-floating-fields", text, x86LogicalFloatingFieldBitDriver, level)
				}
			}
		})
	}
	t.Log("portable LLVM exact bits and private-copy canaries; not native original x86 execution")
}

const x86LogicalFloatingFieldBitDriver = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
extern float Copyfloat32(float), Zerofloat32(float);
extern double Copyfloat64(double), Zerofloat64(double);
int main(void) {
    const uint64_t edges[]={0,UINT64_MAX,1,UINT64_C(0x8000000080000000),
        0x007fffff,0x00800000,0x3f800000,0x7f800000,0xff800000,0x7fc12345,0x7f800123,
        UINT64_C(0x000fffffffffffff),UINT64_C(0x0010000000000000),
        UINT64_C(0x3ff0000000000000),UINT64_C(0x7ff0000000000000),
        UINT64_C(0xfff0000000000000),UINT64_C(0x7ff8000012345678),
        UINT64_C(0x7ff0000012345678)};
    for (unsigned row=0;row<sizeof(edges)/sizeof(edges[0])+257;++row) {
        uint64_t input=row<sizeof(edges)/sizeof(edges[0]) ? edges[row] :
            row*UINT64_C(0x9e3779b97f4a7c15);
        uint32_t small=(uint32_t)input;
        struct {uint64_t left,got[4],right;} output;
        memset(&output,0xa7,sizeof(output));
        float f,fs; double d,ds;
        memcpy(&f,&small,4); memcpy(&d,&input,8);
        fs=Copyfloat32(f); uint32_t bits;
        memcpy(&bits,&fs,4); output.got[0]=bits;
        ds=Copyfloat64(d); memcpy(&output.got[1],&ds,8);
        fs=Zerofloat32(f); memcpy(&bits,&fs,4); output.got[2]=bits;
        ds=Zerofloat64(d); memcpy(&output.got[3],&ds,8);
        uint32_t afterSmall; uint64_t afterLarge;
        memcpy(&afterSmall,&f,4); memcpy(&afterLarge,&d,8);
        const uint64_t want[]={small,input,0,0};
        if (memcmp(output.got,want,sizeof(want)) || afterSmall!=small || afterLarge!=input ||
            output.left!=UINT64_C(0xa7a7a7a7a7a7a7a7) ||
            output.right!=UINT64_C(0xa7a7a7a7a7a7a7a7)) {
            fprintf(stderr,"floating logical field row=%u bits/private-copy/canary\n",row);
            return 1;
        }
    }
    return 0;
}
`
