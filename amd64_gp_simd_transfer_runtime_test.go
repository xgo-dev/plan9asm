package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// Independent full-byte results observe both directions, narrow GP extension,
// self-aliasing and untouched upper banks. Portable AVX lowering is not a
// physical AVX512 execution certificate; Linux executes the required counterpart.
func TestCrossLinuxRuntimeMatrixX86GPSIMDTransferCompleteBytes(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	var source, declarations, checks strings.Builder
	sigs := map[string]FuncSig{}
	count := 0
	for _, op := range []string{"MOVL", "MOVQ", "MOVD", "VMOVD", "VMOVQ"} {
		width := 4
		if op == "MOVQ" || op == "MOVD" || op == "VMOVQ" {
			width = 8
		}
		for _, direction := range []string{"gp-to-x", "x-to-gp", "memory-load", "memory-store", "x-to-x", "self"} {
			if (direction == "x-to-x" || direction == "self") && width == 4 {
				continue
			}
			name := fmt.Sprint("gpxtransfer", count)
			count++
			fmt.Fprintf(&source, "TEXT %s(SB),4,$0-24\nMOVQ out+0(FP),AX\nMOVQ in+8(FP),BX\nMOVQ seed+16(FP),CX\n", name)
			source.WriteString("VMOVUPS (BX),Z0\nVMOVUPS (AX),Z1\nMOVQ $-1,R11\nCMPQ AX,AX\nSTC\n")
			kind := 0
			switch direction {
			case "gp-to-x":
				fmt.Fprintf(&source, "%s CX,X1\nVMOVUPS Z1,(AX)\n", op)
			case "x-to-gp":
				kind = 1
				fmt.Fprintf(&source, "%s X0,R11\nVMOVUPS Z1,(AX)\n", op)
			case "memory-load":
				kind = 2
				fmt.Fprintf(&source, "%s 3(BX),X1\nVMOVUPS Z1,(AX)\n", op)
			case "memory-store":
				kind = 3
				fmt.Fprintf(&source, "VMOVUPS Z1,(AX)\n%s X0,3(AX)\n", op)
			case "x-to-x":
				kind = 4
				fmt.Fprintf(&source, "%s X0,X1\nVMOVUPS Z1,(AX)\n", op)
			case "self":
				kind = 5
				fmt.Fprintf(&source, "%s X1,X1\nVMOVUPS Z1,(AX)\n", op)
			}
			source.WriteString("MOVQ R11,64(AX)\nSETCS 72(AX)\nSETNE 73(AX)\nRET\n")
			sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, I64}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: I64, Index: 2, Field: -1},
			}}}
			fmt.Fprintf(&declarations, "extern void %s(uint8_t*,const uint8_t*,uint64_t);\n", name)
			fmt.Fprintf(&checks, "if(check(%s,\"%s\",%d,%d,%d)) return 1;\n", name, name, width, kind,
				x86FloatAddSubBoolInt(strings.HasPrefix(op, "V")))
		}
	}
	if count != 26 {
		t.Fatal("independent complete transfer runtime denominator changed", count)
	}
	oracle := `#include <stdint.h>
#include <stdio.h>
#include <string.h>
` + declarations.String() + `
static int check(void (*program)(uint8_t*,const uint8_t*,uint64_t),const char *name,
                 unsigned width,int kind,int vector) {
    uint64_t seeds[]={0,UINT64_MAX,UINT64_C(0x98af3bce72510d64),UINT64_C(0x8000000000000001)};
    for(unsigned s=0;s<4;s++) {
        uint8_t input[82],original[82],output[84],before[84],want[84];
        for(unsigned i=0;i<82;i++) input[i]=(uint8_t)(i*37+149);
        for(unsigned i=0;i<84;i++) output[i]=(uint8_t)(i*19+71);
        memcpy(original,input,sizeof(input)); memcpy(before,output,sizeof(output));
        memcpy(want,before,sizeof(want));
        uint64_t gp=UINT64_MAX;
        if(kind==1) { gp=0; memcpy(&gp,input+1,width); }
        else if(kind==3) memcpy(want+4,input+1,width);
        else {
            for(unsigned i=0;i<64;i++) {
                uint8_t value=before[1+i];
                if(i>=16) { if(vector) value=0; }
                else if(i>=width) value=0;
                else if(kind==0) value=(uint8_t)(seeds[s]>>(i*8));
                else if(kind==2) value=input[4+i];
                else if(kind==4) value=input[1+i];
                want[1+i]=value;
            }
        }
        memcpy(want+65,&gp,8); want[73]=1; want[74]=0;
        program(output+1,input+1,seeds[s]);
        if(memcmp(input,original,sizeof(input)) || memcmp(output,want,sizeof(output))) {
            for(unsigned i=0;i<84;i++) if(output[i]!=want[i])
                fprintf(stderr,"%s seed=%u byte=%u got=%x want=%x\n",name,s,i,output[i],want[i]);
            return 1;
        }
    }
    return 0;
}
int main(void) {
` + checks.String() + "return 0;\n}\n"
	goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	for _, optimized := range []bool{false, true} {
		t.Run(fmt.Sprintf("IR_O2=%t", optimized), func(t *testing.T) {
			text := ir
			if optimized {
				text = x86MulDivRoundOptimize(t, text)
			}
			compileAndRunRuntimeTestForTarget(t, llc, clang, "gp-simd-transfer-complete-bytes", triple, text, oracle, prefix)
		})
	}
}
