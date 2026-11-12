package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// Observe both directions independently: a round trip alone could let two
// inverse mistakes agree. The reference does not consult the production spec.
func x86MaskVectorRuntimeFixture(t *testing.T) (string, map[string]FuncSig, string) {
	t.Helper()
	var source, declarations, checks strings.Builder
	sigs := map[string]FuncSig{}
	count := 0
	for _, row := range x86OfficialMaskVectorRows(t) {
		for _, mask := range []string{"K0", "K7"} {
			name := fmt.Sprintf("maskvector%d", count)
			count++
			instruction := strings.ReplaceAll(row, "K1", mask)
			toVector := strings.HasPrefix(instruction, "VPMOVM2")
			fields := strings.Fields(instruction)
			vector := strings.TrimPrefix(strings.TrimSuffix(fields[1], ","+mask), mask+",")
			width := map[byte]int{'X': 16, 'Y': 32, 'Z': 64}[vector[0]]
			lane := strings.TrimPrefix(fields[0], "VPMOV")
			lane = strings.TrimPrefix(strings.TrimSuffix(lane, "2M"), "M2")
			laneBytes := map[string]int{"B": 1, "W": 2, "D": 4, "Q": 8}[lane]
			if width == 0 || laneBytes == 0 {
				t.Fatal("unmodeled independent mask/vector runtime spelling", row)
			}
			fmt.Fprintf(&source, "TEXT %s(SB),4,$0-24\nMOVQ out+0(FP),AX\nMOVQ in+8(FP),BX\nMOVQ mask+16(FP),DX\n", name)
			fmt.Fprintf(&source, "KMOVQ DX,%s\nMOVQ $0x8123456789abcdef,DI\nKMOVQ DI,K2\nVMOVUPS (BX),Z1\nCMPQ AX,AX\nSTC\n", mask)
			fmt.Fprintln(&source, instruction)
			fmt.Fprintf(&source, "VMOVUPS Z1,(AX)\nKMOVQ %s,DX\nMOVQ DX,64(AX)\nKMOVQ K2,DX\nMOVQ DX,72(AX)\nSETCS 80(AX)\nSETNE 81(AX)\nRET\n", mask)
			sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, I64}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: I64, Index: 2, Field: -1},
			}}}
			fmt.Fprintf(&declarations, "extern void %s(uint8_t*,const uint8_t*,uint64_t);\n", name)
			fmt.Fprintf(&checks, "if(checkMaskVector(%s,\"%s\",%d,%d,%d)) return 1;\n", name, name, width, laneBytes, x86FloatAddSubBoolInt(toVector))
		}
	}
	if count != 48 {
		t.Fatalf("independent complete runtime program denominator: %d", count)
	}
	oracle := `#include <stdint.h>
#include <stdio.h>
#include <string.h>
` + declarations.String() + `
static int checkMaskVector(void (*program)(uint8_t*,const uint8_t*,uint64_t),
                          const char *name,unsigned width,unsigned lane,int toVector) {
    const uint64_t masks[]={0,1,UINT64_MAX,UINT64_C(0x55aa55aa55aa55aa),UINT64_C(1)<<63};
    for(unsigned round=0;round<4;round++) for(unsigned m=0;m<5;m++) {
        uint8_t input[66],original[66],output[84];
        for(unsigned i=0;i<66;i++) input[i]=(uint8_t)(i*19+round*83+129);
        memcpy(original,input,sizeof(input));
        memset(output,0xc3,sizeof(output));
        uint32_t saved,before=0x1f80|(round<<13)|round,after;
        __asm__ volatile("stmxcsr %0" : "=m"(saved));
        __asm__ volatile("ldmxcsr %0" : : "m"(before));
        program(output+1,input+1,masks[m]);
        __asm__ volatile("stmxcsr %0" : "=m"(after));
        __asm__ volatile("ldmxcsr %0" : : "m"(saved));
        uint64_t gotMask,otherMask,wantMask=masks[m];
        memcpy(&gotMask,output+65,8);
        memcpy(&otherMask,output+73,8);
        if(!toVector) {
            wantMask=0;
            for(unsigned element=0;element<width/lane;element++)
                wantMask|=(uint64_t)(input[1+element*lane+lane-1]>>7)<<element;
        }
        if(after!=before || output[0]!=0xc3 || output[83]!=0xc3 ||
           output[81]!=1 || output[82]!=0 || gotMask!=wantMask ||
           otherMask!=UINT64_C(0x8123456789abcdef) || memcmp(input,original,sizeof(input))) {
            fprintf(stderr,"%s mask/flags/MXCSR/input/canary failure\n",name);
            return 1;
        }
        for(unsigned i=0;i<64;i++) {
            uint8_t want=input[1+i];
            if(toVector) want=i>=width ? 0 : (masks[m]>>(i/lane)&1) ? 255 : 0;
            if(output[1+i]!=want) {
                fprintf(stderr,"%s byte=%u got=%x want=%x\n",name,i,output[1+i],want);
                return 1;
            }
        }
    }
    return 0;
}
int main(void) {
` + checks.String() + "return 0;\n}\n"
	return source.String(), sigs, oracle
}

func runX86MaskVectorRuntimeFixture(t *testing.T, llc, clang, triple string, prefix []string) {
	t.Helper()
	source, sigs, oracle := x86MaskVectorRuntimeFixture(t)
	goAssemblerOracleOutput(t, "amd64", source, "", true)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	compileAndRunRuntimeTestForTarget(t, llc, clang, "mask-vector-complete-bytes", triple, ir, oracle, prefix)
	t.Log("48 independent direction/lane/width/K0-K7 programs; 20 complete byte/alias/mask/flags/MXCSR/canary observations each")
}

func TestX86MaskVectorCompleteByteRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("requires the mandatory cross-runtime counterpart")
	}
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc/clang required")
	}
	triple := testTargetTriple(runtime.GOOS, "amd64")
	var prefix []string
	if crossRosetta {
		prefix = []string{"/usr/bin/arch", "-x86_64"}
	}
	runX86MaskVectorRuntimeFixture(t, llc, clang, triple, prefix)
}

func TestCrossLinuxRuntimeMatrixX86MaskVectorCompleteByteSemantics(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	runX86MaskVectorRuntimeFixture(t, llc, clang, triple, prefix)
}
