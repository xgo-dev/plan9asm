package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86VectorZeroWholeBankSemantics(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	source, sigs, declarations, checks := x86VectorZeroRuntimeFixture(t)
	requireX86GoAssemblerResult(t, "amd64", source, true)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	main := `#include <stdint.h>
#include <stdio.h>
#include <string.h>
` + declarations + `
static int checkVectorZero(void (*program)(uint8_t*,const uint8_t*,uint64_t),const char *name,int clearLow) {
 for(int round=0;round<16;++round) {
  uint8_t input[2050],output[3596],original[2050];
  for(int i=0;i<2050;++i) input[i]=(uint8_t)(i*73+round*19+1);
  memcpy(original,input,sizeof(input));
  memset(output,0xc3,sizeof(output));
  uint64_t mask=UINT64_C(0x8123456789abcdef)^(uint64_t)round;
  uint32_t saved,before=0x1f80|((round%4)<<13)|round,after;
  __asm__ volatile("stmxcsr %0" : "=m"(saved));
  __asm__ volatile("ldmxcsr %0" : : "m"(before));
  program(output+1,input+1,mask);
  __asm__ volatile("stmxcsr %0" : "=m"(after));
  __asm__ volatile("ldmxcsr %0" : : "m"(saved));
  uint64_t gotMask;
  memcpy(&gotMask,output+3587,8);
  if(after!=before || output[0]!=0xc3 || output[3595]!=0xc3 || output[3585]!=1 || output[3586]!=0 || gotMask!=mask || memcmp(input,original,sizeof(input))) {
   fprintf(stderr,"%s flags/MXCSR/K/input/canary failure\n",name);
   return 1;
  }
  for(int reg=0;reg<32;++reg) {
   const int widths[]={16,32,64},offsets[]={0,16,48};
   for(int view=0;view<3;++view) for(int byte=0;byte<widths[view];++byte) {
    uint8_t want=reg<16 && (clearLow || byte>=16) ? 0 : input[1+reg*64+byte];
    uint8_t got=output[1+reg*112+offsets[view]+byte];
    if(got!=want) {
     fprintf(stderr,"%s round=%d reg=%d width=%d byte=%d got=%x want=%x\n",name,round,reg,widths[view],byte,got,want);
     return 1;
    }
   }
  }
 }
 return 0;
}
int main(void) {
` + checks + "return 0;\n}\n"
	compileAndRunRuntimeTestForTarget(t, llc, clang, "vector-zero-complete", triple, ir, main, prefix)
	t.Log("8 named/VEX2/VEX3/WIG programs; 16 independent complete X/Y/Z-bank, flags, MXCSR, mask and canary inputs each")
}

func x86VectorZeroRuntimeFixture(t *testing.T) (string, map[string]FuncSig, string, string) {
	t.Helper()
	var source, declarations, checks strings.Builder
	sigs := map[string]FuncSig{}
	for index, row := range []struct {
		instruction string
		clearLow    bool
	}{
		{"VZEROUPPER", false}, {"VZEROALL", true},
		{"WORD $0xf8c5\nBYTE $0x77", false}, {"WORD $0xfcc5\nBYTE $0x77", true},
		{"LONG $0x77f8e1c4", false}, {"LONG $0x77fce1c4", true},
		{"LONG $0x7778e1c4", false}, {"LONG $0x777ce1c4", true},
	} {
		name := fmt.Sprintf("vectorzero%d", index)
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-24\nMOVQ out+0(FP),AX\nMOVQ in+8(FP),BX\nMOVQ mask+16(FP),DX\nKMOVQ DX,K1\n", name)
		for register := 0; register < 32; register++ {
			fmt.Fprintf(&source, "VMOVUPS %d(BX),Z%d\n", register*64, register)
		}
		source.WriteString("CMPQ AX,AX\nSTC\n")
		fmt.Fprintln(&source, row.instruction)
		for register := 0; register < 32; register++ {
			for _, view := range []struct {
				bank string
				off  int
			}{{"X", 0}, {"Y", 16}, {"Z", 48}} {
				fmt.Fprintf(&source, "VMOVUPS %s%d,%d(AX)\n", view.bank, register, register*112+view.off)
			}
		}
		source.WriteString("SETCS 3584(AX)\nSETNE 3585(AX)\nKMOVQ K1,DX\nMOVQ DX,3586(AX)\nRET\n")
		sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, I64}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
			{Offset: 0, Type: Ptr, Index: 0, Field: -1},
			{Offset: 8, Type: Ptr, Index: 1, Field: -1},
			{Offset: 16, Type: I64, Index: 2, Field: -1},
		}}}
		fmt.Fprintf(&declarations, "extern void %s(uint8_t*,const uint8_t*,uint64_t);\n", name)
		fmt.Fprintf(&checks, "if(checkVectorZero(%s,\"%s\",%d)) return 1;\n", name, name, x86FloatAddSubBoolInt(row.clearLow))
	}
	return source.String(), sigs, declarations.String(), checks.String()
}
