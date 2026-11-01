package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// The full virtual Z observation proves lowering bytes, not physical AVX512
// execution. The original legacy Go counterpart is an independent root below.
func TestCrossLinuxRuntimeMatrixX86ScalarLaneCompleteBytes(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	var source, declarations, checks strings.Builder
	sigs := map[string]FuncSig{}
	count := 0
	for _, vector := range []bool{false, true} {
		for _, bits := range []int{8, 16, 32, 64} {
			for _, insert := range []bool{false, true} {
				for _, memory := range []bool{false, true} {
					for lane := 0; lane < 128/bits; lane++ {
						op := "P"
						if vector {
							op = "VP"
						}
						if insert {
							op += "INSR"
						} else {
							op += "EXTR"
						}
						op += map[int]string{8: "B", 16: "W", 32: "D", 64: "Q"}[bits]
						name := fmt.Sprint("lane", count)
						count++
						fmt.Fprintf(&source, "TEXT %s(SB),4,$0-24\nMOVQ out+0(FP),AX\nMOVQ in+8(FP),BX\nMOVQ seed+16(FP),CX\nVMOVUPS (BX),Z0\nVMOVUPS (AX),Z1\nCMPQ AX,AX\nSTC\n", name)
						if insert {
							transfer := "CX"
							if memory {
								transfer = "3(BX)"
							}
							fmt.Fprintf(&source, "%s $%d,%s,X1", op, lane, transfer)
							if vector {
								source.WriteString(",X1")
							}
							source.WriteString("\nVMOVUPS Z1,(AX)\n")
						} else {
							transfer := "R11"
							if memory {
								transfer = "3(AX)"
							}
							fmt.Fprintf(&source, "MOVQ $-1,R11\n%s $%d,X0,%s\n", op, lane, transfer)
							if !memory {
								source.WriteString("MOVQ R11,64(AX)\n")
							}
						}
						source.WriteString("SETCS 72(AX)\nSETNE 73(AX)\nRET\n")
						sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, I64}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
							{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1}, {Offset: 16, Type: I64, Index: 2, Field: -1},
						}}}
						fmt.Fprintf(&declarations, "extern void %s(uint8_t*,const uint8_t*,uint64_t);\n", name)
						fmt.Fprintf(&checks, "if(check(%s,%d,%d,%d,%d,%d))return %d;\n", name, bits/8, lane, x86FloatAddSubBoolInt(insert), x86FloatAddSubBoolInt(memory), x86FloatAddSubBoolInt(vector), count)
					}
				}
			}
		}
	}
	if count != 240 {
		t.Fatal("complete independent scalar-lane runtime denominator", count)
	}
	goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	const reference = `#include <stdint.h>
#include <stdio.h>
#include <string.h>
static int check(void (*fn)(uint8_t*,const uint8_t*,uint64_t),unsigned width,unsigned lane,int insert,int memory,int vector) {
 const uint64_t seeds[]={0,UINT64_MAX,UINT64_C(0x9876fedcba543210),UINT64_C(0x8000000000000001)};
 for(unsigned sample=0;sample<8;sample++) {
  uint8_t input[82],saved[82],output[84],want[84];
  for(unsigned i=0;i<82;i++)input[i]=i*37+sample*71;
  for(unsigned i=0;i<84;i++)output[i]=i*19+sample*13;
  memcpy(saved,input,sizeof(input));memcpy(want,output,sizeof(output));
  uint64_t seed=seeds[sample%4];
  if(insert) {
   const uint8_t *from=memory?input+4:(const uint8_t*)&seed;
   memcpy(want+1+lane*width,from,width);
   if(vector)memset(want+17,0,48);
  } else if(memory)memcpy(want+4,input+1+lane*width,width);
  else {uint64_t value=0;memcpy(&value,input+1+lane*width,width);memcpy(want+65,&value,8);}
  want[73]=1;want[74]=0;
  unsigned csr=0x9fc5,after;__asm__ volatile("ldmxcsr %0"::"m"(csr));
  fn(output+1,input+1,seed);__asm__ volatile("stmxcsr %0":"=m"(after));
  if(after!=csr||memcmp(input,saved,sizeof(input))||memcmp(output,want,sizeof(output))) {
   for(unsigned i=0;i<84;i++)if(output[i]!=want[i])fprintf(stderr,"lane width=%u lane=%u ins=%d mem=%d vec=%d sample=%u byte=%u got=%x want=%x\n",width,lane,insert,memory,vector,sample,i,output[i],want[i]);
   return 1;
  }
 }
 return 0;
}
`
	main := reference + declarations.String() + "int main(void){\n" + checks.String() + "unsigned csr=0x1f80;__asm__ volatile(\"ldmxcsr %0\"::\"m\"(csr));return 0;}\n"
	for _, optimized := range []bool{false, true} {
		t.Run(fmt.Sprint("IR_O2=", optimized), func(t *testing.T) {
			text := ir
			if optimized {
				text = x86MulDivRoundOptimize(t, text)
			}
			compileAndRunRuntimeTestForTarget(t, llc, clang, "scalar-lane-bytes", triple, text, main, prefix)
		})
	}
	t.Log("240 independent full-byte programs × 8 patterns × IR absent/present O2; backend retains existing default O2, no physical AVX512 claim")
}
