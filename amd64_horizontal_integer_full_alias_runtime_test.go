package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// All three physical vector-number views are observed after the instruction.
// The scalar reference does not read the production grammar or lane emitter.
// This executes portable LLVM, not original AVX/AVX512 on the host.
func TestCrossLinuxRuntimeMatrixX86HorizontalIntegerFullAliasSentinels(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	var assembly, declarations, prototypes, checks strings.Builder
	declarations.WriteString("package narroworacle\n")
	count := 0
	for _, entry := range []struct {
		legacy, vex              string
		lane, subtract, saturate int
	}{
		{"PHADDW", "VPHADDW", 2, 0, 0},
		{"PHADDD", "VPHADDD", 4, 0, 0},
		{"PHADDSW", "VPHADDSW", 2, 0, 1},
		{"PHSUBW", "VPHSUBW", 2, 1, 0},
		{"PHSUBD", "VPHSUBD", 4, 1, 0},
		{"PHSUBSW", "VPHSUBSW", 2, 1, 1},
	} {
		for _, legacy := range []bool{true, false} {
			widths := []int{16}
			if !legacy {
				widths = append(widths, 32)
			}
			for _, width := range widths {
				bank := map[int]string{16: "X", 32: "Y"}[width]
				for source := 0; source < 3; source++ {
					// Distinct registers, both inputs the destructive source,
					// and full-width memory each have independent witnesses.
					first := bank + "0"
					if source == 1 {
						first = bank + "1"
					} else if source == 2 {
						first = "(CX)"
					}
					for destination := 0; destination < 3; destination++ {
						if legacy && destination != 1 {
							continue
						}
						op := entry.vex
						args := first + "," + bank + "1"
						if legacy {
							op = entry.legacy
						} else {
							args += fmt.Sprintf(",%s%d", bank, destination)
						}
						name := fmt.Sprintf("H%d", count)
						count++
						fmt.Fprintf(&declarations, "func %s(out *[256]byte,a,b,old *[64]byte,flags uint64,csr uint32)\n", name)
						fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-44\nMOVQ out+0(FP),AX\nMOVQ a+8(FP),CX\nMOVQ b+16(FP),DX\nMOVQ old+24(FP),R8\nVMOVUPS (CX),Z0\nVMOVUPS (DX),Z1\nVMOVUPS (R8),Z2\nLDMXCSR csr+40(FP)\nPUSHQ flags+32(FP)\nPOPFQ\n%s %s\nVMOVUPS Z0,(AX)\nVMOVUPS Z1,64(AX)\nVMOVUPS Z2,128(AX)\nVMOVUPS Y%d,192(AX)\nVMOVUPS X%d,224(AX)\nPUSHFQ\nPOPQ R9\nMOVQ R9,240(AX)\nSTMXCSR 248(AX)\nRET\n", name, op, args, destination, destination)
						fmt.Fprintf(&prototypes, "extern void %s(uint8_t*,const uint8_t*,const uint8_t*,const uint8_t*,uint64_t,uint32_t);\n", name)
						fmt.Fprintf(&checks, "if(check(%s,%q,%d,%d,%d,%d,%d,%d,%d))return 1;\n", name, op+" "+args, width, entry.lane, entry.subtract, entry.saturate, x86FloatAddSubBoolInt(legacy), source, destination)
					}
				}
			}
		}
	}
	if count != 126 {
		t.Fatal("independent legacy/VEX source and alias universe changed", count)
	}
	goAssemblerOracleOutput(t, "amd64", assembly.String(), "", true)
	ir := x86NarrowOracleIR(t, assembly.String(), declarations.String(), execution.triple)
	reference := x86HorizontalIntegerFullAliasC + prototypes.String() + "int main(void){\n" + checks.String() + fmt.Sprintf("printf(\"horizontal full-alias kernels %d cases %d failures 0\\n\");return 0;}\n", count, count*97*8)
	for _, optimized := range []bool{false, true} {
		t.Run(fmt.Sprintf("IR_default_O2=%t", optimized), func(t *testing.T) {
			text := ir
			if optimized {
				text = x86MulDivRoundOptimize(t, text)
			}
			for _, backend := range []string{"-O0", "-O2"} {
				t.Run("backend"+backend, func(t *testing.T) {
					output := execution.compileAndRunLLVM(t, "horizontal-full-alias", text, reference, backend)
					want := fmt.Sprintf("horizontal full-alias kernels %d cases %d failures 0\n", count, count*97*8)
					if string(output) != want {
						t.Fatal("full-byte alias oracle did not complete", string(output))
					}
					t.Log(strings.TrimSpace(string(output)))
				})
			}
		})
	}
	t.Log("126 independently Go-accepted legacy/VEX kernels; 97 boundary/random samples and 8 six-flag seeds per axis. All64 bytes of Z0/Z1/Z2 plus destination X/Y views, untouched sources, input/output guards and complete MXCSR; portable LLVM/Rosetta is not original AVX execution.")
}

const x86HorizontalIntegerFullAliasC = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <xmmintrin.h>
typedef void(*Program)(uint8_t*,const uint8_t*,const uint8_t*,const uint8_t*,uint64_t,uint32_t);
struct Input {_Alignas(64) uint8_t before[64],value[64],after[64];};
struct Output {_Alignas(64) uint8_t before[64],value[256],after[64];};
static const uint32_t edges16[]={0,1,2,0x7ffe,0x7fff,0x8000,0x8001,0xfffe,0xffff};
static const uint32_t edges32[]={0,1,2,0x7ffffffe,0x7fffffff,0x80000000,0x80000001,0xfffffffe,0xffffffff};
static const uint64_t flagSeeds[]={0,0x8d5,1,4,0x10,0x40,0x80,0x800};
static int64_t readLane(const uint8_t *p,int bytes) {
 uint64_t value=0;for(int i=0;i<bytes;i++)value|=(uint64_t)p[i]<<(8*i);
 return value&(UINT64_C(1)<<(bytes*8-1))?(int64_t)value-(INT64_C(1)<<(bytes*8)):(int64_t)value;
}
static void fill(uint8_t *a,uint8_t *b,int bytes,int sample) {
 const uint32_t *edges=bytes==2?edges16:edges32;
 for(int lane=0;lane<64/bytes;lane++) {
  uint32_t x=edges[(lane%2?sample/9+(lane/2)*3:sample+lane/2)%9];
  uint32_t y=edges[(lane%2?sample/9+(lane/2)*7+1:sample+(lane/2)*5+3)%9];
  if(sample>=81) {x=UINT32_C(0x9e3779b9)*(unsigned)(sample*17+lane*31);y=UINT32_C(0x85ebca6b)*(unsigned)(sample*43+lane*7);}
  for(int i=0;i<bytes;i++) {a[lane*bytes+i]=(uint8_t)(x>>(i*8));b[lane*bytes+i]=(uint8_t)(y>>(i*8));}
 }
}
static int check(Program program,const char *name,int width,int lane,int sub,int sat,int legacy,int source,int destination) {
 for(int sample=0;sample<97;sample++) for(unsigned state=0;state<sizeof(flagSeeds)/sizeof(flagSeeds[0]);state++) {
  struct Input a,b,old;struct Output out;
  memset(&a,0xa7,sizeof(a));memset(&b,0xb9,sizeof(b));memset(&old,0x6d,sizeof(old));memset(&out,0xc3,sizeof(out));
  fill(a.value,b.value,lane,sample);
  for(int i=0;i<64;i++)old.value[i]=(uint8_t)(193-i*19+sample*37);
  struct Input savedA=a,savedB=b,savedOld=old;
  uint8_t want[192];memcpy(want,a.value,64);memcpy(want+64,b.value,64);memcpy(want+128,old.value,64);
  uint8_t *result=want+destination*64;
  const uint8_t *first=source==1?b.value:a.value;
  for(int at=0;at<width;at+=lane) {
   int within=at%16,pair=at-within+2*(within%8);
   const uint8_t *input=within<8?b.value:first;
   int64_t left=readLane(input+pair,lane),right=readLane(input+pair+lane,lane);
   int64_t value=sub?left-right:left+right;
   if(sat) {if(value<-32768)value=-32768;if(value>32767)value=32767;}
   for(int i=0;i<lane;i++)result[at+i]=(uint8_t)((uint64_t)value>>(8*i));
  }
  if(!legacy)memset(result+width,0,64-width);
  uint64_t seed=flagSeeds[state],flags=0;uint32_t csr=0;
  uint32_t profile=(uint32_t)(0x1f80|((sample%4)<<13)|(sample%64)),savedCSR=_mm_getcsr();
  _mm_setcsr(profile);program(out.value,a.value,b.value,old.value,seed,profile);
  uint32_t afterCSR=_mm_getcsr();_mm_setcsr(savedCSR);
  memcpy(&flags,out.value+240,8);memcpy(&csr,out.value+248,4);
  if((flags&0x8d5)!=seed||csr!=profile||afterCSR!=profile||memcmp(&a,&savedA,sizeof(a))||memcmp(&b,&savedB,sizeof(b))||memcmp(&old,&savedOld,sizeof(old))) {
   fprintf(stderr,"%s sample%d state%u flags/CSR/input guard mismatch\n",name,sample,state);return 1;
  }
  for(int i=0;i<192;i++)if(out.value[i]!=want[i]) {
   fprintf(stderr,"%s sample%d state%u physical Z%d byte%d got%x want%x\n",name,sample,state,i/64,i%64,out.value[i],want[i]);return 2;
  }
  for(int i=0;i<32;i++)if(out.value[192+i]!=result[i]) {
   fprintf(stderr,"%s sample%d state%u Y%d byte%d got%x want%x\n",name,sample,state,destination,i,out.value[192+i],result[i]);return 3;
  }
  for(int i=0;i<16;i++)if(out.value[224+i]!=result[i]) {
   fprintf(stderr,"%s sample%d state%u X%d byte%d got%x want%x\n",name,sample,state,destination,i,out.value[224+i],result[i]);return 4;
  }
  for(int i=0;i<64;i++)if(out.before[i]!=0xc3||out.after[i]!=0xc3)return 5;
  for(int i=252;i<256;i++)if(out.value[i]!=0xc3)return 6;
 }
 return 0;
}
`
