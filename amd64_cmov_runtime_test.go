package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// Actual Go-emitted bytes are embedded in independent native wrappers; none
// of the C arithmetic or condition reference is derived from the typed forms.
func TestCrossLinuxRuntimeMatrixX86CMOVIndependentWholeBytes(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	var assembly, declarations, originals, prototypes, rows strings.Builder
	declarations.WriteString("package narroworacle\n")
	count := 0
	for _, width := range []string{"W", "L", "Q"} {
		for condition, row := range x86CMOVOracleConditions {
			name := "CMOV" + width + row.name
			for mode, source := range []string{"BX", "(SI)", "AX"} {
				fn := fmt.Sprintf("C%d", count)
				count++
				fmt.Fprintf(&declarations, "func %s(out *[16]byte,src *[8]byte,old,seed uint64)\n", fn)
				fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-32\nMOVQ out+0(FP),DI\nMOVQ src+8(FP),SI\nMOVQ old+16(FP),AX\nMOVQ (SI),BX\nPUSHQ seed+24(FP)\nPOPFQ\n%s %s,AX\nMOVQ AX,(DI)\nPUSHFQ\nPOPQ AX\nMOVQ AX,8(DI)\nRET\n", fn, name, source)
				original := "Original" + fn
				actual := x86OrderingHintGoBytes(t, "amd64", "TEXT native(SB),4,$0-0\nPUSHQ BX\nMOVQ DX,AX\nMOVQ (SI),BX\nPUSHQ CX\nPOPFQ\n"+name+" "+source+",AX\nMOVQ AX,(DI)\nPUSHFQ\nPOPQ AX\nMOVQ AX,8(DI)\nPOPQ BX\nRET\n")
				var bytes []string
				for _, value := range actual {
					bytes = append(bytes, fmt.Sprintf("0x%02x", value))
				}
				symbol := original
				if strings.Contains(execution.triple, "apple") {
					symbol = "_" + symbol
				}
				fmt.Fprintf(&originals, "__asm__(%q);\n", ".text\n.globl "+symbol+"\n"+symbol+":\n.byte "+strings.Join(bytes, ",")+"\n")
				fmt.Fprintf(&prototypes, "extern void %s(uint8_t*,const uint8_t*,uint64_t,uint64_t);\n", fn)
				prototypes.WriteString(x86OriginalSysVDeclaration("void", original, "uint8_t*,const uint8_t*,uint64_t,uint64_t"))
				fmt.Fprintf(&rows, "{%s,%s,%d,%d,%d},\n", fn, original, map[string]int{"W": 2, "L": 4, "Q": 8}[width], condition, mode)
			}
		}
	}
	goAssemblerOracleOutput(t, "amd64", assembly.String(), "", true)
	ir := x86NarrowOracleIR(t, assembly.String(), declarations.String(), execution.triple)
	reference := fmt.Sprintf(x86CMOVWholeBytesC, prototypes.String(), originals.String(), rows.String())
	for _, pipeline := range []struct{ name, backend, ir string }{
		{"backend_O0", "-O0", ir}, {"backend_O2", "-O2", ir}, {"IR_O2/backend_O2", "-O2", x86DwordProductIROptimize(t, ir)},
	} {
		t.Run(pipeline.name, func(t *testing.T) {
			output := execution.compileAndRunLLVM(t, "cmov-whole-bytes", pipeline.ir, reference, pipeline.backend)
			want := fmt.Sprintf("cmov kernels %d translated/original whole-byte outcomes %d flags/mxcsr/input/canary failures 0\n", count, count*64*3*2)
			if string(output) != want {
				t.Fatal("independent full bytes, flags and native predicate mismatch", string(output))
			}
			t.Log(strings.TrimSpace(string(output)))
		})
	}
}

const x86CMOVConditionC = `
static int predicate(unsigned c,uint64_t f) {
 int cf=(f>>0)&1,pf=(f>>2)&1,zf=(f>>6)&1,sf=(f>>7)&1,of=(f>>11)&1;
 switch(c) {
 case 0:return !cf;case 1:return cf;case 2:return zf;case 3:return sf==of;
 case 4:return !zf&&sf==of;case 5:return !cf&&!zf;case 6:return zf||sf!=of;
 case 7:return cf||zf;case 8:return sf!=of;case 9:return sf;case 10:return !zf;
 case 11:return !of;case 12:return of;case 13:return !pf;case 14:return !sf;case 15:return pf;
 }return -1;
}
static uint64_t seed(unsigned n) {
 return ((uint64_t)(n&1))|((uint64_t)((n>>1)&1)<<2)|((uint64_t)((n>>2)&1)<<4)|
 ((uint64_t)((n>>3)&1)<<6)|((uint64_t)((n>>4)&1)<<7)|((uint64_t)((n>>5)&1)<<11);
}
`

var x86CMOVWholeBytesC = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <xmmintrin.h>
` + x86CMOVConditionC +
	x86OriginalSysVPointer("void", "OriginalProgram", "uint8_t*,const uint8_t*,uint64_t,uint64_t") + `
%s
%s
typedef void(*Program)(uint8_t*,const uint8_t*,uint64_t,uint64_t);
typedef struct {Program translated;OriginalProgram original;unsigned width,condition,mode;} Kernel;
static Kernel kernels[]={%s};
struct Guard {uint8_t before[32],value[16],after[32];};
int main(void) {
 unsigned count=0;
 const uint64_t edges[]={UINT64_C(0x87654321fedcba98),UINT64_C(0xffff000080000001),UINT64_C(0x0123456789abcdef)};
 for(unsigned k=0;k<sizeof(kernels)/sizeof(kernels[0]);k++) for(unsigned f=0;f<64;f++) for(unsigned v=0;v<3;v++) for(unsigned native=0;native<2;native++) {
  Kernel kernel=kernels[k];struct Guard out;memset(&out,0xa7,sizeof(out));
  uint8_t input[10],copy[10];memset(input,0x59,sizeof(input));
  uint64_t source=edges[(v+1)%%3],old=edges[v],flags=seed(f),got=0,afterFlags=0;
  memcpy(input+1,&source,8);memcpy(copy,input,sizeof(input));
  uint32_t csr=0x1f80|((f%%4)<<13)|(f&63),saved=_mm_getcsr();_mm_setcsr(csr);
  if(native) {
   kernel.original(out.value,input+1,old,flags);
  } else {
   kernel.translated(out.value,input+1,old,flags);
  }
  uint32_t after=_mm_getcsr();_mm_setcsr(saved);
  memcpy(&got,out.value,8);memcpy(&afterFlags,out.value+8,8);
  uint64_t mask=kernel.width==8?UINT64_MAX:((UINT64_C(1)<<(kernel.width*8))-1);
  uint64_t selected=predicate(kernel.condition,flags)?(kernel.mode==2?old:source):old;
  uint64_t want=kernel.width==2?((old&~mask)|(selected&mask)):(selected&mask);
  if(got!=want||(afterFlags&0x8d5)!=flags||after!=csr||memcmp(input,copy,sizeof(input))) {
   fprintf(stderr,"kernel%%u native%%u width%%u flags%%llx got%%llx want%%llx observedflags%%llx\n",k,native,kernel.width,(unsigned long long)flags,(unsigned long long)got,(unsigned long long)want,(unsigned long long)afterFlags);return 1;
  }
  for(unsigned b=0;b<32;b++) if(out.before[b]!=0xa7||out.after[b]!=0xa7) return 2;
  count++;
 }
 printf("cmov kernels %%zu translated/original whole-byte outcomes %%u flags/mxcsr/input/canary failures 0\n",sizeof(kernels)/sizeof(kernels[0]),count);
 return 0;
}
`
