package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// The native oracle contains actual Go bytes and receives raw IEEE bits by
// MOVSS/MOVSD only. Its predicates and byte reference are independent of the
// typed grammar; signaling NaNs never undergo arithmetic or conversion.
func TestCrossLinuxRuntimeMatrixX86CMOVFPBitViewsWholeBytes(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	var assembly, declarations, prototypes, originals, rows, goRows strings.Builder
	declarations.WriteString("package oracle\n")
	count := 0
	for _, typ := range []string{"float32", "float64"} {
		for _, width := range []string{"W", "L", "Q"} {
			if typ == "float32" && width == "Q" {
				continue
			}
			for condition, row := range x86CMOVOracleConditions {
				fn := fmt.Sprintf("F%d", count)
				count++
				name := "CMOV" + width + row.name
				fmt.Fprintf(&declarations, "func %s(out *[16]byte,f %s,old,seed uint64)\n", fn, typ)
				fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-32\nMOVQ out+0(FP),DI\nMOVQ old+16(FP),BX\nPUSHQ seed+24(FP)\nPOPFQ\n%s f+8(FP),BX\nMOVQ BX,(DI)\nPUSHFQ\nPOPQ AX\nMOVQ AX,8(DI)\nRET\n", fn, name)
				move, ctype, size := "MOVSS", "float", 32
				if typ == "float64" {
					move, ctype, size = "MOVSD", "double", 64
				}
				actual := x86OrderingHintGoBytes(t, "amd64", "TEXT native(SB),4,$0-0\nPUSHQ BX\nSUBQ $8,SP\n"+move+" X0,(SP)\nMOVQ SI,BX\nPUSHQ DX\nPOPFQ\n"+name+" (SP),BX\nMOVQ BX,(DI)\nPUSHFQ\nPOPQ AX\nMOVQ AX,8(DI)\nADDQ $8,SP\nPOPQ BX\nRET\n")
				var bytes []string
				for _, value := range actual {
					bytes = append(bytes, fmt.Sprintf("0x%02x", value))
				}
				original, symbol := "Original"+fn, "Original"+fn
				if strings.Contains(execution.triple, "apple") {
					symbol = "_" + symbol
				}
				fmt.Fprintf(&originals, "__asm__(%q);\n", ".text\n.globl "+symbol+"\n"+symbol+":\n.byte "+strings.Join(bytes, ",")+"\n")
				fmt.Fprintf(&prototypes, "extern void %s(uint8_t*,%s,uint64_t,uint64_t);\n", fn, ctype)
				prototypes.WriteString(x86OriginalSysVDeclaration("void", original, "uint8_t*,"+ctype+",uint64_t,uint64_t"))
				if size == 32 {
					fmt.Fprintf(&rows, "{%s,%s,0,0,%d,%d,32},\n", fn, original, map[string]int{"W": 2, "L": 4, "Q": 8}[width], condition)
					fmt.Fprintf(&goRows, "{%s,nil,%d,%d,32},\n", fn, map[string]int{"W": 2, "L": 4, "Q": 8}[width], condition)
				} else {
					fmt.Fprintf(&rows, "{0,0,%s,%s,%d,%d,64},\n", fn, original, map[string]int{"W": 2, "L": 4, "Q": 8}[width], condition)
					fmt.Fprintf(&goRows, "{nil,%s,%d,%d,64},\n", fn, map[string]int{"W": 2, "L": 4, "Q": 8}[width], condition)
				}
			}
		}
	}
	goAssemblerOracleOutput(t, "amd64", assembly.String(), "", true)
	ir := x86NarrowOracleIR(t, assembly.String(), declarations.String(), execution.triple)
	if x86CMOVFPHasNumericConversion(ir) {
		t.Fatal("CMOV floating bit views numerically converted")
	}
	reference := fmt.Sprintf(x86CMOVFPWholeBytesC, prototypes.String(), originals.String(), rows.String())
	for _, pipeline := range []struct{ name, backend, ir string }{
		{"backend_O0", "-O0", ir}, {"backend_O2", "-O2", ir}, {"IR_O2/backend_O2", "-O2", x86DwordProductIROptimize(t, ir)},
	} {
		t.Run(pipeline.name, func(t *testing.T) {
			output := execution.compileAndRunLLVM(t, "cmov-fp-whole-bytes", pipeline.ir, reference, pipeline.backend)
			want := fmt.Sprintf("cmov FP kernels %d translated/original whole-byte outcomes %d NaN/zero/flags/mxcsr/canary failures 0\n", count, count*64*8*2)
			if string(output) != want {
				t.Fatal("independent FP payload/predicate mismatch", string(output))
			}
			t.Log(strings.TrimSpace(string(output)))
		})
	}
	x86WordMultiplyRunOriginalGo(t, execution, declarations.String(), assembly.String(), fmt.Sprintf(x86CMOVFPOriginalGo, goRows.String()))
	t.Logf("%d actual original Go ABI0 floating-source kernels ×64 flag seeds ×8 IEEE edge payloads; native host execution is not strict native Linux evidence", count)
}

var x86CMOVFPWholeBytesC = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <xmmintrin.h>
` + x86CMOVConditionC +
	x86OriginalSysVPointer("void", "OriginalProgram32", "uint8_t*,float,uint64_t,uint64_t") +
	x86OriginalSysVPointer("void", "OriginalProgram64", "uint8_t*,double,uint64_t,uint64_t") + `
%s
%s
typedef void(*Program32)(uint8_t*,float,uint64_t,uint64_t);
typedef void(*Program64)(uint8_t*,double,uint64_t,uint64_t);
typedef struct {Program32 f32;OriginalProgram32 o32;Program64 f64;OriginalProgram64 o64;unsigned width,condition,bits;} Kernel;
static Kernel kernels[]={%s};
int main(void) {
 const uint32_t bits32[]={0,0x80000000,0x7fc00001,0x7f800001,0xffc12345,0x7f800000,0xffffffff,0x00000001};
 const uint64_t bits64[]={0,UINT64_C(0x8000000000000000),UINT64_C(0x7ff8000000000001),UINT64_C(0x7ff0000000000001),UINT64_C(0xfff8123456789abc),UINT64_C(0x7ff0000000000000),UINT64_MAX,1};
 unsigned count=0;
 for(unsigned k=0;k<sizeof(kernels)/sizeof(kernels[0]);k++) for(unsigned f=0;f<64;f++) for(unsigned v=0;v<8;v++) for(unsigned native=0;native<2;native++) {
  Kernel kernel=kernels[k];uint8_t out[80];memset(out,0xa7,sizeof(out));
  uint64_t source=kernel.bits==32?bits32[v]:bits64[v],old=UINT64_C(0x87654321fedcba98)^((uint64_t)v<<40),flags=seed(f),got,afterFlags;
  uint32_t csr=0x1f80|((f%%4)<<13)|(f&63),saved=_mm_getcsr();_mm_setcsr(csr);
  if(kernel.bits==32) {
   float value;
   memcpy(&value,bits32+v,4);
   if(native) {
    kernel.o32(out+32,value,old,flags);
   } else {
    kernel.f32(out+32,value,old,flags);
   }
  } else {
   double value;
   memcpy(&value,bits64+v,8);
   if(native) {
    kernel.o64(out+32,value,old,flags);
   } else {
    kernel.f64(out+32,value,old,flags);
   }
  }
  uint32_t after=_mm_getcsr();_mm_setcsr(saved);
  memcpy(&got,out+32,8);memcpy(&afterFlags,out+40,8);
  uint64_t mask=kernel.width==8?UINT64_MAX:((UINT64_C(1)<<(kernel.width*8))-1);
  uint64_t selected=predicate(kernel.condition,flags)?source:old;
  uint64_t want=kernel.width==2?((old&~mask)|(selected&mask)):(selected&mask);
  if(got!=want||(afterFlags&0x8d5)!=flags||after!=csr) {fprintf(stderr,"kernel%%u native%%u payload%%llx got%%llx want%%llx\n",k,native,(unsigned long long)source,(unsigned long long)got,(unsigned long long)want);return 1;}
  for(unsigned b=0;b<32;b++) if(out[b]!=0xa7||out[48+b]!=0xa7) return 2;
  count++;
 }
 printf("cmov FP kernels %%zu translated/original whole-byte outcomes %%u NaN/zero/flags/mxcsr/canary failures 0\n",sizeof(kernels)/sizeof(kernels[0]),count);
 return 0;
}
`

const x86CMOVFPOriginalGo = `package oracle
import("encoding/binary";"math";"testing")
func TestOriginal(t *testing.T) {
 kernels:=[]struct{f32 func(*[16]byte,float32,uint64,uint64);f64 func(*[16]byte,float64,uint64,uint64);width,condition,bits int}{%s}
 bits32:=[]uint32{0,0x80000000,0x7fc00001,0x7f800001,0xffc12345,0x7f800000,0xffffffff,1}
 bits64:=[]uint64{0,0x8000000000000000,0x7ff8000000000001,0x7ff0000000000001,0xfff8123456789abc,0x7ff0000000000000,0xffffffffffffffff,1}
 count:=0
 for k,kernel:=range kernels {for f:=uint64(0);f<64;f++ {for v:=0;v<8;v++ {
  flags:=(f&1)|((f>>1&1)<<2)|((f>>2&1)<<4)|((f>>3&1)<<6)|((f>>4&1)<<7)|((f>>5&1)<<11)
  cf,pf,zf,sf,of:=flags&1!=0,flags&4!=0,flags&64!=0,flags&128!=0,flags&2048!=0
  predicates:=[]bool{!cf,cf,zf,sf==of,!zf&&sf==of,!cf&&!zf,zf||sf!=of,cf||zf,sf!=of,sf,!zf,!of,of,!pf,!sf,pf}
  source:=bits64[v];if kernel.bits==32 {source=uint64(bits32[v])}
  old:=uint64(0x87654321fedcba98)^(uint64(v)<<40);selected:=old;if predicates[kernel.condition] {selected=source}
  mask:=uint64(0xffffffffffffffff);if kernel.width<8 {mask=(uint64(1)<<uint(kernel.width*8))-1}
  want:=selected&mask;if kernel.width==2 {want|=old&^mask}
  var out [16]byte;if kernel.bits==32 {kernel.f32(&out,math.Float32frombits(bits32[v]),old,flags)} else {kernel.f64(&out,math.Float64frombits(bits64[v]),old,flags)}
  got,afterFlags:=binary.LittleEndian.Uint64(out[:8]),binary.LittleEndian.Uint64(out[8:])
  if got!=want||afterFlags&0x8d5!=flags {t.Fatalf("kernel%%d bits%%x got%%x want%%x flags%%x",k,source,got,want,afterFlags)};count++
 }}}
 t.Logf("actual Go FP whole-byte outcomes %%d payload/zero/flags failures 0",count)
}
`
