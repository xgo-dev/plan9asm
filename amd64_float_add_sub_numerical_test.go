package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// This oracle executes real legacy SSE under an explicitly saved/restored
// MXCSR. It is independent of the translated opcode table and numerical
// accumulator, including NaN payload priority and DAZ/FTZ signed zeros.
const x86FloatAddSubSSEOracle = `#include <stdint.h>
#include <string.h>
#include <stdio.h>
static unsigned last_sse_csr;
static uint64_t sse_result(unsigned width,uint64_t left,uint64_t right,int sub,unsigned csr) {
 unsigned saved; __asm__ volatile("stmxcsr %0":"=m"(saved));
 __asm__ volatile("ldmxcsr %0"::"m"(csr));
 uint64_t bits=0;
 if(width==32) {
  uint32_t l=(uint32_t)left,r=(uint32_t)right,out; float a,b;
  memcpy(&a,&l,4);memcpy(&b,&r,4);
  if(sub) __asm__ volatile("subss %1,%0":"+x"(a):"x"(b));
  else __asm__ volatile("addss %1,%0":"+x"(a):"x"(b));
  memcpy(&out,&a,4);bits=out;
 } else {
  double a,b;memcpy(&a,&left,8);memcpy(&b,&right,8);
  if(sub) __asm__ volatile("subsd %1,%0":"+x"(a):"x"(b));
  else __asm__ volatile("addsd %1,%0":"+x"(a):"x"(b));
  memcpy(&bits,&a,8);
 }
 __asm__ volatile("stmxcsr %0":"=m"(last_sse_csr));
 __asm__ volatile("ldmxcsr %0"::"m"(saved)); return bits;
}
`

func x86FloatAddSubRuntimeTools(t *testing.T) (llc, clang, triple string, prefix []string) {
	t.Helper()
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("requires amd64 numerical counterpart")
	}
	var found bool
	llc, clang, found = findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc/clang missing")
	}
	triple = testTargetTriple(runtime.GOOS, "amd64")
	if crossRosetta {
		prefix = []string{"/usr/bin/arch", "-x86_64"}
	}
	return
}

func TestCrossLinuxRuntimeMatrixX86FloatAddSubFixedRoundSSEExtremes(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	var ir strings.Builder
	ir.WriteString("declare i128 @llvm.ctlz.i128(i128, i1)\n")
	for _, bits := range []int{32, 64} {
		typ := amd64FMA3LLVMType(1, bits)
		fmt.Fprintf(&ir, "declare %s @llvm.fma.f%d(%s,%s,%s)\n", typ, bits, typ, typ, typ)
		emitAMD64FMA3RoundingHelper(&ir, bits)
		emitX86FloatAddSubRoundingHelper(&ir, bits)
		fmt.Fprintf(&ir, "define i%d @addsub_round%d(i%d %%a,i%d %%b,i1 %%sub,i32 %%mode,i32 %%csr){\n %%a_float=bitcast i%d %%a to %s\n %%b_float=bitcast i%d %%b to %s\n %%value=call %s @__plan9asm_add_sub_round_f%d(%s %%a_float,%s %%b_float,i1 %%sub,i32 %%mode,i32 %%csr)\n %%bits=bitcast %s %%value to i%d\n ret i%d %%bits\n}\n", bits, bits, bits, bits, bits, typ, bits, typ, typ, bits, typ, typ, typ, bits, bits)
	}
	main := x86FloatAddSubSSEOracle + `
extern uint32_t addsub_round32(uint32_t,uint32_t,_Bool,unsigned,unsigned);
extern uint64_t addsub_round64(uint64_t,uint64_t,_Bool,unsigned,unsigned);
int main(void) {
 const uint64_t edges32[]={0,0x80000000,1,0x80000001,0x7fffff,0x800000,
  0x7f7fffff,0xff7fffff,0x3f800000,0xbf800000,0x3f800001,0x33800000,
  0x7f800000,0xff800000,0x7fc12345,0xffc45678,0x7f812345,0xff845678};
 const uint64_t edges64[]={0,UINT64_C(0x8000000000000000),1,
  UINT64_C(0x8000000000000001),UINT64_C(0xfffffffffffff),UINT64_C(0x10000000000000),
  UINT64_C(0x7fefffffffffffff),UINT64_C(0xffefffffffffffff),UINT64_C(0x3ff0000000000000),
  UINT64_C(0xbff0000000000000),UINT64_C(0x3ff0000000000001),UINT64_C(0x3ca0000000000000),
  UINT64_C(0x7ff0000000000000),UINT64_C(0xfff0000000000000),UINT64_C(0x7ff8123456789abc),
  UINT64_C(0xfff8fedcba987654),UINT64_C(0x7ff0123456789abc),UINT64_C(0xfff0fedcba987654)};
 const unsigned controls[]={0x1f80,0x1fc0,0x9f80,0x9fc0,0x1f85,0x9fe0};
 uint64_t state=UINT64_C(0x7182329ab3293821);
 for(unsigned width=32;width<=64;width+=32) for(unsigned pair=0;pair<1000;pair++) {
  const uint64_t *edges=width==32?edges32:edges64;
  uint64_t a=edges[pair%18],b=edges[(pair/18)%18];
  if(pair>=324){ state^=state<<13;state^=state>>7;state^=state<<17;a=state;
   state^=state<<13;state^=state>>7;state^=state<<17;b=state; }
  for(unsigned sub=0;sub<2;sub++) for(unsigned mode=0;mode<4;mode++)
   for(unsigned ambient=0;ambient<4;ambient++) for(unsigned control=0;control<6;control++) {
    unsigned csr=controls[control],ambientCSR=csr|(ambient<<13),after;
    __asm__ volatile("ldmxcsr %0"::"m"(ambientCSR));
    uint64_t got=width==32?addsub_round32(a,b,sub,mode,csr):addsub_round64(a,b,sub,mode,csr);
    __asm__ volatile("stmxcsr %0":"=m"(after));
    uint64_t want=sse_result(width,a,b,sub,csr|(mode<<13));
    if(got!=want || after!=ambientCSR) {
     fprintf(stderr,"binary width/sub/mode/ambient/csr=%u/%u/%u/%u/%x a=%llx b=%llx got=%llx want=%llx after=%x\n",
      width,sub,mode,ambient,csr,(unsigned long long)a,(unsigned long long)b,(unsigned long long)got,(unsigned long long)want,after);return 1;
    }
   }
 }
 unsigned csr=0x1f80;__asm__ volatile("ldmxcsr %0"::"m"(csr));return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "binary-fixed-sse", triple, ir.String(), main, prefix)
}

func TestCrossLinuxRuntimeMatrixX86FloatAddSubCompletePhysicalSemantics(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	var source, declarations, checks strings.Builder
	sigs := map[string]FuncSig{}
	count := 0
	for _, row := range x86FloatAddSubFormats("amd64") {
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		form, _, err := x86FloatAddSubProperties(file.Funcs[0].Instrs[1], "amd64")
		if err != nil {
			t.Fatal(err)
		}
		fixedMode := -1
		for mode, suffix := range []string{"RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE"} {
			if form.rounding == suffix {
				fixedMode = mode
			}
		}
		name := fmt.Sprintf("binary%d", count)
		count++
		row = strings.Replace(row, "8(AX)", "(BX)", 1)
		row = strings.Replace(row, "(AX)", "(BX)", 1)
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-32\nMOVQ out+0(FP),AX\nMOVQ a+8(FP),BX\nMOVQ b+16(FP),CX\nMOVQ mask+24(FP),DX\nVMOVUPS (BX),Z0\nVMOVUPS (CX),Z1\nVMOVUPS (CX),Z2\nKMOVQ DX,K1\nSTC\n%s\nVMOVUPS Z%d,(AX)\nSETCS 64(AX)\nRET\n", name, row, map[bool]int{true: 1, false: 2}[form.spec.legacy])
		sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr, I64}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
			{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1}, {Offset: 16, Type: Ptr, Index: 2, Field: -1}, {Offset: 24, Type: I64, Index: 3, Field: -1},
		}}}
		fmt.Fprintf(&declarations, "extern void %s(void*,const void*,const void*,uint64_t);\n", name)
		arithmeticBytes := form.byteWidth
		if form.spec.scalar {
			arithmeticBytes = form.spec.bits / 8
		}
		opcode := strings.Split(strings.Fields(row)[0], ".")[0]
		independentSubtract := strings.Contains(opcode, "SUB")
		// Only legacy packed native memory has m128 alignment semantics.
		// Keep scalar/VEX/EVEX inputs unaligned; the separate exact-opcode
		// fault oracle retains every old mod16 case instead of erasing it.
		aligned := form.legacy && !form.scalar && form.memory >= 0
		fmt.Fprintf(&checks, `
 for(int round=0;round<4;round++) for(int m=0;m<4;m++) for(int control=0;control<6;control++) for(int ambient=0;ambient<4;ambient++) {
  uint8_t aStorage[96] __attribute__((aligned(16))),bStorage[68],out[67];uint8_t *a=aStorage+(%[13]d?16:1),*b=bStorage+3;
  memset(aStorage,0xa7,96);memset(bStorage,0xb9,68);memset(out,0xc3,67);
  for(int i=0;i<64/%[2]d;i++) { uint64_t av=%[3]d==32?UINT64_C(0x3f000001)+i*0x12345+round*0x10000:UINT64_C(0x3fe0000000000001)+i*0x123456789;
   uint64_t bv=%[3]d==32?UINT64_C(0xbf800001)+i*0x12345:UINT64_C(0xbff0000000000001)+i*0x2345678;
   if(round==1){av=%[3]d==32?UINT64_C(0x7fc12345)+i:UINT64_C(0x7ff8123456789abc)+i;bv=%[3]d==32?UINT64_C(0xffc45678)+i:UINT64_C(0xfff8fedcba987654)+i;}
   if(round==2){av=%[3]d==32?UINT64_C(0x7f812345)+i:UINT64_C(0x7ff0123456789abc)+i;bv=%[3]d==32?UINT64_C(0xff800000):UINT64_C(0xfff0000000000000);}
   if(round==3){av=1+i;bv=(%[3]d==32?UINT64_C(0x80000000):UINT64_C(0x8000000000000000))|i;}
   memcpy(a+i*%[2]d,&av,%[2]d);memcpy(b+i*%[2]d,&bv,%[2]d); }
  unsigned csr=controls[control]|(ambient<<13),observed,expectedFlags=0;
  __asm__ volatile("ldmxcsr %%0"::"m"(csr));
  uint64_t mask=masks[m];%[1]s(out+1,a,b,mask);
  __asm__ volatile("stmxcsr %%0":"=m"(observed));
  for(int i=0;i<64/%[2]d;i++) {
   uint64_t av=0,bv=0,got=0;memcpy(&av,a+(%[4]d?0:i*%[2]d),%[2]d);memcpy(&bv,b+i*%[2]d,%[2]d);memcpy(&got,out+1+i*%[2]d,%[2]d);
   int active=%[5]d<0 || ((mask>>i)&1);
   unsigned operationCSR=%[12]d<0?csr:((csr&~0x6000u)|((unsigned)%[12]d<<13));
   uint64_t want=i*%[2]d<%[6]d?(active?sse_result(%[3]d,bv,av,%[7]d,operationCSR):(%[8]d?0:bv)):(%[9]d || (%[10]d && i*%[2]d<16)?bv:0);
   if(i*%[2]d<%[6]d && active && %[12]d<0)expectedFlags|=last_sse_csr&63;
   if(got!=want){fprintf(stderr,"%[1]s lane=%%d got=%%llx want=%%llx\n",i,(unsigned long long)got,(unsigned long long)want);return %[11]d;}
  }
  if(observed!=(csr|expectedFlags)){fprintf(stderr,"%[1]s sticky observed=%%x expected=%%x\n",observed,csr|expectedFlags);return 3;}
  if(out[0]!=0xc3 || out[65]!=1 || out[66]!=0xc3 || a[-1]!=0xa7 || a[64]!=0xa7 || bStorage[2]!=0xb9 || bStorage[67]!=0xb9)return 2;
 }
`, name, form.spec.bits/8, form.spec.bits, x86FloatAddSubBoolInt(form.broadcast), form.mask, arithmeticBytes, x86FloatAddSubBoolInt(independentSubtract), x86FloatAddSubBoolInt(form.zeroing), x86FloatAddSubBoolInt(form.spec.legacy), x86FloatAddSubBoolInt(form.spec.scalar), count+10, fixedMode, x86FloatAddSubBoolInt(aligned))
	}
	requireX86GoAssemblerResult(t, "amd64", source.String(), true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	main := x86FloatAddSubSSEOracle + declarations.String() + "int main(void){const uint64_t masks[]={0,1,0x55aa55aa55aa55aaULL,~0ULL}; const unsigned controls[]={0x1f80,0x1fc0,0x9f80,0x9fc0,0x1f85,0x9fe0};\n" + checks.String() + "unsigned csr=0x1f80;__asm__ volatile(\"ldmxcsr %0\"::\"m\"(csr));return 0;}\n"
	compileAndRunRuntimeTestForTarget(t, llc, clang, "binary-complete-semantics", triple, ir, main, prefix)
	t.Logf("%d independent opcode/width/memory/mask programs x384 IEEE/MXCSR/canary inputs", count)
}

func x86FloatAddSubBoolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
