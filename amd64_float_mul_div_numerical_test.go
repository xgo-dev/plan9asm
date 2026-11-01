package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// The arithmetic reference is actual independent legacy SSE. No production
// opcode/rounding helper supplies expected numerical bits or MXCSR flags.
var x86FloatMulDivSSEOracle = strings.NewReplacer("subss", "divss", "subsd", "divsd", "addss", "mulss", "addsd", "mulsd").Replace(x86FloatAddSubSSEOracle)

func TestCrossLinuxRuntimeMatrixX86FloatMulDivDefaultPhysicalSemantics(t *testing.T) {
	testX86FloatMulDivPhysicalSemantics(t, false)
}

func TestCrossLinuxRuntimeMatrixX86FloatMulDivFixedRoundPhysicalSemantics(t *testing.T) {
	testX86FloatMulDivPhysicalSemantics(t, true)
}

func testX86FloatMulDivPhysicalSemantics(t *testing.T, fixed bool) {
	t.Helper()
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	var source, declarations, checks strings.Builder
	sigs := map[string]FuncSig{}
	count := 0
	for _, row := range x86FloatMulDivFormats("amd64") {
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		form, _, err := x86FloatMulDivProperties(file.Funcs[0].Instrs[1], "amd64")
		if err != nil {
			t.Fatal(err)
		}
		if (form.rounding != "") != fixed {
			continue
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
		independentDivide := strings.Contains(opcode, "DIV")
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
`, name, form.spec.bits/8, form.spec.bits, x86FloatAddSubBoolInt(form.broadcast), form.mask, arithmeticBytes, x86FloatAddSubBoolInt(independentDivide), x86FloatAddSubBoolInt(form.zeroing), x86FloatAddSubBoolInt(form.spec.legacy), x86FloatAddSubBoolInt(form.spec.scalar), count+10, fixedMode, x86FloatAddSubBoolInt(aligned))
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
	main := x86FloatMulDivSSEOracle + declarations.String() + "int main(void){const uint64_t masks[]={0,1,0x55aa55aa55aa55aaULL,~0ULL}; const unsigned controls[]={0x1f80,0x1fc0,0x9f80,0x9fc0,0x1f85,0x9fe0};\n" + checks.String() + "unsigned csr=0x1f80;__asm__ volatile(\"ldmxcsr %0\"::\"m\"(csr));return 0;}\n"
	compileAndRunRuntimeTestForTarget(t, llc, clang, "mul-div-default-semantics", triple, ir, main, prefix)
	t.Logf("%d independent opcode/width/memory/mask programs x384 IEEE/MXCSR/canary inputs", count)
}
