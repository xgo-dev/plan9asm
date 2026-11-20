package plan9asm

import (
	"strings"
	"testing"
)

func TestX86SignedIntegerScalarFloatOriginalCaller(t *testing.T) {
	const body = "VMOVUPS (DI),X0\nVCVTSI2SSL AX,X0,X1\nVMOVSS X1,(DX)"
	assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
	goAssemblerOracleOutput(t, "amd64", assembly, "", true)
	pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
	if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
		t.Fatal(err)
	}
}

func TestCrossLinuxRuntimeMatrixX86SignedIntegerScalarFloatAmbientConstant(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	const source = "TEXT convert(SB),4,$0-8\nMOVQ out+0(FP),AX\nMOVL $16777217,CX\nCVTSL2SS CX,X0\nMOVSS X0,(AX)\nRET\n"
	goAssemblerOracleOutput(t, "amd64", source, "", true)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	sig := FuncSig{Args: []LLVMType{Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}}}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: map[string]FuncSig{"convert": sig}})
	if err != nil {
		t.Fatal(err)
	}
	const reference = `#include <stdint.h>
#include <stdio.h>
extern void convert(uint32_t*);
int main(void) {
 uint32_t out=0,csr=0x5f80,observed,reference;
 int32_t value=16777217;
 __asm__ volatile("ldmxcsr %0;cvtsi2ssl %1,%%xmm0;movd %%xmm0,%2;stmxcsr %3"
  :"=m"(csr),"+r"(value),"=r"(reference),"=m"(observed):"0"(csr):"xmm0","memory");
 if(reference!=UINT32_C(0x4b800001)||observed!=(csr|32))return 2;
 __asm__ volatile("ldmxcsr %0"::"m"(csr):"memory");
 convert(&out);
 __asm__ volatile("stmxcsr %0":"=m"(observed)::"memory");
 if(out!=reference||observed!=(csr|32)){
  fprintf(stderr,"ambient conversion bits=%x want=%x MXCSR=%x want=%x\n",out,reference,observed,csr|32);
  return 1;
 }
 return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "signed-integer-scalar-float-constant", triple, x86SignedIntegerFloatOptimize(t, ir), reference, prefix)
}
