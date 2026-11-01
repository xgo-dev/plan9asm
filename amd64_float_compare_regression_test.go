package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86GoCallerFloatingCompareOriginalSourceReachesObjects(t *testing.T) {
	for _, opcode := range []string{"CMPPS", "CMPPD", "CMPSS", "CMPSD", "VCMPPS", "VCMPPD", "VCMPSS", "VCMPSD"} {
		t.Run(opcode, func(t *testing.T) {
			row, destination := opcode+" X0,X1,$0", "X1"
			if strings.HasPrefix(opcode, "V") {
				row, destination = opcode+" $0,X0,X1,X2", "X2"
			}
			body := "VMOVUPS (DI),X0\nVMOVUPS (SI),X1\n" + row + "\nVMOVSS " + destination + ",(DX)"
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			goAssemblerOracleOutput(t, "amd64", assembly, "", true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCrossLinuxRuntimeMatrixX86FloatingCompareLegacyUpperAliases(t *testing.T) {
	execution := x86FloatCompareRuntimeTools(t, x86FloatCompareSSE)
	var assembly, declarations, checks strings.Builder
	sigs := map[string]FuncSig{}
	for index, opcode := range []string{"CMPPS", "CMPPD", "CMPSS", "CMPSD"} {
		name := fmt.Sprintf("compare_alias%d", index)
		bits, scalar := 32, strings.HasSuffix(opcode, "SS") || strings.HasSuffix(opcode, "SD")
		if strings.HasSuffix(opcode, "PD") || strings.HasSuffix(opcode, "SD") {
			bits = 64
		}
		fmt.Fprintf(&assembly, "TEXT %s(SB),4,$0-24\nMOVQ out+0(FP),AX\nMOVQ a+8(FP),BX\nMOVQ b+16(FP),CX\nVMOVUPS (BX),Z0\nVMOVUPS (CX),Z1\nSTC\n%s X0,X1,$0\nVMOVUPS Z1,(AX)\nSETCS 64(AX)\nRET\n", name, opcode)
		sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1},
			}}}
		fmt.Fprintf(&declarations, "extern void %s(void*,const void*,const void*);\n", name)
		fmt.Fprintf(&checks, `
 {
  uint8_t a[64], b[64], out[67], expected[64];
  for(int i=0; i<64; i++) a[i]=b[i]=(uint8_t)(i*29+11);
  memset(out,0xc3,sizeof(out));
  memcpy(expected,b,64);
  int compared=%d ? %d : 16;
  memset(expected,0xff,compared);
  %s(out+1,a,b);
  for(int i=0;i<64;i++) {
   if(out[i+1]!=expected[i]) {
    fprintf(stderr,"%s byte=%%d got=%%x expected=%%x\n",i,out[i+1],expected[i]);
    return 10;
   }
  }
  if(out[0]!=0xc3 || out[65]!=1 || out[66]!=0xc3) return 11;
 }
`, x86FloatAddSubBoolInt(scalar), bits/8, name, opcode)
	}
	goAssemblerOracleOutput(t, "amd64", assembly.String(), "", true)
	file, err := Parse(ArchAMD64, assembly.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: execution.triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	main := "#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n" + declarations.String() + "int main(void){\n" + checks.String() + "return 0;}\n"
	execution.compileAndRunLLVM(t, "floating-compare-legacy-alias", ir, main, "-O2")
}
