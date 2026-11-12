package plan9asm

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86ABI0ScalarImportIndependentResult(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	const declaration = "func view(x uint32,p *byte) uint32\n"
	const source = `TEXT ·view(SB),4,$0-20
MOVL x+0(FP),X0
MOVQ p+8(FP),SI
MOVQ SI,DI
MOVL $7,CX
LEAQ 4(DI)(CX*2),BX
PEXTRD $0,X0,AX
MOVL AX,ret+16(FP)
RET
`
	const originalTest = `package scalarimport
import "testing"
func TestOriginal(t *testing.T) {
 for sample:=uint32(0);sample<257;sample++ {
  x:=sample*0x9e3779b9
  data:=[4]byte{0x19,0x28,0x37,0x46}
  for _,p:=range []*byte{nil,&data[0],&data[3]} {
   if got:=view(x,p);got!=x { t.Fatalf("sample%d got%x want%x",sample,got,x) }
   if data!=[4]byte{0x19,0x28,0x37,0x46} { t.Fatal("opaque pointer transport touched input") }
  }
 }
}
`
	dir := t.TempDir()
	for name, contents := range map[string]string{
		"go.mod":       "module scalarimport\n\ngo 1.20\n",
		"view.go":      "package scalarimport\n" + declaration,
		"view_amd64.s": source, "view_test.go": originalTest,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	x86LEAActualTargetGoObject(t, "amd64", execution.triple, source)
	binary := filepath.Join(dir, "original.test")
	ctx, cancel := runtimeOracleStageContext(t)
	command := exec.CommandContext(ctx, "go", "test", "-p=2", "-vet=off", "-c", "-o", binary, ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOARCH=amd64", "CGO_ENABLED=0")
	output, err := runtimeOracleCombinedOutput(ctx, command)
	cancel()
	if err != nil {
		t.Fatalf("original first-party scalar-import object: %v\n%s", err, output)
	}
	if output := execution.run(t, binary, "-test.run=^TestOriginal$", "-test.count=1", "-test.v"); !strings.Contains(string(output), "--- PASS: TestOriginal") {
		t.Fatalf("original scalar-import runtime has no passing terminal: %s", output)
	}
	ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", execution.triple, "Go")
	if err != nil {
		t.Fatal(err)
	}
	const main = `#include <stdint.h>
#include <stdio.h>
#include <string.h>
extern uint32_t view(uint32_t,void *);
int main(void) {
 for(uint32_t sample=0;sample<257;sample++) {
  uint32_t x=sample*UINT32_C(0x9e3779b9);
  uint8_t data[4]={0x19,0x28,0x37,0x46};
  const uint8_t expected[4]={0x19,0x28,0x37,0x46};
  void *p[3]={NULL,data,data+3};
  for(int i=0;i<3;i++) {
   volatile struct { uint32_t before,value,after; } result={0x11223344,view(x,p[i]),0x88776655};
   if(result.value!=x||result.before!=0x11223344||result.after!=0x88776655||memcmp(data,expected,4)) {
    fprintf(stderr,"sample%u pointer%d got%x want%x\n",sample,i,result.value,x);return 1;
   }
  }
 }
 puts("SCALAR_IMPORT_NUMERICAL_AND_INPUT_GUARDS_PASS");return 0;
}
`
	for _, level := range []string{"-O0", "-O2"} {
		t.Run("backend"+level, func(t *testing.T) {
			output := execution.compileAndRunLLVM(t, "scalar-import", ir, main, level)
			if !strings.Contains(string(output), "SCALAR_IMPORT_NUMERICAL_AND_INPUT_GUARDS_PASS") {
				t.Fatalf("LLVM scalar-import runtime has no passing terminal: %s", output)
			}
		})
	}
	t.Log("257 numerical inputs ×3 opaque identities, original Go plus LLVM backend O0/O2; no pointee read or native Linux claim on Rosetta")
}
