package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// This independent regression is runnable on the original production code;
// it does not call the new result/effect descriptor or derive its reference
// from the immediate conversion used by the emitter.
func TestX86ExplicitIMULTwoOperandImm32OriginalGoAndLLVM(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	pkg, file, sig, source := x86ResultInitializationFixture(t, "amd64", "func Value(x uint64) uint64",
		"MOVQ x+0(FP),BX\nIMULQ $2147483648,BX\nMOVQ BX,ret0+8(FP)\nRET")
	_ = pkg
	goAssemblerOracleOutput(t, "amd64", source, "", true)
	dir := t.TempDir()
	for name, contents := range map[string]string{
		"go.mod":        "module imulred\n\ngo 1.20\n",
		"value.go":      "package imulred\nfunc Value(x uint64) uint64\n",
		"value_amd64.s": source,
		"value_test.go": `package imulred
import "testing"
func TestOriginal(t *testing.T) {
 factor:=int64(-2147483648)
 for _,x:=range []uint64{0,1,0xfaceb00c01234567,0x8000000000000000,0xffffffffffffffff} {
  want:=x*uint64(factor)
  if got:=Value(x);got!=want {t.Fatalf("x=%x got=%x want=%x",x,got,want)}
 }
}
`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	binary := filepath.Join(dir, "original.test")
	command := exec.Command("go", "test", "-p=2", "-vet=off", "-c", "-o", binary, ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOARCH=amd64", "CGO_ENABLED=0", "GOMAXPROCS=2")
	x86FloatCompareCaptureCommand(t, command)
	output := execution.run(t, binary, "-test.run=^TestOriginal$", "-test.count=1", "-test.v")
	if !strings.Contains(string(output), "--- PASS: TestOriginal") {
		t.Fatalf("original Go immediate oracle failed: %s", output)
	}
	t.Log("original Go accepted IMULQ imm32 and independently matched five initialized inputs")
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: execution.triple, Sigs: map[string]FuncSig{"Value": sig},
		ResolveSym: func(symbol string) string { return strings.TrimPrefix(symbol, "·") }})
	if err != nil {
		t.Fatal(err)
	}
	reference := `#include <stdint.h>
#include <stdio.h>
extern uint64_t Value(uint64_t);
int main(void) {
 const uint64_t inputs[]={0,1,UINT64_C(0xfaceb00c01234567),UINT64_C(0x8000000000000000),UINT64_C(0xffffffffffffffff)};
 for(unsigned i=0;i<5;i++) {
  uint64_t want=inputs[i]*UINT64_C(0xffffffff80000000),got=Value(inputs[i]);
  if(got!=want) {fprintf(stderr,"original imm32 x=%llx got=%llx want=%llx\n",(unsigned long long)inputs[i],(unsigned long long)got,(unsigned long long)want);return 1;}
 }
 return 0;
}
`
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(fmt.Sprint(level), func(t *testing.T) {
			execution.compileAndRunLLVM(t, "original-imul-imm32", ir, reference, level)
		})
	}
}
