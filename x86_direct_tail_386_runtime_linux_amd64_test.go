//go:build linux && amd64

package plan9asm

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The required Linux AMD64 owner executes this static i386 original and LLVM
// counterpart through the kernel's compatibility ISA. An emulated local host
// is only diagnostic; a missing compiler/compatibility entry fails, never skips.
func TestCrossLinuxRuntimeMatrixX86DirectTail386OriginalGoAndLLVM(t *testing.T) {
	for _, carrier := range []string{"SI", "BP", "SI-stack", "BP-stack"} {
		t.Run(carrier, func(t *testing.T) {
			register := strings.TrimSuffix(carrier, "-stack")
			source := strings.ReplaceAll(x86DirectTail386ASM, "SI", register)
			if strings.HasSuffix(carrier, "-stack") {
				source = strings.Replace(source, " MOVL "+register+",AX", " PUSHL "+register+"\n POPL AX", 1)
			}
			x86DirectTail386ExecuteOriginalGoAndLLVM(t, source)
		})
	}
}

func x86DirectTail386ExecuteOriginalGoAndLLVM(t *testing.T, source string) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	compiler, err := exec.LookPath("i686-linux-gnu-gcc")
	if llc == "" || err != nil {
		t.Fatalf("required LLVM22/i386 native counterpart tools: llc=%q compiler=%v", llc, err)
	}
	execution := x86FloatCompareExecution{llc: llc, triple: "i386-unknown-linux-gnu",
		compiler: []string{compiler, "-static", "-no-pie"}}
	dir := t.TempDir()
	goDriver := `package main
import "fmt"
` + x86DirectTail386Go + `
func main() {
 values:=[]uint32{0,1,7,0xffff,0x10000,0x7fffffff,0x80000000,0xffffffff}
 calls:=0
 for _,a:=range values {
  if got:=First(a); got!=a+7 {panic(fmt.Sprintf("First got=%x want=%x",got,a+7))}
  calls++
  for _,b:=range values {
   x,y:=uint16(a),uint16(b)
   if got:=Second(x,y); got!=uint32(x)+uint32(y) {panic(fmt.Sprintf("Second got=%x want=%x",got,uint32(x)+uint32(y)))}
   calls++
  }
 }
 fmt.Printf("i386 whole direct-tail original/LLVM: %d independent value checks\n",calls)
}
`
	for name, source := range map[string]string{
		"go.mod": "module directtail386\n\ngo 1.20\n", "main.go": goDriver, "tail_386.s": source,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	original := filepath.Join(dir, "original")
	command := exec.Command("go", "build", "-p=1", "-o", original, ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH=386", "CGO_ENABLED=0", "GOMAXPROCS=2")
	x86FloatCompareCaptureCommand(t, command)
	want := "i386 whole direct-tail original/LLVM: 72 independent value checks\n"
	if output := execution.run(t, original); string(output) != want {
		t.Fatalf("incomplete original i386 execution: %s", output)
	}
	driver := `#include <stdint.h>
#include <stdio.h>
extern uint32_t First(uint32_t);
extern uint32_t Second(uint16_t,uint16_t);
int main(void) {
    const uint32_t values[]={0,1,7,0xffff,0x10000,0x7fffffff,0x80000000,0xffffffff};
    volatile uint32_t canaries[]={0x12345678,0x87654321};
    unsigned calls=0;
    for(unsigned i=0;i<sizeof(values)/sizeof(values[0]);i++) {
        uint32_t a=values[i],got=First(a),want=a+7;
        if(got!=want) {fprintf(stderr,"First sample=%u got=%x want=%x\n",i,got,want);return 1;}
        calls++;
        for(unsigned j=0;j<sizeof(values)/sizeof(values[0]);j++) {
            uint16_t x=(uint16_t)a,y=(uint16_t)values[j];
            got=Second(x,y);want=(uint32_t)x+y;
            if(got!=want) {fprintf(stderr,"Second samples=%u,%u got=%x want=%x\n",i,j,got,want);return 1;}
            calls++;
        }
        if(canaries[0]!=0x12345678||canaries[1]!=0x87654321) return 1;
    }
    printf("i386 whole direct-tail original/LLVM: %u independent value checks\n",calls);
    return 0;
}
`
	for _, api := range []string{"text", "module", "Go"} {
		ir, err := x86ScalarFPBitViewAPI(t, source, x86DirectTail386Go, "386", execution.triple, api)
		if err != nil {
			t.Fatal(api, err)
		}
		for _, level := range []string{"-O0", "-O2"} {
			output := execution.compileAndRunLLVM(t, "whole-direct-tail-386", ir, driver, level)
			if string(output) != want {
				t.Fatalf("%s/%s incomplete i386 LLVM counterpart: %s", api, level, output)
			}
			t.Log(api, level, strings.TrimSpace(string(output)))
		}
	}
}
