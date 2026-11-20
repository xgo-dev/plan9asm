//go:build unix

package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// The Go assembler owns the prologue and NAME_AUTO bias. A write through the
// formed address, followed by a physical-SP read, distinguishes a misplaced
// address even when an unrelated spill happens to contain the original input.
func TestCrossLinuxRuntimeMatrixGoAMD64NamedLocalAddressBias(t *testing.T) {
	execution := x86FloatCompareRuntimeTools(t, x86FloatCompareSSE)
	goAMD64FramePrepareOwnedToolCache(t)
	var assembly, declarations, goCalls, cDeclarations, cCalls strings.Builder
	prefix := ""
	if strings.Contains(execution.triple, "apple") {
		prefix = "_"
	}
	for index, address := range []string{"MOVQ $slot-16(SP),BX", "LEAQ slot-16(SP),BX"} {
		name := fmt.Sprintf("Address%d", index)
		fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$16-16\nMOVQ input+0(FP),AX\nMOVQ AX,0(SP)\n%s\nMOVQ $0x13579bdf2468ace0,CX\nMOVQ CX,(BX)\nMOVQ 0(SP),AX\nMOVQ AX,ret+8(FP)\nRET\n", name, address)
		fmt.Fprintf(&declarations, "func %s(input uint64) uint64\n", name)
		fmt.Fprintf(&goCalls, "check(%d,%s)\n", index, name)
		fmt.Fprintf(&cDeclarations, "extern uint64_t address%d(uint64_t) __asm__(%s);\n", index,
			runtimeCAsmLabel(prefix+"example.invalid/framefixture."+name))
		fmt.Fprintf(&cCalls, "check(%d,address%d);\n", index, index)
	}
	original := `package main
import "fmt"
` + declarations.String() + `
func check(index int, call func(uint64) uint64) {
    for sample,input := range []uint64{0,1,0xffffffffffffffff,0x0123456789abcdef} {
        got := call(input)
        if got != 0x13579bdf2468ace0 { panic("original Go NAME_AUTO address differs from physical SP") }
        fmt.Printf("%d %d %016x\n",index,sample,got)
    }
}
func main(){
` + goCalls.String() + "}\n"
	driver := `#include <stdint.h>
#include <stdio.h>
` + runtimeCAsmLabelPreamble + cDeclarations.String() + `
static void check(int index, uint64_t (*call)(uint64_t)) {
    const uint64_t inputs[]={0,1,UINT64_MAX,UINT64_C(0x0123456789abcdef)};
    for(unsigned sample=0; sample<4; sample++) {
        printf("%d %u %016llx\n",index,sample,(unsigned long long)call(inputs[sample]));
    }
}
int main(void){
` + cCalls.String() + "return 0;}\n"
	want := strings.TrimSpace(string(x86ScalarFloatIntegerOriginalOutput(t, execution, assembly.String(), original)))
	if len(strings.Split(want, "\n")) != 8 {
		t.Fatal("original Go did not execute both address forms and all four inputs", want)
	}
	t.Log("original Go executed original MOVQ and LEAQ with its actual native frame/prologue: 8 observations")
	pkg, request, _, options := fixedLocalTransportFixture(t, assembly.String(), declarations.String(), runtime.GOOS+"/amd64", execution.triple)
	fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"}, func(t *testing.T, ir string, err error) {
		if err != nil {
			t.Fatal("same original source lost its captured private-frame contract", err)
		}
		for _, level := range []string{"-O0", "-O2"} {
			t.Run(level, func(t *testing.T) {
				input := ir
				if level == "-O2" {
					input = x86MulDivRoundOptimize(t, ir)
				}
				got := strings.TrimSpace(string(execution.compileAndRunLLVM(t, "named-local-address", input, driver, level)))
				if got != want {
					t.Errorf("original Go/LLVM named-address writeback differs:\nGo:\n%s\nLLVM:\n%s", want, got)
				}
			})
		}
	})
}
