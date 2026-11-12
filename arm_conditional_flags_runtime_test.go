package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixARMConditionalFlags(t *testing.T) {
	if os.Getenv("PLAN9ASM_CROSS_EXEC") != "1" {
		t.Skip("set PLAN9ASM_CROSS_EXEC=1 for actual ARM predicated-flags execution")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Fatal("ARM conditional-flags oracle requires a Linux driver")
	}
	for _, tool := range []string{"arm-linux-gnueabihf-gcc", "qemu-arm"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatal(err)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc not found")
	}
	var source strings.Builder
	source.WriteString("TEXT conditional(SB),4,$0-8\n MOVW out+4(FP),R4\n")
	for index, instruction := range []string{
		"CMP.NE $1,R0", "CMN.NE $1,R0", "TST.NE $1,R0", "TEQ.NE $1,R0",
		"ADD.EQ.S $1,R0", "ORR.EQ.S $0x80000000,R0", "MOVW.EQ.S R0,R2",
		"MOVW $0,R0\n CMP $1,R0\n ORR.S $0x80000000,R0", "AND.EQ.S $0x7fffffff,R0",
		"TST $0x40000000,R0", "TEQ $0x40000000,R0",
	} {
		fmt.Fprintf(&source, " MOVW value+0(FP),R0\n CMP R0,R0\n %s\n MOVW CPSR,R1\n SRL $28,R1\n MOVW R1,%d(R4)\n", instruction, index*4)
	}
	source.WriteString(" RET\n")
	const main = `package main
import "fmt"
func conditional(value uint32,out *[11]uint32)
func main() {
 inputs := [...]uint32{0,1,0x7fffffff,0x80000000,0xffffffff}
 additions := [...]uint32{0,0,9,8,6}
 moves := [...]uint32{6,2,2,10,10}
 complements := [...]uint32{6,2,2,6,2}
 tests := [...]uint32{4,4,0,4,0}
 exclusive := [...]uint32{0,0,0,8,8}
 for i,value := range inputs {
  var out [11]uint32
  conditional(value,&out)
  want := [11]uint32{6,6,6,6,additions[i],10,moves[i],10,complements[i],tests[i],exclusive[i]}
  if out != want { panic(fmt.Sprintf("Go predicated flags input=%x got=%v want=%v",value,out,want)) }
 }
 fmt.Println("Go CMP/CMN/TST/TEQ false predicates and ADD/ORR single-decision flag writes passed")
}
`
	dir := t.TempDir()
	for name, data := range map[string]string{
		"go.mod": "module armpredicateoracle\n\ngo 1.20\n", "main.go": main,
		"oracle_arm.s": strings.Replace(source.String(), "TEXT conditional(", "TEXT ·conditional(", 1),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("go", "run", "-p=1", "-exec=qemu-arm", ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm", "GOARM=7", "CGO_ENABLED=0")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("native Go ARM predicated-flags oracle: %v\n%s", err, output)
	} else {
		t.Logf("actual Go oracle: %s", output)
	}
	file, err := Parse(ArchARM, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{
		"conditional": {Name: "conditional", Args: []LLVMType{I32, Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
			{Offset: 0, Type: I32, Index: 0, Field: -1}, {Offset: 4, Type: Ptr, Index: 1, Field: -1},
		}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	const oracle = `#include <stdint.h>
#include <stdio.h>
extern void conditional(uint32_t,uint32_t*);
int main(void) {
 const uint32_t inputs[]={0,1,0x7fffffffu,0x80000000u,0xffffffffu},additions[]={0,0,9,8,6};
 const uint32_t moves[]={6,2,2,10,10},complements[]={6,2,2,6,2},tests[]={4,4,0,4,0},exclusive[]={0,0,0,8,8};
 for (unsigned i=0;i<5;i++) {
  uint32_t out[11]={0},want[]={6,6,6,6,additions[i],10,moves[i],10,complements[i],tests[i],exclusive[i]};
  conditional(inputs[i],out);
  for (unsigned j=0;j<11;j++) if(out[j]!=want[j]) {
   fprintf(stderr,"LLVM predicated flags input=%x lane=%u got=%x want=%x\n",inputs[i],j,out[j],want[j]);return 1;
  }
 }
 return 0;
}
`
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"arm-linux-gnueabihf-gcc", "-no-pie"}, "conditional_flags", "armv7-unknown-linux-gnueabihf", ir, oracle,
		[]string{"qemu-arm", "-L", "/usr/arm-linux-gnueabihf"})
}
