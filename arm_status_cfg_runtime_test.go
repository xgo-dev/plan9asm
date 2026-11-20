package plan9asm

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCrossLinuxRuntimeMatrixARMStatusCFG(t *testing.T) {
	if os.Getenv("PLAN9ASM_CROSS_EXEC") != "1" {
		t.Skip("set PLAN9ASM_CROSS_EXEC=1 for actual Go/LLVM ARM status CFG execution")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Fatal("ARM status CFG oracle requires a Linux driver")
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
	const rejected = `TEXT rejected<>(SB),4,$0
 B read
 CMP R0,R0
read:
 MOVW CPSR,R0
 SRL $28,R0
 RET
`
	const accepted = `TEXT flags(SB),4,$0-8
 MOVW value+0(FP),R0
 B setup
read:
 MOVW CPSR,R0
 SRL $28,R0
 MOVW R0,ret+4(FP)
 RET
setup:
 CMP $0,R0
 BEQ zero
 CMP $1,R0
 B read
zero:
 CMP $2,R0
 B read
`
	const wrapper = `TEXT ·oracle(SB),4,$0-4
 MOVW out+0(FP),R4
 MOVW $0,R0
 CMP R0,R0
 BL rejected<>(SB)
 MOVW R0,(R4)
 RET
`
	const main = `package main
import "fmt"
func oracle(out *uint32)
func flags(value uint32) uint32
func main() {
 out := uint32(0)
 oracle(&out)
 if out != 6 { panic(fmt.Sprintf("Go bypassed flags writer: got NZCV=%x want6",out)) }
 for _,test := range []struct{value,want uint32}{{0,8},{1,6},{2,2},{0x80000000,3},{0xffffffff,10}} {
  if actual := flags(test.value); actual != test.want { panic(fmt.Sprintf("Go CFG NZCV input=%x got=%x want=%x",test.value,actual,test.want)) }
 }
 fmt.Println("Go native-entry NZCV=6; source-defined CFG vectors passed")
}
`
	dir := t.TempDir()
	for name, data := range map[string]string{
		"go.mod": "module armstatusoracle\n\ngo 1.20\n", "main.go": main,
		"oracle_arm.s": rejected + wrapper + "TEXT ·" + accepted[len("TEXT "):],
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("go", "run", "-p=1", "-exec=qemu-arm", ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm", "GOARM=7", "CGO_ENABLED=0")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("native Go ARM status CFG oracle: %v\n%s", err, output)
	} else {
		t.Logf("actual Go oracle: %s", output)
	}
	file, err := Parse(ArchARM, rejected)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", ResolveSym: func(string) string { return "rejected" }, Sigs: map[string]FuncSig{
		"rejected": {Name: "rejected", Ret: I32},
	}})
	if err == nil {
		// The old implementation packs zero-filled slots because it saw an
		// unreachable CMP while compiling, despite the real entry NZCV=6.
		const oldOracle = `#include <stdint.h>
#include <stdio.h>
extern uint32_t rejected(void);
int main(void) {
 register uint32_t result __asm__("r0");
 __asm__ volatile("cmp r0,r0; bl rejected" : "=r"(result) : : "r1","r2","r3","r12","lr","cc","memory");
 if (result != 6) { fprintf(stderr,"LLVM bypassed-writer NZCV=%x; native Go=6\n",result); return 1; }
 return 0;
}
`
		compileAndRunRuntimeTestWithCompiler(t, llc, []string{"arm-linux-gnueabihf-gcc", "-no-pie"}, "old_status_cfg", "armv7-unknown-linux-gnueabihf", ir, oldOracle,
			[]string{"qemu-arm", "-L", "/usr/arm-linux-gnueabihf"})
		t.Fatal("unbound native-entry flags cannot pass by sampling physical flags after an LLVM prologue")
	}
	if !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("unbound initial flags must remain a context failure: %v", err)
	}
	file, err = Parse(ArchARM, accepted)
	if err != nil {
		t.Fatal(err)
	}
	ir, err = Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{
		"flags": {Name: "flags", Args: []LLVMType{I32}, Ret: I32, Frame: FrameLayout{
			Params:  []FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}},
			Results: []FrameSlot{{Offset: 4, Type: I32, Index: 0, Field: -1}},
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	const oracle = `#include <stdint.h>
#include <stdio.h>
extern uint32_t flags(uint32_t);
int main(void) {
 const uint32_t input[]={0,1,2,0x80000000u,0xffffffffu}, want[]={8,6,2,3,10};
 for (unsigned i=0;i<5;i++) {
  uint32_t actual=flags(input[i]);
  if (actual!=want[i]) { fprintf(stderr,"LLVM CFG NZCV input=%x got=%x want=%x\n",input[i],actual,want[i]); return 1; }
 }
 return 0;
}
`
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"arm-linux-gnueabihf-gcc", "-no-pie"}, "status_cfg", "armv7-unknown-linux-gnueabihf", ir, oracle,
		[]string{"qemu-arm", "-L", "/usr/arm-linux-gnueabihf"})
}
