package plan9asm

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// This is deliberately a Go-only witness for source continuations that the
// LLVM helper contract must reject. The wrapper restores the observed SP
// before crossing back into Go, so a framed B does not corrupt the Go caller.
func TestCrossLinuxRuntimeMatrixARMKernelSourceContinuation(t *testing.T) {
	if os.Getenv("PLAN9ASM_CROSS_EXEC") != "1" {
		t.Skip("set PLAN9ASM_CROSS_EXEC=1 for the actual Go ARM continuation oracle")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Fatal("ARM continuation oracle requires a Linux driver")
	}
	if _, err := exec.LookPath("qemu-arm"); err != nil {
		t.Fatal(err)
	}
	const main = `package main
import "fmt"
func oracle(ptr *uint32, out *[4]uint32, kind uint32)
func main() {
 deltas := [...]uint32{0,8,20,36,0,0,0,0,4,0,0}
 for kind,delta := range deltas {
  word,out := uint32(0),[4]uint32{}
  oracle(&word,&out,uint32(kind))
  marker := uint32(77)
  if kind == 10 { marker = 99 }
  if word != 1 || out != [4]uint32{delta,0,1,marker} {
   panic(fmt.Sprintf("Go continuation kind=%d word=%x out=%v want delta=%d marker=%d",kind,word,out,delta,marker))
  }
  fmt.Printf("kind=%d SP-delta=%d status=%d C=%d continuation=%d\n",kind,out[0],out[1],out[2],out[3])
 }
}
`
	const assembly = `#include "textflag.h"
TEXT cas<>(SB),NOSPLIT,$0
 MOVW $0xffff0fc0,R15
TEXT dummy<>(SB),NOSPLIT,$0
 RET
TEXT b0<>(SB),NOSPLIT,$0
 B cas<>(SB)
TEXT b4<>(SB),NOSPLIT,$4
 B cas<>(SB)
TEXT b16<>(SB),NOSPLIT,$16
 B cas<>(SB)
TEXT b32<>(SB),NOSPLIT,$32
 B cas<>(SB)
TEXT ret0<>(SB),NOSPLIT,$0
 RET cas<>(SB)
TEXT ret4<>(SB),NOSPLIT,$4
 RET cas<>(SB)
TEXT ret16<>(SB),NOSPLIT,$16
 RET cas<>(SB)
TEXT ret32<>(SB),NOSPLIT,$32
 RET cas<>(SB)
TEXT implicitB<>(SB),NOSPLIT,$0
 BL dummy<>(SB)
 MOVW (R13),R14
 B cas<>(SB)
TEXT implicitRET<>(SB),NOSPLIT,$0
 BL dummy<>(SB)
 RET cas<>(SB)
TEXT redirect<>(SB),NOSPLIT,$0
 MOVW R14,R9
 MOVW $continuation<>(SB),R14
 B cas<>(SB)
TEXT continuation<>(SB),NOSPLIT,$0
 MOVW $99,R7
 MOVW R9,R14
 RET
TEXT ·oracle(SB),NOSPLIT,$96-12
 MOVW ptr+0(FP),R2
 MOVW out+4(FP),R4
 MOVW kind+8(FP),R5
 MOVW $0,R0
 MOVW $1,R1
 MOVW $77,R7
 MOVW R13,R8
 CMP $0,R5
 BEQ case0
 CMP $1,R5
 BEQ case1
 CMP $2,R5
 BEQ case2
 CMP $3,R5
 BEQ case3
 CMP $4,R5
 BEQ case4
 CMP $5,R5
 BEQ case5
 CMP $6,R5
 BEQ case6
 CMP $7,R5
 BEQ case7
 CMP $8,R5
 BEQ case8
 CMP $9,R5
 BEQ case9
 BL redirect<>(SB)
 B report
case0:
 BL b0<>(SB)
 B report
case1:
 BL b4<>(SB)
 B report
case2:
 BL b16<>(SB)
 B report
case3:
 BL b32<>(SB)
 B report
case4:
 BL ret0<>(SB)
 B report
case5:
 BL ret4<>(SB)
 B report
case6:
 BL ret16<>(SB)
 B report
case7:
 BL ret32<>(SB)
 B report
case8:
 BL implicitB<>(SB)
 B report
case9:
 BL implicitRET<>(SB)
report:
 MOVW $0,R6
 MOVW.CS $1,R6
 SUB R13,R8,R5
 MOVW R8,R13
 MOVW R5,0(R4)
 MOVW R0,4(R4)
 MOVW R6,8(R4)
 MOVW R7,12(R4)
 RET
`
	dir := t.TempDir()
	for name, data := range map[string]string{
		"go.mod":  "module armcontinuationoracle\n\ngo 1.20\n",
		"main.go": main, "oracle_arm.s": assembly,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("go", "run", "-p=1", "-exec=qemu-arm", ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm", "GOARM=7", "CGO_ENABLED=0")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("actual Go source B/RET/SP/LR oracle: %v\n%s", err, output)
	}
	t.Logf("actual Go source continuation witness:\n%s", output)
}
