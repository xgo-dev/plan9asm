package plan9asm

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixARMSupervisorCall(t *testing.T) {
	const triple = "armv7-unknown-linux-gnueabihf"
	const src = `TEXT rawPID(SB),NOSPLIT,$0-4
	MOVW $20,R7
	SWI
	MOVW R0,ret+0(FP)
	RET
TEXT badClose(SB),NOSPLIT,$0-8
	MOVW fd+0(FP),R0
	MOVW $6,R7
	SWI $0
	MOVW R0,ret+4(FP)
	RET
TEXT conditionalPID(SB),NOSPLIT,$0-8
	MOVW yes+0(FP),R1
	MOVW $123456789,R0
	MOVW $20,R7
	CMP $0,R1
	SWI.NE $0
	MOVW R0,ret+4(FP)
	RET
TEXT secondRegister(SB),NOSPLIT,$0-4
	MOVW $1729,R1
	MOVW $20,R7
	SWI $0
	MOVW R1,ret+0(FP)
	RET
TEXT encodedSvc(SB),NOSPLIT,$0-0
	SWI $65535
	RET
`
	f, err := Parse(ArchARM, src)
	if err != nil {
		t.Fatal(err)
	}
	sigs := map[string]FuncSig{"encodedSvc": {Ret: Void}}
	for _, name := range []string{"rawPID", "secondRegister"} {
		sigs[name] = FuncSig{Name: name, Ret: I32, Frame: FrameLayout{Results: []FrameSlot{{Type: I32, Field: -1}}}}
	}
	for _, name := range []string{"badClose", "conditionalPID"} {
		sigs[name] = crossUnarySig("arm", name)
	}
	options := Options{Goarch: "arm", TargetTriple: triple, Sigs: sigs}
	ll, err := Translate(f, options)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ll, "@syscall(") || !strings.Contains(ll, ".inst 0xef00ffff") {
		t.Fatal("A32 SWI must preserve its encoded immediate and raw kernel ABI")
	}
	for _, target := range []string{"", "x86_64-unknown-linux-gnu", "armv7-unknown-freebsd", "armv7a-none-eabi"} {
		options.TargetTriple = target
		if _, err := Translate(f, options); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("%q: got %v, want missing Linux A32 ABI", target, err)
		}
	}
	ll = runOptO2(t, ll)
	verifyLLVMWithTargetLLC(t, ll, triple)
	if os.Getenv("PLAN9ASM_CROSS_EXEC") == "1" {
		const main = `
#include <unistd.h>
extern int rawPID(void), badClose(int), conditionalPID(int), secondRegister(void);
int main(void) {
 int pid = getpid();
 if (pid <= 0 || rawPID() != pid) return 1;
 if (badClose(-1) != -9) return 2;
 if (conditionalPID(1) != pid || conditionalPID(0) != 123456789) return 3;
 if (secondRegister() != 1729) return 4;
 return 0;
}
`
		compileAndRunRuntimeTestWithCompiler(t, findLLVM22Tool("llc"), []string{"arm-linux-gnueabihf-gcc", "-marm"}, "supervisor", triple, ll, main, []string{"qemu-arm", "-L", "/usr/arm-linux-gnueabihf"})
	}
}
