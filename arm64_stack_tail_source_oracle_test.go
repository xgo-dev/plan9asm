package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func arm64StackTailTargetSource() string {
	var source strings.Builder
	source.WriteString("TEXT ·arm64ABI0TailTarget(SB),4,$0-144\nMOVD $0,R0\n")
	for i := 0; i < 17; i++ {
		fmt.Fprintf(&source, "MOVD a%d+%d(FP),R1\nADD R1,R0\n", i, i*8)
	}
	source.WriteString("MOVD R0,ret+136(FP)\nRET\n")
	return source.String()
}

func arm64StackTailOriginalSource() string {
	var source strings.Builder
	source.WriteString("TEXT ·arm64ABI0StackTail(SB),$144-0\n")
	for i := 0; i < 17; i++ {
		fmt.Fprintf(&source, "MOVD $%d,R0\nMOVD R0,%d(RSP)\n", i+1, 8+i*8)
	}
	source.WriteString("JMP ·arm64ABI0TailTarget(SB)\n")
	return source.String()
}

func TestCrossLinuxRuntimeMatrixARM64StackTailOriginalSPOracle(t *testing.T) {
	_, _, _, runner := arm64FPPairRuntimeTools(t)
	source := `TEXT ·Measure(SB),516,$0-16
MOVD RSP,R19
MOVD R30,R23
MOVD R29,R24
CALL ·arm64ABI0StackTail(SB)
MOVD 144(RSP),R1
SUB R19,RSP,R0
MOVD R19,RSP
MOVD R24,R29
MOVD R23,R30
MOVD R0,delta+0(FP)
MOVD R1,sum+8(FP)
RET
` + arm64StackTailOriginalSource() + arm64StackTailTargetSource()
	runARM64LocalRegisterGoOracle(t, source, `package main
func Measure() (int64,uint64)
func arm64ABI0StackTail()
func arm64ABI0TailTarget(uint64,uint64,uint64,uint64,uint64,uint64,uint64,uint64,uint64,uint64,uint64,uint64,uint64,uint64,uint64,uint64,uint64) uint64
func main() {
  for i:=0;i<5;i++ {
    delta,sum:=Measure()
    if delta!=-160 || sum!=153 { println(delta,sum); panic("original framed JMP does not unwind its Go frame") }
  }
}
`, len(runner) != 0)
	t.Log("native Go original 17-slot JMP computes 153 but leaves caller SP delta -160; real caller state is restored by observation trampoline")
}

// Matching incoming Go ABI0 slots can be forwarded without manufacturing an
// outgoing frame. This is a real frameless source tail, including arguments
// beyond both the Go and platform-native register banks.
func TestCrossLinuxRuntimeMatrixARM64StackTailIncomingFrame(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	source := "TEXT ·Pass(SB),4,$0-144\nB ·arm64ABI0TailTarget(SB)\n" + arm64StackTailTargetSource()
	var parameters, arguments strings.Builder
	for i := 0; i < 17; i++ {
		if i != 0 {
			parameters.WriteString(",")
			arguments.WriteString(",")
		}
		parameters.WriteString("uint64")
		fmt.Fprintf(&arguments, "a+%d", i+1)
	}
	decl := fmt.Sprintf("func Pass(%s) uint64\nfunc arm64ABI0TailTarget(%s) uint64\n", parameters.String(), parameters.String())
	runARM64LocalRegisterGoOracle(t, source, "package main\n"+decl+fmt.Sprintf(`func main() {
  for _,a:=range []uint64{0,1,123,0x8000000000000000,^uint64(0)} {
    if Pass(%s)!=a*17+153 { panic("proper incoming-frame tail mismatch") }
  }
}
`, arguments.String()), len(runner) != 0)
	pkg := mustGoPackage(t, "test/stacktail", "package stacktail\n"+decl)
	translate := func(target string) string {
		tr, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{
			GOARCH: "arm64", TargetTriple: target,
			ResolveSym: func(sym string) string { return strings.TrimPrefix(sym, "·") },
		})
		if err != nil {
			t.Fatal(err)
		}
		defer tr.Module.Dispose()
		return tr.Module.String()
	}
	for _, target := range []string{"aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl", "aarch64-apple-darwin", "aarch64-pc-windows-msvc"} {
		compileLLVMToObject(t, llc, target, "incoming-tail.ll", "incoming-tail.o", translate(target))
	}
	cParams := strings.TrimSuffix(strings.Repeat("uint64_t,", 17), ",")
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "incoming_tail", triple, translate(triple), fmt.Sprintf(`#include <stdint.h>
extern uint64_t Pass(%s);
int main(void) {
  uint64_t inputs[]={0,1,123,UINT64_C(0x8000000000000000),UINT64_MAX};
  for (unsigned i=0;i<5;i++) {
    uint64_t a=inputs[i];
    if (Pass(%s)!=a*17+153) return 1;
  }
  return 0;
}
`, cParams, arguments.String()), runner)
}
