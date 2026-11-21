package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

const armLocalCallOracle = `TEXT oracle(SB),516,$0-8
	MOVW value+0(FP),R0
	MOVW R14,R8
	CMP $0,R0
	BL.EQ helper
	ADD.NE $3,R0
	MOVW.NE R0,ret+4(FP)
	RET.NE
	CALL helper
	MOVW R8,R14
	MOVW R0,ret+4(FP)
	RET
helper:
	MOVW R14,R9
	BL inner
	MOVW R9,R7
	MOVW R9,R14
	B (R7)
inner:
	ADD $3,R0
	ADD.EQ $5,R0
	RET
`

func armLocalCallSignature(name string) FuncSig {
	return FuncSig{
		Name: name, Args: []LLVMType{I32}, Ret: I32,
		Frame: FrameLayout{
			Params:  []FrameSlot{{Offset: 0, Index: 0, Type: I32, Field: -1}},
			Results: []FrameSlot{{Offset: 4, Index: 0, Type: I32, Field: -1}},
		},
	}
}

func TestARMNamedLocalCallContinuationObjects(t *testing.T) {
	sigs := map[string]FuncSig{"oracle": armLocalCallSignature("oracle")}
	for _, source := range []string{armLocalCallOracle, `TEXT oracle(SB),4,$0-8
	MOVW value+0(FP),R0
	BL 3(PC)
	MOVW R0,ret+4(FP)
	RET
	ADD $3,R0
	B (R14)
`, `TEXT oracle(SB),516,$0-8
	B setup
	ADD $3,R0
	B (R14)
setup:
	MOVW value+0(FP),R0
	MOVW R14,R8
	CALL -4(PC)
	MOVW R8,R14
	MOVW R0,ret+4(FP)
	RET
`} {
		requireARMGoAssemblerResult(t, source, true)
		translateARMCompleteForms(t, source, sigs)
	}
}

func TestARMNamedLocalCallConditionForms(t *testing.T) {
	var assembly strings.Builder
	sigs := make(map[string]FuncSig)
	for index, condition := range []string{"", "AL", "EQ", "NE", "CS", "HS", "CC", "LO", "MI", "PL", "VS", "VC", "HI", "LS", "GE", "LT", "GT", "LE"} {
		op := "BL"
		if condition != "" {
			op += "." + condition
		}
		name := fmt.Sprintf("condition%d", index)
		fmt.Fprintf(&assembly, "TEXT %s(SB),4,$0-8\nMOVW value+0(FP),R0\nCMP $0,R0\n%s 3(PC)\n", name, op)
		assembly.WriteString("MOVW R0,ret+4(FP)\nRET\nADD $3,R0\nB (R14)\n")
		sigs[name] = armLocalCallSignature(name)
	}
	requireARMGoAssemblerResult(t, assembly.String(), true)
	translateARMCompleteForms(t, assembly.String(), sigs)
}

func TestARMNamedLocalCallRejectsUnprovedLinkUse(t *testing.T) {
	for _, body := range []string{
		"MOVW R14, ret+4(FP)\nB (R14)", // Observed code address.
		"ADD $4, R14\nB (R14)",         // Changed continuation.
		"MOVW $1,R14\nB (R14)",         // Native register branch.
		"MOVW R14,R11\nB (R11)",        // Go can use R11 for instruction expansion.
	} {
		source := "TEXT oracle(SB),4,$0-8\nBL helper\nRET\nhelper:\n" + body + "\n"
		requireARMGoAssemblerResult(t, source, true)
		file, err := Parse(ArchARM, source)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{"oracle": armLocalCallSignature("oracle")}})
		if !errors.Is(err, ErrProbeNeedsContext) {
			t.Errorf("%q: expected a link context error, got %v", body, err)
		}
	}
}

func TestCrossLinuxRuntimeMatrixARMNamedLocalCall(t *testing.T) {
	llc := requireARMScalarRuntime(t)
	runARMGoSourceOracle(t, armLocalCallOracle, `package main
import "fmt"
func oracle(value int32) int32
func main() {
	for _, value := range []int32{0, 1, -1, 42, -42} {
		want := value + 3
		if value == 0 { want = 16 }
		if got := oracle(value); got != want { panic(fmt.Sprintf("oracle(%d) = %d, want %d", value, got, want)) }
	}
	fmt.Println("original Go local calls matched")
}
`)
	ir := translateARMCompleteForms(t, armLocalCallOracle, map[string]FuncSig{"oracle": armLocalCallSignature("oracle")})
	const mainC = `
#include <stdint.h>
#include <stdio.h>
extern int32_t oracle(int32_t);
int main(void) {
	int32_t inputs[] = {0, 1, -1, 42, -42};
	for (unsigned i = 0; i < sizeof(inputs)/sizeof(inputs[0]); i++) {
		const int32_t value = inputs[i];
		const int32_t want = value == 0 ? 16 : value + 3;
		const int32_t got = oracle(value);
		if (got == want) continue;
		fprintf(stderr, "oracle(%d) = %d, want %d\n", value, got, want);
		return 1;
	}
	return 0;
}
`
	for _, level := range []int{0, 2} {
		t.Run(fmt.Sprintf("O%d", level), func(t *testing.T) {
			compileAndRunRuntimeTestWithCompiler(t, llc, []string{"arm-linux-gnueabihf-gcc", "-no-pie"},
				"arm_named_local_call", "armv7-unknown-linux-gnueabihf", ir, mainC,
				[]string{"qemu-arm", "-L", "/usr/arm-linux-gnueabihf"}, level)
		})
	}
}
