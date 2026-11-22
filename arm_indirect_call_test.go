package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

func TestARMIndirectCallOriginalRegisterForms(t *testing.T) {
	const start = "TEXT invoke(SB),4,$4-8\nMOVW value+0(FP),R4\nCMP $0,R4\n"
	const finish = "\nMOVW $19,R0\nORR.EQ $256,R0\nMOVW R0,ret+4(FP)\nRET\n"
	for _, call := range []string{
		"BL (R4)", "CALL 0(R4)", "BL R3,(R4)", "CALL.EQ R3,(R4)", "BL (R4)(R5*2)",
	} {
		t.Run(call, func(t *testing.T) {
			source := start + call + finish
			requireARMGoAssemblerResult(t, source, true)
			ir := translateARMCompleteForms(t, source, map[string]FuncSig{"invoke": armLocalCallSignature("invoke")})
			if !strings.Contains(ir, "blx ") || !strings.Contains(ir, "~{lr}") {
				t.Fatal("native indirect call lacks the physical link-register clobber")
			}
			if strings.Contains(ir, "load i32, ptr %reg_R5") || strings.Contains(ir, "load i32, ptr %reg_R3") {
				t.Fatal("ignored Go BL register annotations supplied the native target")
			}
		})
	}
}

func TestARMIndirectCallRejectsNonzeroDisplacement(t *testing.T) {
	const body = "MOVW $3,R4\nBL 4(R4)"
	source := "TEXT invoke(SB),4,$4-0\n" + body + "\nRET\n"
	requireARMGoAssemblerResult(t, source, false)
	rejectARMFormsOutsideGo127Optabs(t, []string{body})
}

func TestARMConditionalIndirectCallDoesNotSupplyFlagsOnItsSkipPath(t *testing.T) {
	const source = `TEXT invoke(SB),4,$4-8
 MOVW value+0(FP),R4
 TST R4,R4
 CALL.EQ R3,(R4)
 MOVW CPSR,R0
 MOVW R0,ret+4(FP)
 RET
`
	requireARMGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Translate(file, Options{
		Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf",
		Sigs: map[string]FuncSig{"invoke": armLocalCallSignature("invoke")},
	})
	if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "needs source-defined NZCV on every path") {
		t.Fatalf("conditional native call granted CPSR knowledge on the skip path: %v", err)
	}
}
