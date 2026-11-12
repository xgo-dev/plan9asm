package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

const fixedLocalLayoutPingPong = `
LEAQ 16(SP),R14
LEAQ 24(SP),R15
MOVQ $1,(R14)
loop:
CMPQ CX,$0
JEQ done
MOVQ (R14),AX
ADDQ $1,AX
MOVQ AX,(R15)
XCHGQ R14,R15
SUBQ $1,CX
JMP loop
done:
MOVQ (R14),AX
MOVQ AX,ret+16(FP)
RET
`

const fixedLocalLayoutDeadReturn = `
MOVQ $7,ret+16(FP)
CMPQ CX,$0
JEQ done
LEAQ 16(SP),AX
done:
RET
`

func fixedLocalTerminalReturnBodies() []string {
	return []string{fixedLocalLayoutDeadReturn, strings.Replace(fixedLocalLayoutDeadReturn,
		"LEAQ 16(SP),AX", "LEAQ 24(SP),AX\nMOVQ AX,16(SP)", 1)}
}

func TestGoAMD64FixedLocalTerminalJoinPrograms(t *testing.T) {
	rows := []struct {
		name, body string
		accept     bool
	}{
		{"dead private register at return", fixedLocalTerminalReturnBodies()[0], true},
		{"dead private spill at return", fixedLocalTerminalReturnBodies()[1], true},
		{"undefined joined register is used", strings.Replace(fixedLocalLayoutDeadReturn,
			"done:\nRET", "done:\nMOVQ (AX),BX\nRET", 1), false},
		{"result is missing", strings.Replace(fixedLocalLayoutDeadReturn,
			"MOVQ $7,ret+16(FP)\n", "", 1), false},
		{"only one predecessor writes the result", `
CMPQ CX,$0
JEQ missing
MOVQ $7,ret+16(FP)
JMP done
missing:
NOP
done:
RET
`, false},
		{"private SP is not restored", strings.Replace(fixedLocalLayoutDeadReturn,
			"LEAQ 16(SP),AX", "LEAQ 8(SP),AX\nMOVQ AX,SP", 1), false},
		{"private and native roles conflict", `
CMPQ CX,$0
JEQ native
LEAQ 16(SP),AX
MOVQ $1,(AX)
JMP joined
native:
MOVQ p+0(FP),AX
joined:
MOVQ (AX),BX
MOVQ BX,ret+16(FP)
RET
`, false},
		{"initial buffer is undefined", strings.Replace(fixedLocalLayoutPingPong,
			"MOVQ $1,(R14)\n", "", 1), false},
		{"next buffer is not written", strings.Replace(fixedLocalLayoutPingPong,
			"MOVQ AX,(R15)\n", "", 1), false},
	}
	functions := make([]Func, len(rows))
	signatures := make([]FuncSig, len(rows))
	var original strings.Builder
	for index, row := range rows {
		_, _, sig, source := x86ResultInitializationFixture(t, "amd64",
			"func Value(p *uint64, n uint64) uint64", "MOVQ n+8(FP),CX\n"+row.body)
		source = strings.Replace(source, "$0-24", "$64-24", 1)
		file, err := Parse(ArchAMD64, source)
		if err != nil || len(file.Funcs) != 1 || file.Funcs[0].FrameSize != 64 {
			t.Fatal("complete source fixture has no expected private frame", err)
		}
		functions[index], signatures[index] = file.Funcs[0], sig
		original.WriteString(strings.Replace(source, "·Value", fmt.Sprintf("·Value%d", index), 1))
	}
	// All complete source functions must assemble before their distinct
	// translation outcomes are checked. Source legality is not a memory proof.
	goAssemblerOracleOutput(t, "amd64", original.String(), "", true)
	for index, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			_, err := proveX86FixedLocal(functions[index], signatures[index])
			if row.accept && err != nil {
				t.Fatal("complete initialized source lost a valid private layout", err)
			}
			if !row.accept && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("unproved source gained a private frame", err)
			}
		})
	}
}

func fixedLocalTerminalReturnProgram() (assembly, declarations string) {
	var asm, decl strings.Builder
	for index, body := range fixedLocalTerminalReturnBodies() {
		body = strings.ReplaceAll(body, "ret+16(FP)", "ret+8(FP)")
		fmt.Fprintf(&asm, "TEXT ·Value%d(SB),4,$64-16\nMOVQ a+0(FP),CX\n%s", index, body)
		fmt.Fprintf(&decl, "func Value%d(a uint64) uint64\n", index)
	}
	return asm.String(), decl.String()
}

func TestGoAMD64FixedLocalTerminalJoinObjects(t *testing.T) {
	assembly, declarations := fixedLocalTerminalReturnProgram()
	fixedLocalCompleteVectorObjects(t, assembly, declarations, 2)
}
