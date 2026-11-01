package plan9asm

import (
	"reflect"
	"strings"
	"testing"
)

func TestX86ExtensionHelperAcceptsMatchingCaseAndEmptyIdentity(t *testing.T) {
	for _, operation := range x86ExtensionTestOperations {
		for _, identity := range []string{"", operation, strings.ToLower(operation), "Mov" + strings.ToLower(operation[3:])} {
			for _, dispatch := range []Op{Op(operation), Op(strings.ToLower(operation))} {
				instruction := Instr{Op: Op(identity), Raw: operation + " AX,BX", Args: []Operand{
					{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: BX},
				}}
				before := append([]Operand(nil), instruction.Args...)
				form, recognized, err := x86ScalarExtensionProperties(dispatch, instruction, "amd64")
				if !recognized || err != nil || form.result != BX || !reflect.DeepEqual(before, instruction.Args) || instruction.Op != Op(identity) {
					t.Fatalf("%s identity %q: form=%+v recognized=%t err=%v", operation, identity, form, recognized, err)
				}
				ctx, _ := newAMD64CtxWithFuncForTest(t, Func{Instrs: []Instr{instruction}}, FuncSig{Ret: Void}, nil)
				if err := ctx.lowerScalarExtensionMove(dispatch, instruction); err != nil {
					t.Fatalf("matching dispatch %s / %q: %v", operation, identity, err)
				}
			}
		}
	}
}

func TestX86ExtensionHelperRejectsUnknownOrConflictingDispatchBeforeIR(t *testing.T) {
	for _, operation := range []Op{"MOVLQSX", "UNKNOWN_EXTENSION", "MOVQ"} {
		instruction := Instr{Op: "MOVWQSX", Raw: "MOVWQSX AX,BX", Args: []Operand{
			{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: BX},
		}}
		before := append([]Operand(nil), instruction.Args...)
		ctx, output := newAMD64CtxWithFuncForTest(t, Func{Instrs: []Instr{instruction}}, FuncSig{Ret: Void}, nil)
		length := output.Len()
		if err := ctx.lowerScalarExtensionMove(operation, instruction); err == nil || output.Len() != length || !reflect.DeepEqual(before, instruction.Args) {
			t.Fatalf("dispatch %s: err=%v emitted=%d mutated=%t", operation, err, output.Len()-length, !reflect.DeepEqual(before, instruction.Args))
		}
	}
}
