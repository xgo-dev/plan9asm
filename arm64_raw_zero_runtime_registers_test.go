package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// Return-state restoration is sufficient for the separate object proof,
// but an asynchronous Go runtime observer can see a temporary g/OS18 write.
// The fixture actually executed by Go therefore never writes either register.
func arm64RawZeroRuntimeRegisterSafety(source string) error {
	file, err := Parse(ArchARM64, source)
	if err != nil {
		return err
	}
	if len(file.Funcs) != 1 {
		return fmt.Errorf("runtime fixture must contain one function")
	}
	const reserved = uint32(1<<18 | 1<<28)
	for _, ins := range file.Funcs[0].Instrs {
		switch ins.Op {
		case OpTEXT:
		case "MOVD":
			if len(ins.Args) != 2 {
				return fmt.Errorf("unknown fixture MOVD: %s", ins.Raw)
			}
			destination := ins.Args[1]
			if destination.Kind == OpReg && (destination.Reg == "R18" || destination.Reg == "R28" || destination.Reg == "g") {
				return fmt.Errorf("runtime fixture writes reserved register: %s", ins.Raw)
			}
		case OpWORD:
			if len(ins.Args) != 1 || ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" || ins.Args[0].ImmIsFloat {
				return fmt.Errorf("unresolved fixture WORD: %s", ins.Raw)
			}
			word := uint32(ins.Args[0].Imm)
			// Direct BL writes LR; exact RET reads LR. Neither writes g/OS18.
			if word&0xfc000000 == 0x94000000 || word == 0xd65f03c0 {
				continue
			}
			writes, known := arm64RawPoolGPWrites(word)
			if !known {
				return fmt.Errorf("unknown fixture WORD effects: %s", ins.Raw)
			}
			if writes&reserved != 0 {
				return fmt.Errorf("runtime fixture writes reserved register: %s", ins.Raw)
			}
		default:
			return fmt.Errorf("unknown runtime fixture instruction: %s", ins.Raw)
		}
	}
	return nil
}

func TestARM64RawZeroRepeatedRuntimeKeepsReservedRegisters(t *testing.T) {
	source := arm64RawZeroRepeatedNumericSource(t)
	if err := arm64RawZeroRuntimeRegisterSafety(source); err != nil {
		t.Fatal(err)
	}
	// Keep the guard tied to decoded effects, including the restore load,
	// rather than just detecting the old ADD spelling or eventual identity.
	words := assembleARM64LLVMWords(t, []string{
		"add x28,sp,#0", "add x18,sp,#0", "ldp x28,x18,[sp],#16",
	}, "")
	for _, word := range words {
		broken := strings.Replace(source, "MOVD (R0),R4", fmt.Sprintf("WORD $%#08x\nMOVD (R0),R4", word), 1)
		if err := arm64RawZeroRuntimeRegisterSafety(broken); err == nil {
			t.Fatalf("reserved-register WORD %#08x passed runtime safety", word)
		}
	}
	for _, instruction := range []string{"MOVD R0,g", "MOVD R0,R18", "WORD $0xffffffff"} {
		broken := strings.Replace(source, "MOVD (R0),R4", instruction+"\nMOVD (R0),R4", 1)
		if err := arm64RawZeroRuntimeRegisterSafety(broken); err == nil {
			t.Fatalf("unsafe/unknown fixture instruction passed: %s", instruction)
		}
	}
}
