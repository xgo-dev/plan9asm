package plan9asm

import (
	"fmt"
	"strings"
)

type arm64DivideRemainderForm struct {
	divisor, dividend, destination Operand
	word, signed, remainder        bool
}

// Go's two C_ZREG rows cover the eight W/X signed/unsigned forms. REM is
// expanded to DIV -> R27 then MSUB, not a hardware remainder operation.
func parseARM64DivideRemainderForm(op Op, ins Instr) (form arm64DivideRemainderForm, handled bool, err error) {
	switch op {
	case "SDIV", "SDIVW", "UDIV", "UDIVW", "REM", "REMW", "UREM", "UREMW":
	default:
		return form, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 && len(ins.Args) != 3 {
		return form, true, fmt.Errorf("arm64 %s expects two or three unsuffixed general registers: %q", op, ins.Raw)
	}
	for _, operand := range ins.Args {
		if operand.Kind != OpReg || !isARM64GeneralOrZeroReg(operand.Reg) {
			return form, true, fmt.Errorf("arm64 %s expects only general registers or ZR: %q", op, ins.Raw)
		}
	}
	form.divisor, form.dividend, form.destination = ins.Args[0], ins.Args[1], ins.Args[len(ins.Args)-1]
	form.word = strings.HasSuffix(string(op), "W")
	form.signed = strings.HasPrefix(string(op), "S") || strings.HasPrefix(string(op), "REM")
	form.remainder = strings.Contains(string(op), "REM")
	return form, true, nil
}
