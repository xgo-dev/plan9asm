package plan9asm

import (
	"fmt"
	"strings"
)

// arm64CarryForm is the common Go register grammar for add/subtract and
// negate-with-carry. It validates syntax only, never supplying incoming flags.
type arm64CarryForm struct {
	word, subtract, setFlags, negate bool
	left, destination                Operand
}

func parseARM64CarryForm(op Op, ins Instr) (form arm64CarryForm, handled bool, err error) {
	switch op {
	case "ADC", "ADCW", "ADCS", "ADCSW":
	case "SBC", "SBCW", "SBCS", "SBCSW":
		form.subtract = true
	case "NGC", "NGCW", "NGCS", "NGCSW":
		form.negate = true
	default:
		return form, false, nil
	}
	form.word = op == "ADCW" || op == "ADCSW" || op == "SBCW" || op == "SBCSW" || op == "NGCW" || op == "NGCSW"
	form.setFlags = op == "ADCS" || op == "ADCSW" || op == "SBCS" || op == "SBCSW" || op == "NGCS" || op == "NGCSW"
	if strings.ToUpper(string(ins.Op)) != string(op) {
		return form, true, fmt.Errorf("arm64 %s does not accept an instruction suffix: %q", op, ins.Raw)
	}
	if form.negate {
		if len(ins.Args) != 2 || !arm64AddSubCarryRegisterOrZero(ins.Args[0], false) ||
			!arm64AddSubCarryRegisterOrZero(ins.Args[1], false) {
			return form, true, fmt.Errorf("arm64 %s expects C_ZREG source and destination: %q", op, ins.Raw)
		}
		form.destination = ins.Args[1]
		return form, true, nil
	}
	if len(ins.Args) != 2 && len(ins.Args) != 3 {
		return form, true, fmt.Errorf("arm64 %s expects 2 or 3 operands: %q", op, ins.Raw)
	}
	if !arm64AddSubCarryRegisterOrZero(ins.Args[0], true) {
		return form, true, fmt.Errorf("arm64 %s first operand must be a general register or zero: %q", op, ins.Raw)
	}
	form.destination = ins.Args[len(ins.Args)-1]
	if !arm64AddSubCarryRegisterOrZero(form.destination, false) {
		return form, true, fmt.Errorf("arm64 %s destination must be a general register: %q", op, ins.Raw)
	}
	form.left = form.destination
	if len(ins.Args) == 3 {
		form.left = ins.Args[1]
		if !arm64AddSubCarryRegisterOrZero(form.left, false) {
			return form, true, fmt.Errorf("arm64 %s second operand must be a general register: %q", op, ins.Raw)
		}
	}
	return form, true, nil
}
