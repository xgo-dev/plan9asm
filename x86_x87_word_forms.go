package plan9asm

import (
	"fmt"
	"strings"
)

type x86X87WordKind uint8

const (
	x86X87Initialize x86X87WordKind = iota
	x86X87Clear
	x86X87StoreControl
	x86X87StoreStatus
	x86X87LoadControl
)

// These are the complete Go init/clear/m16-word rows, not Intel's spelling
// aliases or an environment/rounding/trapping permission. Go FINIT and FCLEX
// themselves encode the no-wait DB E3 and DB E2 forms; WAIT is separate.
var x86X87WordSpecs = map[Op]x86X87WordKind{
	"FINIT": x86X87Initialize,
	"FCLEX": x86X87Clear,
	"FSTCW": x86X87StoreControl,
	"FSTSW": x86X87StoreStatus,
	"FLDCW": x86X87LoadControl,
}

type x86X87WordForm struct {
	kind    x86X87WordKind
	operand Operand
}

func x86X87WordProperties(ins Instr, arch string) (x86X87WordForm, bool, error) {
	name, _, dotted := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	kind, known := x86X87WordSpecs[Op(name)]
	if !known {
		return x86X87WordForm{}, false, nil
	}
	form := x86X87WordForm{kind: kind}
	fail := func(reason string) (x86X87WordForm, bool, error) {
		return form, true, fmt.Errorf("%s %s %s: %q", arch, ins.Op, reason, ins.Raw)
	}
	if arch != "386" && arch != "amd64" || dotted {
		return fail("requires its actual x86 mode and unsuffixed Go row")
	}
	if kind == x86X87Initialize || kind == x86X87Clear {
		if len(ins.Args) != 0 {
			return fail("takes no operands")
		}
		return form, true, nil
	}
	if len(ins.Args) == 1 {
		form.operand = ins.Args[0]
		if err := x86NamedMultiplyMemoryError(form.operand, arch); err != nil {
			return fail(err.Error()) // Ym address grammar only, no numerical MUL role.
		}
		memory := isX87MemoryOperand(form.operand)
		if form.operand.Kind == OpSym {
			symbol := strings.TrimSpace(form.operand.Sym)
			_, integer := parseInt(symbol)
			memory = !strings.HasPrefix(symbol, "$") && (strings.HasSuffix(symbol, "(SB)") || integer == nil)
		}
		if memory || kind == x86X87StoreStatus && form.operand.Kind == OpReg && form.operand.Reg == AX {
			return form, true, nil
		}
	}
	switch kind {
	case x86X87LoadControl:
		return fail("expects memory source")
	case x86X87StoreStatus:
		return fail("expects memory destination or AX")
	default:
		return fail("expects memory destination")
	}
}
