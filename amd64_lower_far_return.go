package plan9asm

import (
	"fmt"
	"strings"
)

type amd64FarReturnKind uint8

const (
	amd64InterruptReturn amd64FarReturnKind = iota
	amd64FarReturn
)

type amd64FarReturnSpec struct {
	kind           amd64FarReturnKind
	bits           int
	allowImmediate bool
}

// amd64FarReturnSpecs is the complete Go 1.27 interrupt/far-return grammar.
// Every RETF width accepts both the operand-free CB encoding and Go's Yi32
// immediate row, whose value is truncated to the architectural imm16. Q-width
// rows are absent from the 386 encoder even though W/L rows are shared.
var amd64FarReturnSpecs = map[Op]amd64FarReturnSpec{
	"IRETW": {kind: amd64InterruptReturn, bits: 16},
	"IRETL": {kind: amd64InterruptReturn, bits: 32},
	"IRETQ": {kind: amd64InterruptReturn, bits: 64},
	"RETFW": {kind: amd64FarReturn, bits: 16, allowImmediate: true},
	"RETFL": {kind: amd64FarReturn, bits: 32, allowImmediate: true},
	"RETFQ": {kind: amd64FarReturn, bits: 64, allowImmediate: true},
}

type amd64FarReturnForm struct {
	hasImmediate bool
	immediate    uint16
}

func (c *amd64Ctx) lowerFarReturn(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	spec, recognized := amd64FarReturnSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("%s %s does not accept instruction suffixes: %q", c.goarch, baseOp, ins.Raw)
	}
	if c.goarch == "386" && spec.bits == 64 {
		return true, false, fmt.Errorf("386 %s is absent from Go 1.27's 32-bit encoding table: %q", baseOp, ins.Raw)
	}
	form, err := c.parseFarReturnForm(baseOp, spec, ins)
	if err != nil {
		return true, false, err
	}
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q()\n",
		spec.encoding(form), "~{memory},~{dirflag},~{fpsr},~{flags}")
	c.b.WriteString("  unreachable\n")
	return true, true, nil
}

func (c *amd64Ctx) parseFarReturnForm(op string, spec amd64FarReturnSpec, ins Instr) (amd64FarReturnForm, error) {
	var form amd64FarReturnForm
	if len(ins.Args) == 0 {
		return form, nil
	}
	if !spec.allowImmediate || len(ins.Args) != 1 || ins.Args[0].Kind != OpImm {
		return form, fmt.Errorf("%s %s expects no operands or one Go 1.27 Yi32 immediate: %q", c.goarch, op, ins.Raw)
	}
	value := ins.Args[0].Imm
	if c.goarch != "386" && (value < -2147483648 || value > 4294967295) {
		return form, fmt.Errorf("amd64 %s immediate is outside Go 1.27's Yi32 class: %q", op, ins.Raw)
	}
	form.hasImmediate = true
	form.immediate = uint16(value)
	return form, nil
}

func (spec amd64FarReturnSpec) encoding(form amd64FarReturnForm) string {
	bytes := make([]byte, 0, 4)
	switch spec.bits {
	case 16:
		bytes = append(bytes, 0x66)
	case 32:
	case 64:
		bytes = append(bytes, 0x48)
	default:
		panic("unknown amd64 far-return width")
	}
	if spec.kind == amd64InterruptReturn {
		bytes = append(bytes, 0xcf)
	} else if form.hasImmediate {
		bytes = append(bytes, 0xca, byte(form.immediate), byte(form.immediate>>8))
	} else {
		bytes = append(bytes, 0xcb)
	}
	parts := make([]string, len(bytes))
	for index, value := range bytes {
		parts[index] = fmt.Sprintf("0x%02x", value)
	}
	return ".byte " + strings.Join(parts, ", ")
}
