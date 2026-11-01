package plan9asm

import (
	"fmt"
	"strings"
)

type amd64SystemTransferKind uint8

const (
	amd64SystemEnter amd64SystemTransferKind = iota
	amd64SystemExit
	amd64SystemReturn
)

type amd64SystemTransferInputs uint8

const (
	amd64SystemTransferCX amd64SystemTransferInputs = 1 << iota
	amd64SystemTransferDX
	amd64SystemTransferR11
)

type amd64SystemTransferSpec struct {
	kind   amd64SystemTransferKind
	mode64 bool
	inputs amd64SystemTransferInputs
}

// amd64SystemTransferSpecs is the complete Go 1.27 SYSENTER/SYSEXIT/SYSRET
// grammar. SYSCALL is intentionally separate because plan9asm provides a
// hosted libc-backed syscall implementation for it. These raw architectural
// transfers retain exact Go bytes and explicitly materialize the GP registers
// consumed by their exit/return conventions.
var amd64SystemTransferSpecs = map[Op]amd64SystemTransferSpec{
	"SYSENTER":   {kind: amd64SystemEnter},
	"SYSENTER64": {kind: amd64SystemEnter, mode64: true},
	"SYSEXIT":    {kind: amd64SystemExit, inputs: amd64SystemTransferCX | amd64SystemTransferDX},
	"SYSEXIT64":  {kind: amd64SystemExit, mode64: true, inputs: amd64SystemTransferCX | amd64SystemTransferDX},
	"SYSRET":     {kind: amd64SystemReturn, inputs: amd64SystemTransferCX | amd64SystemTransferR11},
}

func (spec amd64SystemTransferSpec) terminates() bool {
	return spec.kind != amd64SystemEnter
}

func (spec amd64SystemTransferSpec) encoding() string {
	var opcode byte
	switch spec.kind {
	case amd64SystemEnter:
		opcode = 0x34
	case amd64SystemExit:
		opcode = 0x35
	case amd64SystemReturn:
		opcode = 0x07
	default:
		panic("unknown amd64 system-transfer kind")
	}
	if spec.mode64 {
		return fmt.Sprintf(".byte 0x48, 0x0f, 0x%02x", opcode)
	}
	return fmt.Sprintf(".byte 0x0f, 0x%02x", opcode)
}

func (c *amd64Ctx) lowerSystemTransfer(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	spec, recognized := amd64SystemTransferSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("%s %s does not accept instruction suffixes: %q", c.goarch, baseOp, ins.Raw)
	}
	if c.goarch == "386" && spec.mode64 {
		return true, false, fmt.Errorf("386 %s is absent from Go 1.27's 32-bit encoding table: %q", baseOp, ins.Raw)
	}
	if len(ins.Args) != 0 {
		return true, false, fmt.Errorf("%s %s takes no operands: %q", c.goarch, baseOp, ins.Raw)
	}
	constraints := make([]string, 0, 7)
	arguments := make([]string, 0, 3)
	for _, input := range []struct {
		bit        amd64SystemTransferInputs
		reg        Reg
		constraint string
	}{
		{bit: amd64SystemTransferCX, reg: CX, constraint: "{cx}"},
		{bit: amd64SystemTransferDX, reg: DX, constraint: "{dx}"},
		{bit: amd64SystemTransferR11, reg: Reg("R11"), constraint: "{r11}"},
	} {
		if spec.inputs&input.bit == 0 || (c.goarch == "386" && input.bit == amd64SystemTransferR11) {
			continue
		}
		typ := I32
		if spec.mode64 || spec.kind == amd64SystemReturn {
			typ = I64
		}
		value, err := c.evalIntSized(Operand{Kind: OpReg, Reg: input.reg}, typ)
		if err != nil {
			return true, false, err
		}
		constraints = append(constraints, input.constraint)
		arguments = append(arguments, fmt.Sprintf("%s %s", typ, value))
	}
	constraints = append(constraints, "~{memory}", "~{dirflag}", "~{fpsr}", "~{flags}")
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(%s)\n",
		spec.encoding(), strings.Join(constraints, ","), strings.Join(arguments, ", "))
	if !spec.terminates() {
		return true, false, nil
	}
	c.b.WriteString("  unreachable\n")
	return true, true, nil
}
