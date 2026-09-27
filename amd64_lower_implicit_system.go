package plan9asm

import (
	"fmt"
	"strings"
)

type amd64ImplicitSystemOperand uint8

const (
	amd64ImplicitSystemNoOperand amd64ImplicitSystemOperand = iota
	amd64ImplicitSystemGP
)

type amd64ImplicitRegisterSet uint8

const (
	amd64ImplicitAX amd64ImplicitRegisterSet = 1 << iota
	amd64ImplicitCX
	amd64ImplicitDX
)

type amd64ImplicitSystemSpec struct {
	operand     amd64ImplicitSystemOperand
	inputs      amd64ImplicitRegisterSet
	outputs     amd64ImplicitRegisterSet
	writesCarry bool
}

// amd64ImplicitSystemSpecs is the complete Go 1.27 grammar for the system
// instructions whose architectural state is carried by implicit AX/CX/DX
// registers, plus the WAITPKG instructions' one explicit Yrl register. The
// table separates operand syntax from data flow so parsing, register liveness,
// and emission all consume the same typed description.
var amd64ImplicitSystemSpecs = map[Op]amd64ImplicitSystemSpec{
	"MONITOR":  {inputs: amd64ImplicitAX | amd64ImplicitCX | amd64ImplicitDX},
	"MWAIT":    {inputs: amd64ImplicitAX | amd64ImplicitCX},
	"RDPMC":    {inputs: amd64ImplicitCX, outputs: amd64ImplicitAX | amd64ImplicitDX},
	"RDPKRU":   {inputs: amd64ImplicitCX, outputs: amd64ImplicitAX | amd64ImplicitDX},
	"WRPKRU":   {inputs: amd64ImplicitAX | amd64ImplicitCX | amd64ImplicitDX},
	"XSETBV":   {inputs: amd64ImplicitAX | amd64ImplicitCX | amd64ImplicitDX},
	"UMONITOR": {operand: amd64ImplicitSystemGP},
	"UMWAIT":   {operand: amd64ImplicitSystemGP, inputs: amd64ImplicitAX | amd64ImplicitDX, writesCarry: true},
	"TPAUSE":   {operand: amd64ImplicitSystemGP, inputs: amd64ImplicitAX | amd64ImplicitDX, writesCarry: true},
}

type amd64ImplicitSystemForm struct {
	register Reg
}

func (c *amd64Ctx) lowerImplicitSystem(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	spec, recognized := amd64ImplicitSystemSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("%s %s does not accept instruction suffixes: %q", c.goarch, baseOp, ins.Raw)
	}
	form, err := c.parseImplicitSystemForm(baseOp, spec, ins)
	if err != nil {
		return true, false, err
	}
	return c.emitImplicitSystem(baseOp, spec, form)
}

func (c *amd64Ctx) parseImplicitSystemForm(op string, spec amd64ImplicitSystemSpec, ins Instr) (amd64ImplicitSystemForm, error) {
	var form amd64ImplicitSystemForm
	switch spec.operand {
	case amd64ImplicitSystemNoOperand:
		if len(ins.Args) != 0 {
			return form, fmt.Errorf("%s %s takes no operands: %q", c.goarch, op, ins.Raw)
		}
	case amd64ImplicitSystemGP:
		if len(ins.Args) != 1 || ins.Args[0].Kind != OpReg || !isX86YrlRegisterForArch(ins.Args[0].Reg, c.goarch) {
			return form, fmt.Errorf("%s %s expects one Go 1.27 Yrl register: %q", c.goarch, op, ins.Raw)
		}
		form.register = ins.Args[0].Reg
	default:
		panic("unknown amd64 implicit-system operand kind")
	}
	return form, nil
}

func (c *amd64Ctx) emitImplicitSystem(op string, spec amd64ImplicitSystemSpec, form amd64ImplicitSystemForm) (bool, bool, error) {
	wordType := I64
	if c.goarch == "386" {
		wordType = I32
	}
	constraints := make([]string, 0, 8)
	arguments := make([]string, 0, 4)
	if spec.outputs == amd64ImplicitAX|amd64ImplicitDX {
		constraints = append(constraints, "={ax}", "={dx}")
	}
	if spec.writesCarry {
		constraints = append(constraints, "=q")
	}
	if spec.operand == amd64ImplicitSystemGP {
		value, err := c.evalIntSized(Operand{Kind: OpReg, Reg: form.register}, wordType)
		if err != nil {
			return true, false, err
		}
		constraints = append(constraints, "r")
		arguments = append(arguments, fmt.Sprintf("%s %s", wordType, value))
	}
	for _, implicit := range []struct {
		bit        amd64ImplicitRegisterSet
		reg        Reg
		constraint string
	}{
		{bit: amd64ImplicitAX, reg: AX, constraint: "{ax}"},
		{bit: amd64ImplicitCX, reg: CX, constraint: "{cx}"},
		{bit: amd64ImplicitDX, reg: DX, constraint: "{dx}"},
	} {
		if spec.inputs&implicit.bit == 0 {
			continue
		}
		value, err := c.evalIntSized(Operand{Kind: OpReg, Reg: implicit.reg}, I32)
		if err != nil {
			return true, false, err
		}
		constraints = append(constraints, implicit.constraint)
		arguments = append(arguments, "i32 "+value)
	}
	constraints = append(constraints, "~{memory}", "~{dirflag}", "~{fpsr}", "~{flags}")

	assembly := strings.ToLower(op)
	if spec.operand == amd64ImplicitSystemGP {
		operandIndex := 0
		if spec.writesCarry {
			operandIndex = 1
		}
		assembly += fmt.Sprintf(" $%d", operandIndex)
	}
	if spec.writesCarry {
		assembly += "; setc $0"
		call := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i8 asm sideeffect %q, %q(%s)\n",
			call, assembly, strings.Join(constraints, ","), strings.Join(arguments, ", "))
		carry := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i8 %%%s to i1\n", carry, call)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", carry, c.flagsCFSlot)
		return true, false, nil
	}
	if spec.outputs == amd64ImplicitAX|amd64ImplicitDX {
		call := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call { i32, i32 } asm sideeffect %q, %q(%s)\n",
			call, assembly, strings.Join(constraints, ","), strings.Join(arguments, ", "))
		for index, reg := range []Reg{AX, DX} {
			part := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractvalue { i32, i32 } %%%s, %d\n", part, call, index)
			if err := c.storeRegSized(reg, I32, "%"+part); err != nil {
				return true, false, err
			}
		}
		return true, false, nil
	}
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(%s)\n",
		assembly, strings.Join(constraints, ","), strings.Join(arguments, ", "))
	return true, false, nil
}
