package plan9asm

import (
	"fmt"
	"strings"
)

func (c *amd64Ctx) lowerSyscall(op Op, ins Instr) (ok bool, terminated bool, err error) {
	source := ins
	if source.Op == "" {
		source.Op = op
	}
	if form, known, err := x86LinuxSyscallProperties(source, c.goarch, c.targetTriple); known {
		if err != nil {
			return true, false, err
		}
		return true, false, c.emitLinuxSyscall(form)
	}
	switch op {
	case "WAIT":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("x86 WAIT expects no operands: %q", ins.Raw)
		}
		c.b.WriteString("  call void asm sideeffect \"wait\", \"~{memory}\"()\n")
		return true, false, nil
	case "HLT":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("x86 HLT expects no operands: %q", ins.Raw)
		}
		c.b.WriteString("  call void asm sideeffect \"hlt\", \"~{memory}\"()\n")
		c.b.WriteString("  unreachable\n")
		return true, true, nil
	case "UD2":
		return c.lowerX86UndefinedTrap(op, ins)
	case "INT":
		if c.goarch == "386" && (len(ins.Args) != 1 || ins.Args[0].Kind != OpImm) {
			return true, false, fmt.Errorf("386 INT expects an immediate vector: %q", ins.Raw)
		}
		// Software interrupt/trap path (e.g. runtime.exitThread INT $3).
		if c.goarch == "386" {
			c.emitX86Trap()
		} else {
			// Preserve the established amd64 lowering. The 386 path needs an
			// actual trap because Windows uses INT $3 as an executable stub.
			c.b.WriteString("  unreachable\n")
		}
		return true, true, nil
	}
	return false, false, nil
}

func (c *amd64Ctx) emitLinuxSyscall(form x86LinuxSyscallForm) error {
	typ := I64
	if form.width == 4 {
		typ = I32
	}
	resultType := string(typ)
	constraints := []string{"={ax}"}
	if form.observesDX {
		resultType = fmt.Sprintf("{ %s, %s }", typ, typ)
		constraints = append(constraints, "={dx}")
	}

	args := make([]string, len(form.inputs))
	for index, register := range form.inputs {
		value, err := c.evalIntSized(Operand{Kind: OpReg, Reg: register}, typ)
		if err != nil {
			return err
		}
		args[index] = string(typ) + " " + value
		switch {
		case register == AX:
			constraints = append(constraints, "0") // AX carries both the number and raw result.
		case register == DX && form.observesDX:
			constraints = append(constraints, "1")
		default:
			constraints = append(constraints, "{"+strings.ToLower(string(register))+"}")
		}
	}
	for _, register := range form.clobbers {
		if register == "" {
			continue
		}
		name := strings.ToLower(string(register))
		if register == CX {
			name = "rcx"
		}
		constraints = append(constraints, "~{"+name+"}")
	}
	constraints = append(constraints, "~{dirflag}", "~{fpsr}", "~{flags}", "~{memory}")
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q(%s)\n", result, resultType,
		form.instruction, strings.Join(constraints, ","), strings.Join(args, ", "))
	if !form.observesDX {
		return c.storeRegSized(AX, typ, "%"+result)
	}
	for index, register := range [...]Reg{AX, DX} {
		word := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractvalue %s %%%s, %d\n", word, resultType, result, index)
		if err := c.storeRegSized(register, typ, "%"+word); err != nil {
			return err
		}
	}
	return nil
}

func (c *amd64Ctx) emitX86Trap() {
	c.b.WriteString("  call void asm sideeffect \"int3\", \"~{memory}\"()\n")
	c.b.WriteString("  unreachable\n")
}
