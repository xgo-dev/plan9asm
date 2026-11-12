package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
)

// lowerMachineRegisterMove covers the complete machine-state-register portion
// of Go 1.27's x86 ymovtab: CR, DR, and TR registers plus the descriptor-state
// aliases GDTR, IDTR, LDTR, MSW, and TASK. Segment and TLS moves are a separate
// family.
func (c *amd64Ctx) lowerMachineRegisterMove(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	if baseOp != "MOVW" && baseOp != "MOVL" && baseOp != "MOVQ" {
		return false, false, nil
	}
	if len(ins.Args) != 2 {
		return false, false, nil
	}
	sourceClass, sourceIndex, sourceSpecial := x86MachineRegisterOperand(ins.Args[0])
	destinationClass, destinationIndex, destinationSpecial := x86MachineRegisterOperand(ins.Args[1])
	if !sourceSpecial && !destinationSpecial {
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("%s machine-register %s does not accept instruction suffixes: %q", c.goarch, baseOp, ins.Raw)
	}
	if sourceSpecial == destinationSpecial {
		return true, false, fmt.Errorf("%s %s machine-register form expects exactly one special register: %q", c.goarch, baseOp, ins.Raw)
	}

	specialClass, specialIndex := sourceClass, sourceIndex
	other := ins.Args[1]
	readSpecial := sourceSpecial
	if destinationSpecial {
		specialClass, specialIndex = destinationClass, destinationIndex
		other = ins.Args[0]
	}

	switch specialClass {
	case "cr":
		return true, false, c.lowerControlDebugRegisterMove(baseOp, "cr", specialIndex, other, readSpecial, ins)
	case "dr":
		return true, false, c.lowerControlDebugRegisterMove(baseOp, "dr", specialIndex, other, readSpecial, ins)
	case "tr":
		return true, false, c.lowerTestRegisterMove(baseOp, specialIndex, other, readSpecial, ins)
	case "gdtr", "idtr", "ldtr", "msw", "task":
		return true, false, c.lowerDescriptorRegisterAlias(baseOp, specialClass, other, readSpecial, ins)
	default:
		panic("machine-register classifier drift")
	}
}

func x86MachineRegisterOperand(operand Operand) (class string, index int, ok bool) {
	if operand.Kind != OpReg {
		return "", 0, false
	}
	return x86MachineRegister(operand.Reg)
}

func x86MachineRegister(reg Reg) (class string, index int, ok bool) {
	name := strings.ToUpper(string(reg))
	switch name {
	case "GDTR", "IDTR", "LDTR", "MSW", "TASK":
		return strings.ToLower(name), 0, true
	}
	if len(name) < 3 {
		return "", 0, false
	}
	prefix := strings.ToLower(name[:2])
	if prefix != "cr" && prefix != "dr" && prefix != "tr" {
		return "", 0, false
	}
	index, err := strconv.Atoi(name[2:])
	if err != nil {
		return "", 0, false
	}
	return prefix, index, true
}

func (c *amd64Ctx) lowerControlDebugRegisterMove(op, class string, index int, other Operand, readSpecial bool, ins Instr) error {
	if op != "MOVL" && op != "MOVQ" {
		return fmt.Errorf("%s %s %s register form is absent from Go 1.27's ymovtab: %q", c.goarch, op, strings.ToUpper(class), ins.Raw)
	}
	allowed := false
	switch class {
	case "cr":
		allowed = index == 0 || index == 2 || index == 3 || index == 4 || index == 8
		if index == 8 && c.goarch == "386" {
			allowed = false
		}
	case "dr":
		if op == "MOVL" {
			allowed = index == 0 || index == 6 || index == 7
		} else {
			allowed = index == 0 || index == 2 || index == 3 || index == 6 || index == 7
		}
	}
	if !allowed {
		return fmt.Errorf("%s %s %s%d form is absent from Go 1.27's ymovtab: %q", c.goarch, op, strings.ToUpper(class), index, ins.Raw)
	}
	if other.Kind != OpReg || !isX86YrlRegisterForArch(other.Reg, c.goarch) {
		return fmt.Errorf("%s %s %s%d expects a Go 1.27 Yrl GP register: %q", c.goarch, op, strings.ToUpper(class), index, ins.Raw)
	}

	special := fmt.Sprintf("%%%s%d", class, index)
	hardwareType := I64
	if c.goarch == "386" {
		hardwareType = I32
	}
	constraints := "~{memory},~{dirflag},~{fpsr},~{flags}"
	if readSpecial {
		call := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q()\n",
			call, hardwareType, "mov "+special+", $0", "=r,"+constraints)
		value := "%" + call
		resultType := hardwareType
		if op == "MOVL" && hardwareType == I64 {
			value = c.truncI64(value, I32)
			resultType = I32
		}
		return c.storeRegSized(other.Reg, resultType, value)
	}

	value, err := c.loadReg(other.Reg)
	if err != nil {
		return err
	}
	if hardwareType == I32 {
		value = c.truncI64(value, I32)
	}
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(%s %s)\n",
		"mov $0, "+special, "r,"+constraints, hardwareType, value)
	return nil
}

func (c *amd64Ctx) lowerTestRegisterMove(op string, index int, other Operand, readSpecial bool, ins Instr) error {
	if op != "MOVL" || (index != 6 && index != 7) {
		return fmt.Errorf("%s %s TR%d form is absent from Go 1.27's ymovtab: %q", c.goarch, op, index, ins.Raw)
	}
	if other.Kind == OpReg {
		if !isX86YrlRegisterForArch(other.Reg, c.goarch) {
			return fmt.Errorf("%s MOVL TR%d operand is outside Go 1.27's Yml class: %q", c.goarch, index, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(other) {
		return fmt.Errorf("%s MOVL TR%d expects a Go 1.27 Yml register or memory: %q", c.goarch, index, ins.Raw)
	}
	modRM := 0xc0 | byte(index<<3)
	constraints := "~{memory},~{dirflag},~{fpsr},~{flags}"
	if readSpecial {
		call := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i32 asm sideeffect %q, %q()\n",
			call, fmt.Sprintf(".byte 0x0f, 0x24, 0x%02x", modRM), "={ax},"+constraints)
		return c.storeScalarIntegerOperand(other, I32, "%"+call)
	}
	value, err := c.evalIntSized(other, I32)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(i32 %s)\n",
		fmt.Sprintf(".byte 0x0f, 0x26, 0x%02x", modRM), "{ax},"+constraints, value)
	return nil
}

func (c *amd64Ctx) lowerDescriptorRegisterAlias(op, class string, other Operand, readSpecial bool, ins Instr) error {
	directOp := ""
	switch class {
	case "gdtr":
		if op != "MOVL" && op != "MOVQ" {
			break
		}
		if readSpecial {
			directOp = "SGDT"
		} else {
			directOp = "LGDT"
		}
	case "idtr":
		if op != "MOVL" && op != "MOVQ" {
			break
		}
		if readSpecial {
			directOp = "SIDT"
		} else {
			directOp = "LIDT"
		}
	case "ldtr":
		if op == "MOVW" {
			if readSpecial {
				directOp = "SLDTW"
			} else {
				directOp = "LLDT"
			}
		}
	case "msw":
		if op == "MOVW" {
			if readSpecial {
				directOp = "SMSWW"
			} else {
				directOp = "LMSW"
			}
		}
	case "task":
		if op == "MOVW" {
			if readSpecial {
				directOp = "STRW"
			} else {
				directOp = "LTR"
			}
		}
	}
	if directOp == "" {
		return fmt.Errorf("%s %s %s form is absent from Go 1.27's ymovtab: %q", c.goarch, op, strings.ToUpper(class), ins.Raw)
	}
	ok, _, err := c.lowerDescriptorTable(Op(directOp), Instr{Op: Op(directOp), Args: []Operand{other}, Raw: ins.Raw})
	if !ok {
		panic("descriptor MOV alias lowering drift")
	}
	return err
}
