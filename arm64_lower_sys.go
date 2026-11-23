package plan9asm

import (
	"fmt"
	"strings"
)

const arm64SYSArgumentMask int64 = 7<<16 | 15<<12 | 15<<8 | 7<<5

type arm64SYSFields struct {
	op1 uint8
	cn  uint8
	cm  uint8
	op2 uint8
}

type arm64SystemOperation struct {
	arm64SYSFields
	register Reg
	read     bool
}

func decodeARM64SYSArgument(arg int64) (arm64SYSFields, bool) {
	if arg < 0 || arg&^arm64SYSArgumentMask != 0 {
		return arm64SYSFields{}, false
	}
	return arm64SYSFields{
		op1: uint8(arg >> 16 & 7),
		cn:  uint8(arg >> 12 & 15),
		cm:  uint8(arg >> 8 & 15),
		op2: uint8(arg >> 5 & 7),
	}, true
}

func decodeARM64RawSystemOperation(word uint32) (arm64SystemOperation, bool) {
	const sys, sysl = 0xd5080000, 0xd5280000
	base := word & 0xfff80000
	if base != sys && base != sysl {
		return arm64SystemOperation{}, false
	}
	fields, _ := decodeARM64SYSArgument(int64(word) & arm64SYSArgumentMask)
	register := ZR
	if word&31 != 31 {
		register = Reg(fmt.Sprintf("R%d", word&31))
	}
	return arm64SystemOperation{arm64SYSFields: fields, register: register, read: base == sysl}, true
}

func (f arm64SYSFields) operandString() string {
	return fmt.Sprintf("#%d, c%d, c%d, #%d", f.op1, f.cn, f.cm, f.op2)
}

func arm64IsSYSOpcode(op Op) bool {
	switch op {
	case "AT", "SYS", "SYSL":
		return true
	default:
		return false
	}
}

func parseARM64SystemOperation(op Op, ins Instr) (arm64SystemOperation, bool, error) {
	if op == "TLBI" {
		return parseARM64TLBI(ins)
	}
	if !arm64IsSYSOpcode(op) {
		return arm64SystemOperation{}, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) {
		return arm64SystemOperation{}, true, fmt.Errorf("arm64 %s does not accept an instruction suffix: %q", op, ins.Raw)
	}
	if len(ins.Args) == 0 || ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" {
		return arm64SystemOperation{}, true, fmt.Errorf("arm64 %s expects a resolved system-argument constant: %q", op, ins.Raw)
	}
	fields, valid := decodeARM64SYSArgument(ins.Args[0].Imm)
	if !valid {
		return arm64SystemOperation{}, true, fmt.Errorf("arm64 %s system argument is outside Go's SYSARG4 encoding: %q", op, ins.Raw)
	}

	form := arm64SystemOperation{arm64SYSFields: fields, register: ZR, read: op == "SYSL"}
	if len(ins.Args) > 2 || form.read && len(ins.Args) != 2 {
		return arm64SystemOperation{}, true, fmt.Errorf("arm64 %s has the wrong number of system operands: %q", op, ins.Raw)
	}
	if len(ins.Args) == 2 {
		operand := ins.Args[1]
		if operand.Kind != OpReg || !isARM64GeneralOrZeroReg(operand.Reg) {
			return arm64SystemOperation{}, true, fmt.Errorf("arm64 %s expects an R/ZR operand: %q", op, ins.Raw)
		}
		form.register = operand.Reg
	}
	return form, true, nil
}

func (c *arm64Ctx) lowerARM64SystemOperation(form arm64SystemOperation) error {
	fields := form.operandString()
	if form.read {
		if form.register == ZR {
			fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q()\n", "sysl xzr, "+fields, "~{memory}")
			return nil
		}
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i64 asm sideeffect %q, %q()\n", result, "sysl $0, "+fields, "=r,~{memory}")
		return c.storeReg(form.register, "%"+result)
	}
	assembly, constraints, args := "sys "+fields+", xzr", "~{memory}", ""
	if form.register != ZR {
		value, err := c.loadReg(form.register)
		if err != nil {
			return err
		}
		assembly, constraints, args = "sys "+fields+", $0", "r,~{memory}", "i64 "+value
	}

	const format = "  call void asm sideeffect %q, %q(%s)\n"
	if form.isKnownTLBI() {
		// TLB maintenance keeps the modeled registers and NZCV intact.
		c.emitMachineNeutralNativeIR(format, assembly, constraints, args)
	} else {
		fmt.Fprintf(c.b, format, assembly, constraints, args)
	}
	return nil
}
