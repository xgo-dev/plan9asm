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

func (f arm64SYSFields) operandString() string {
	return fmt.Sprintf("#%d, c%d, c%d, #%d", f.op1, f.cn, f.cm, f.op2)
}

func (c *arm64Ctx) lowerARM64SYS(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "SYS" && op != "SYSL" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) {
		return true, false, fmt.Errorf("arm64 %s does not accept an instruction suffix: %q", op, ins.Raw)
	}
	if len(ins.Args) == 0 || ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" {
		return true, false, fmt.Errorf("arm64 %s expects a resolved system-argument constant: %q", op, ins.Raw)
	}
	fields, valid := decodeARM64SYSArgument(ins.Args[0].Imm)
	if !valid {
		return true, false, fmt.Errorf("arm64 %s system argument is outside Go's SYSARG4 encoding: %q", op, ins.Raw)
	}

	if op == "SYS" {
		if len(ins.Args) == 1 {
			asm := "sys " + fields.operandString() + ", xzr"
			fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q()\n", asm, "~{memory}")
			return true, false, nil
		}
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg || !isARM64GeneralOrZeroReg(ins.Args[1].Reg) {
			return true, false, fmt.Errorf("arm64 SYS expects a system argument and optional R/ZR operand: %q", ins.Raw)
		}
		if ins.Args[1].Reg == ZR {
			asm := "sys " + fields.operandString() + ", xzr"
			fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q()\n", asm, "~{memory}")
			return true, false, nil
		}
		value, err := c.loadReg(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		asm := "sys " + fields.operandString() + ", $0"
		fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(i64 %s)\n", asm, "r,~{memory}", value)
		return true, false, nil
	}

	if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg || !isARM64GeneralOrZeroReg(ins.Args[1].Reg) {
		return true, false, fmt.Errorf("arm64 SYSL expects a system argument and one R/ZR destination: %q", ins.Raw)
	}
	result := c.newTmp()
	asm := "sysl $0, " + fields.operandString()
	fmt.Fprintf(c.b, "  %%%s = call i64 asm sideeffect %q, %q()\n", result, asm, "=r,~{memory}")
	if ins.Args[1].Reg != ZR {
		if err := c.storeReg(ins.Args[1].Reg, "%"+result); err != nil {
			return true, false, err
		}
	}
	return true, false, nil
}
