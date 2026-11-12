package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
)

type arm64RawSVEAddress struct {
	op          Op
	immediate   int
	source      int
	destination int
}

func decodeARM64RawSVEAddress(word uint32) (arm64RawSVEAddress, bool) {
	form := arm64RawSVEAddress{}
	switch {
	case word&0xffe0f800 == 0x04205000:
		form.op = "ADDVL"
	case word&0xffe0f800 == 0x04605000:
		form.op = "ADDPL"
	case word&0xfffff800 == 0x04bf5000:
		form.op = "RDVL"
	default:
		return arm64RawSVEAddress{}, false
	}
	immediate := int(word>>5) & 63
	if immediate&32 != 0 {
		immediate -= 64
	}
	form.immediate = immediate
	form.source = int(word>>16) & 31
	form.destination = int(word) & 31
	if form.op == "RDVL" && form.destination == 31 {
		return arm64RawSVEAddress{}, false
	}
	return form, true
}

func arm64SVEAddressReg(operand Operand, allowSP bool) (Reg, bool) {
	if operand.Kind != OpReg {
		return "", false
	}
	s := strings.ToUpper(string(operand.Reg))
	if operand.Reg == SP || s == "RSP" {
		return SP, allowSP
	}
	if !strings.HasPrefix(s, "R") {
		return "", false
	}
	index, err := strconv.Atoi(s[1:])
	if err != nil || index < 0 || index > 30 {
		return "", false
	}
	return Reg(fmt.Sprintf("R%d", index)), true
}

func (c *arm64Ctx) lowerARM64SVEAddress(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ADDVL" && op != "ADDPL" && op != "RDVL" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) < 2 || ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" || ins.Args[0].Imm < -32 || ins.Args[0].Imm > 31 {
		return true, false, fmt.Errorf("arm64 %s expects a signed 6-bit immediate and no suffix: %q", op, ins.Raw)
	}
	immediate := ins.Args[0].Imm
	var source, destination Reg
	if op == "RDVL" {
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("arm64 RDVL expects $imm, Rdst: %q", ins.Raw)
		}
		var valid bool
		destination, valid = arm64SVEAddressReg(ins.Args[1], false)
		if !valid {
			return true, false, fmt.Errorf("arm64 RDVL destination must be R0..R30: %q", ins.Raw)
		}
	} else {
		if len(ins.Args) != 3 {
			return true, false, fmt.Errorf("arm64 %s expects $imm, Rsrc|RSP, Rdst|RSP: %q", op, ins.Raw)
		}
		var sourceValid, destinationValid bool
		source, sourceValid = arm64SVEAddressReg(ins.Args[1], true)
		destination, destinationValid = arm64SVEAddressReg(ins.Args[2], true)
		if !sourceValid || !destinationValid {
			return true, false, fmt.Errorf("arm64 %s source and destination must be R0..R30 or RSP: %q", op, ins.Raw)
		}
	}

	vscale := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call i64 @llvm.vscale.i64()\n", vscale)
	bytesPerVScale := int64(16)
	if op == "ADDPL" {
		bytesPerVScale = 2
	}
	scaled := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = mul i64 %%%s, %d\n", scaled, vscale, immediate*bytesPerVScale)
	value := "%" + scaled
	if op != "RDVL" {
		base, err := c.loadReg(source)
		if err != nil {
			return true, false, err
		}
		added := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i64 %s, %s\n", added, base, value)
		value = "%" + added
	}
	return true, false, c.storeReg(destination, value)
}

func (c *arm64Ctx) lowerRawSVEAddress(form arm64RawSVEAddress) error {
	reg := func(index int, spAllowed bool) Operand {
		if index == 31 && spAllowed {
			return Operand{Kind: OpReg, Reg: SP}
		}
		return Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("R%d", index))}
	}
	args := []Operand{{Kind: OpImm, Imm: int64(form.immediate)}}
	if form.op == "RDVL" {
		args = append(args, reg(form.destination, false))
	} else {
		args = append(args, reg(form.source, true), reg(form.destination, true))
	}
	ins := Instr{Op: form.op, Raw: fmt.Sprintf("decoded ARM64 WORD as %s", form.op), Args: args}
	ok, _, err := c.lowerARM64SVEAddress(form.op, ins)
	if !ok && err == nil {
		return fmt.Errorf("arm64 raw %s decoder reached no semantic lowerer", form.op)
	}
	return err
}
