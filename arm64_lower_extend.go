package plan9asm

import (
	"fmt"
	"strings"
)

type arm64ScalarExtendSpec struct {
	sourceBits      int
	signed          bool
	wordDestination bool
}

var arm64ScalarExtendSpecs = map[Op]arm64ScalarExtendSpec{
	"SXTB":  {sourceBits: 8, signed: true},
	"SXTBW": {sourceBits: 8, signed: true, wordDestination: true},
	"SXTH":  {sourceBits: 16, signed: true},
	"SXTHW": {sourceBits: 16, signed: true, wordDestination: true},
	"SXTW":  {sourceBits: 32, signed: true},
	"UXTB":  {sourceBits: 8},
	"UXTBW": {sourceBits: 8, wordDestination: true},
	"UXTH":  {sourceBits: 16},
	"UXTHW": {sourceBits: 16, wordDestination: true},
	"UXTW":  {sourceBits: 32},
}

func (c *arm64Ctx) lowerARM64ScalarExtend(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64ScalarExtendSpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) {
		return true, false, fmt.Errorf("arm64 %s does not accept an opcode suffix: %q", op, ins.Raw)
	}
	if len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("arm64 %s expects source and destination registers: %q", op, ins.Raw)
	}
	source, err := c.loadReg(ins.Args[0].Reg)
	if err != nil {
		return true, false, err
	}
	narrow := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i%d\n", narrow, source, spec.sourceBits)
	destinationBits := 64
	if spec.wordDestination {
		destinationBits = 32
	}
	extended := c.newTmp()
	extension := "zext"
	if spec.signed {
		extension = "sext"
	}
	fmt.Fprintf(c.b, "  %%%s = %s i%d %%%s to i%d\n", extended, extension, spec.sourceBits, narrow, destinationBits)
	value := "%" + extended
	if spec.wordDestination {
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", wide, value)
		value = "%" + wide
	}
	return true, false, c.storeReg(ins.Args[1].Reg, value)
}
