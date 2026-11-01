package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) lowerARM64BitReverse(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "RBIT" && op != "RBITW" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) {
		return true, false, fmt.Errorf("arm64 %s does not accept an instruction suffix: %q", op, ins.Raw)
	}
	if len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg ||
		!isARM64GeneralOrZeroReg(ins.Args[0].Reg) || !isARM64GeneralOrZeroReg(ins.Args[1].Reg) {
		return true, false, fmt.Errorf("arm64 %s expects general register, general register: %q", op, ins.Raw)
	}

	if op == "RBITW" {
		source, err := c.eval32(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		reversed := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.bitreverse.i32(i32 %s)\n", reversed, source)
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", wide, reversed)
		return true, false, c.storeReg(ins.Args[1].Reg, "%"+wide)
	}

	source, err := c.loadReg(ins.Args[0].Reg)
	if err != nil {
		return true, false, err
	}
	reversed := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call i64 @llvm.bitreverse.i64(i64 %s)\n", reversed, source)
	return true, false, c.storeReg(ins.Args[1].Reg, "%"+reversed)
}
