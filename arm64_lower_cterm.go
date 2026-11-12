package plan9asm

import (
	"fmt"
	"strings"
)

var arm64CTERMOps = map[Op]bool{
	"CTERMEQ":  true,
	"CTERMEQW": true,
	"CTERMNE":  true,
	"CTERMNEW": true,
}

func (c *arm64Ctx) lowerARM64CTERM(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if !arm64CTERMOps[op] {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg ||
		!isARM64GeneralOrZeroReg(ins.Args[0].Reg) || !isARM64GeneralOrZeroReg(ins.Args[1].Reg) || ins.Args[0].Reg == SP || ins.Args[0].Reg == Reg("RSP") || ins.Args[1].Reg == SP || ins.Args[1].Reg == Reg("RSP") {
		return true, false, fmt.Errorf("arm64 %s requires two R0..R30 or ZR operands: %q", op, ins.Raw)
	}
	first, err := c.loadReg(ins.Args[0].Reg)
	if err != nil {
		return true, false, err
	}
	second, err := c.loadReg(ins.Args[1].Reg)
	if err != nil {
		return true, false, err
	}
	typeName := "i64"
	if strings.HasSuffix(string(op), "W") {
		typeName = "i32"
		first32 := c.newTmp()
		second32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", first32, first)
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", second32, second)
		first = "%" + first32
		second = "%" + second32
	}
	mnemonic := strings.ToLower(strings.TrimSuffix(string(op), "W"))
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, \"r,r\"(%s %s, %s %s)\n", mnemonic+" $0, $1", typeName, first, typeName, second)
	return true, false, nil
}
