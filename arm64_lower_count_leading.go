package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) lowerARM64CountLeading(op Op, ins Instr) (ok bool, terminated bool, err error) {
	signed := op == "CLS" || op == "CLSW"
	word := op == "CLZW" || op == "CLSW"
	if !signed && !word && op != "CLZ" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) {
		return true, false, fmt.Errorf("arm64 %s does not accept an instruction suffix: %q", op, ins.Raw)
	}
	if len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg ||
		!isARM64GeneralOrZeroReg(ins.Args[0].Reg) || !isARM64GeneralOrZeroReg(ins.Args[1].Reg) {
		return true, false, fmt.Errorf("arm64 %s expects general register, general register: %q", op, ins.Raw)
	}

	if word {
		source, err := c.eval32(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		value := source
		if signed {
			sign := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = ashr i32 %s, 31\n", sign, source)
			normalized := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor i32 %s, %%%s\n", normalized, source, sign)
			value = "%" + normalized
		}
		count := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.ctlz.i32(i32 %s, i1 false)\n", count, value)
		result := "%" + count
		if signed {
			adjusted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = sub i32 %s, 1\n", adjusted, result)
			result = "%" + adjusted
		}
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", wide, result)
		return true, false, c.storeReg(ins.Args[1].Reg, "%"+wide)
	}

	source, err := c.loadReg(ins.Args[0].Reg)
	if err != nil {
		return true, false, err
	}
	value := source
	if signed {
		sign := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ashr i64 %s, 63\n", sign, source)
		normalized := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i64 %s, %%%s\n", normalized, source, sign)
		value = "%" + normalized
	}
	count := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call i64 @llvm.ctlz.i64(i64 %s, i1 false)\n", count, value)
	result := "%" + count
	if signed {
		adjusted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub i64 %s, 1\n", adjusted, result)
		result = "%" + adjusted
	}
	return true, false, c.storeReg(ins.Args[1].Reg, result)
}
