package plan9asm

import (
	"fmt"
	"strings"
)

func (c *armCtx) lowerARMSignedMultiply(op, cond string, setFlags bool, ins Instr) error {
	for _, suffix := range armInstructionSuffixes(ins) {
		if suffix == "" || armCondCodes[suffix] || suffix == "S" && op == "MULL" {
			continue
		}
		return fmt.Errorf("arm %s suffix %q is absent from the Go 1.27 optab: %q", op, suffix, ins.Raw)
	}
	if setFlags && op != "MULL" {
		return fmt.Errorf("arm %s does not accept the .S suffix: %q", op, ins.Raw)
	}
	loadRegOperand := func(operand Operand) (string, error) {
		if operand.Kind != OpReg || !isARMGeneralReg(operand.Reg) {
			return "", fmt.Errorf("arm %s accepts only general-register operands: %q", op, ins.Raw)
		}
		return c.loadReg(operand.Reg)
	}
	signed64 := func(value string) string {
		name := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sext i32 %s to i64\n", name, value)
		return "%" + name
	}
	signedHalf := func(value string, top bool) string {
		if top {
			name := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = ashr i32 %s, 16\n", name, value)
			return "%" + name
		}
		narrow := c.newTmp()
		extended := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i32 %s to i16\n", narrow, value)
		fmt.Fprintf(c.b, "  %%%s = sext i16 %%%s to i32\n", extended, narrow)
		return "%" + extended
	}
	multiply64 := func(first, second string) string {
		product := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = mul i64 %s, %s\n", product, signed64(first), signed64(second))
		return "%" + product
	}
	highWord := func(product string) string {
		shifted := c.newTmp()
		word := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ashr i64 %s, 32\n", shifted, product)
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", word, shifted)
		return "%" + word
	}

	if op == "MULL" {
		if len(ins.Args) != 3 || ins.Args[2].Kind != OpRegList || len(ins.Args[2].RegList) != 2 ||
			!armRegListAllGPR(ins.Args[2].RegList) {
			return fmt.Errorf("arm MULL expects src, src, (hi,lo): %q", ins.Raw)
		}
		first, err := loadRegOperand(ins.Args[0])
		if err != nil {
			return err
		}
		second, err := loadRegOperand(ins.Args[1])
		if err != nil {
			return err
		}
		product := multiply64(first, second)
		low := c.newTmp()
		highShifted := c.newTmp()
		high := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", low, product)
		fmt.Fprintf(c.b, "  %%%s = lshr i64 %s, 32\n", highShifted, product)
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", high, highShifted)
		if err := c.selectRegPairWrite(ins.Args[2].RegList[0], ins.Args[2].RegList[1], cond, "%"+high, "%"+low); err != nil {
			return err
		}
		if setFlags {
			execute := "true"
			if cond != "" && !strings.EqualFold(cond, "AL") {
				execute, err = c.condValue(cond)
				if err != nil {
					return err
				}
			}
			zero := c.newTmp()
			negative := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp eq i64 %s, 0\n", zero, product)
			fmt.Fprintf(c.b, "  %%%s = icmp slt i64 %s, 0\n", negative, product)
			c.storeFlagPredicate(c.flagsZSlot, "%"+zero, execute)
			c.storeFlagPredicate(c.flagsNSlot, "%"+negative, execute)
			c.flagsWritten = true
		}
		return nil
	}

	wantArgs := 3
	if op == "MMULA" || op == "MMULS" || op == "MULABB" || op == "MULAWB" || op == "MULAWT" || op == "MULS" {
		wantArgs = 4
	}
	if len(ins.Args) != wantArgs {
		return fmt.Errorf("arm %s expects %d general-register operands: %q", op, wantArgs, ins.Raw)
	}
	values := make([]string, len(ins.Args))
	for i, operand := range ins.Args {
		value, err := loadRegOperand(operand)
		if err != nil {
			return err
		}
		values[i] = value
	}
	result := ""
	switch op {
	case "MMUL", "MMULA", "MMULS":
		high := highWord(multiply64(values[0], values[1]))
		if op == "MMUL" {
			result = high
		} else {
			combined := c.newTmp()
			llvmOp := "add"
			if op == "MMULS" {
				llvmOp = "sub"
				fmt.Fprintf(c.b, "  %%%s = sub i32 %s, %s\n", combined, values[2], high)
			} else {
				fmt.Fprintf(c.b, "  %%%s = %s i32 %s, %s\n", combined, llvmOp, high, values[2])
			}
			result = "%" + combined
		}
	case "MULBB", "MULABB":
		first := signedHalf(values[0], false)
		second := signedHalf(values[1], false)
		product := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = mul i32 %s, %s\n", product, first, second)
		result = "%" + product
		if op == "MULABB" {
			combined := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add i32 %s, %s\n", combined, result, values[2])
			result = "%" + combined
		}
	case "MULWB", "MULWT", "MULAWB", "MULAWT":
		top := op == "MULWT" || op == "MULAWT"
		half := signedHalf(values[0], top)
		product := multiply64(half, values[1])
		shifted := c.newTmp()
		word := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ashr i64 %s, 16\n", shifted, product)
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", word, shifted)
		result = "%" + word
		if op == "MULAWB" || op == "MULAWT" {
			combined := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add i32 %s, %s\n", combined, result, values[2])
			result = "%" + combined
		}
	case "MULS":
		product := c.newTmp()
		combined := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = mul i32 %s, %s\n", product, values[0], values[1])
		fmt.Fprintf(c.b, "  %%%s = sub i32 %s, %%%s\n", combined, values[2], product)
		result = "%" + combined
	default:
		return fmt.Errorf("arm: unsupported signed multiply instruction %s", op)
	}
	return c.selectRegWrite(ins.Args[len(ins.Args)-1].Reg, cond, result)
}
