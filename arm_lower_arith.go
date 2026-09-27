package plan9asm

import (
	"fmt"
	"math/bits"
	"strings"
)

func (c *armCtx) lowerArith(op, cond string, setFlags bool, ins Instr) (ok bool, terminated bool, err error) {
	switch op {
	case "ADD", "SUB", "AND", "ORR", "EOR", "RSB", "BIC":
		return true, false, c.lowerARMALU(op, cond, setFlags, ins)
	case "MVN":
		return true, false, c.lowerARMMVN(cond, setFlags, ins)
	case "ADC", "SBC", "RSC":
		return true, false, c.lowerARMADCSBC(op, cond, setFlags, ins)
	case "MUL", "MULU":
		return true, false, c.lowerARMMUL(cond, ins)
	case "MULLU":
		return true, false, c.lowerARMMULLU(cond, ins)
	case "MULL", "MMUL", "MMULA", "MMULS", "MULABB", "MULAWB", "MULBB", "MULS", "MULWB", "MULWT":
		return true, false, c.lowerARMSignedMultiply(op, cond, setFlags, ins)
	case "MULA":
		return true, false, c.lowerARMMULA(cond, ins)
	case "MULAL", "MULALU":
		return true, false, c.lowerARMMULAL(cond, ins)
	case "MULAWT":
		return true, false, c.lowerARMSignedMultiply(op, cond, setFlags, ins)
	case "DIV", "DIVU", "MOD", "MODU", "DIVHW", "DIVUHW":
		return true, false, c.lowerARMDivMod(op, cond, setFlags, ins)
	case "CLZ":
		return true, false, c.lowerARMCLZ(cond, ins)
	case "REV", "REV16", "REVSH", "RBIT":
		return true, false, c.lowerARMReverseBits(op, cond, ins)
	case "BFC", "BFI", "BFX", "BFXU":
		return true, false, c.lowerARMBitfield(op, cond, ins)
	case "XTAB", "XTABU", "XTAH", "XTAHU":
		return true, false, c.lowerARMExtendAdd(op, cond, ins)
	case "SWPW", "SWPBU":
		return true, false, c.lowerARMAtomicSwap(op, cond, ins)
	case "UADD8", "USUB8":
		return true, false, c.lowerARMUnsignedParallelByteAddSub(op, cond, setFlags, ins)
	case "SLL", "SRL", "SRA":
		return true, false, c.lowerARMShift(op, cond, setFlags, ins)
	case "MRC":
		return true, false, c.lowerARMMRC(ins)
	case "MCR":
		return true, false, c.lowerARMMCR(ins)
	case "CMP", "CMN", "TST", "TEQ":
		return true, false, c.lowerARMCompare(op, ins)
	}
	return false, false, nil
}

func (c *armCtx) lowerARMDivMod(op, cond string, setFlags bool, ins Instr) error {
	if err := armRequireConditionOnlySuffix(ins); err != nil {
		return err
	}
	if setFlags {
		return fmt.Errorf("arm %s does not accept the .S suffix: %q", op, ins.Raw)
	}
	if len(ins.Args) != 2 && len(ins.Args) != 3 {
		return fmt.Errorf("arm %s expects divisor, dst or divisor, numerator, dst: %q", op, ins.Raw)
	}
	for _, operand := range ins.Args {
		if operand.Kind != OpReg || !isARMGeneralReg(operand.Reg) {
			return fmt.Errorf("arm %s accepts only general registers: %q", op, ins.Raw)
		}
	}

	divisor, err := c.loadReg(ins.Args[0].Reg)
	if err != nil {
		return err
	}
	numeratorOperand := ins.Args[len(ins.Args)-2]
	destination := ins.Args[len(ins.Args)-1].Reg
	numerator, err := c.loadReg(numeratorOperand.Reg)
	if err != nil {
		return err
	}

	zero := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq i32 %s, 0\n", zero, divisor)
	safeDivisor := divisor
	overflow := "false"
	if op == "DIV" || op == "MOD" || op == "DIVHW" {
		isMin := c.newTmp()
		isMinusOne := c.newTmp()
		overflowTmp := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq i32 %s, -2147483648\n", isMin, numerator)
		fmt.Fprintf(c.b, "  %%%s = icmp eq i32 %s, -1\n", isMinusOne, divisor)
		fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", overflowTmp, isMin, isMinusOne)
		overflow = "%" + overflowTmp
		invalid := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i1 %%%s, %s\n", invalid, zero, overflow)
		safe := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i32 1, i32 %s\n", safe, invalid, divisor)
		safeDivisor = "%" + safe
	} else {
		safe := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i32 1, i32 %s\n", safe, zero, divisor)
		safeDivisor = "%" + safe
	}

	calculated := c.newTmp()
	switch op {
	case "DIV", "DIVHW":
		fmt.Fprintf(c.b, "  %%%s = sdiv i32 %s, %s\n", calculated, numerator, safeDivisor)
	case "DIVU", "DIVUHW":
		fmt.Fprintf(c.b, "  %%%s = udiv i32 %s, %s\n", calculated, numerator, safeDivisor)
	case "MOD":
		fmt.Fprintf(c.b, "  %%%s = srem i32 %s, %s\n", calculated, numerator, safeDivisor)
	case "MODU":
		fmt.Fprintf(c.b, "  %%%s = urem i32 %s, %s\n", calculated, numerator, safeDivisor)
	}
	result := "%" + calculated
	if op == "DIV" || op == "DIVHW" {
		wrapped := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %s, i32 -2147483648, i32 %s\n", wrapped, overflow, result)
		result = "%" + wrapped
	} else if op == "MOD" {
		wrapped := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %s, i32 0, i32 %s\n", wrapped, overflow, result)
		result = "%" + wrapped
	}
	zeroResult := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i32 0, i32 %s\n", zeroResult, zero, result)
	return c.selectRegWrite(destination, cond, "%"+zeroResult)
}

func armRotatedImmediateEncodable(value uint32) bool {
	for i := 0; i < 16; i++ {
		if value&^uint32(0xff) == 0 {
			return true
		}
		value = bits.RotateLeft32(value, 2)
	}
	return false
}

func (c *armCtx) lowerARMShift(op, cond string, setFlags bool, ins Instr) error {
	if len(ins.Args) != 2 && len(ins.Args) != 3 {
		return fmt.Errorf("arm %s expects shift, dstReg or shift, srcReg, dstReg: %q", op, ins.Raw)
	}
	shift := ins.Args[0]
	var src, dst Operand
	if len(ins.Args) == 2 {
		src, dst = ins.Args[1], ins.Args[1]
	} else {
		src, dst = ins.Args[1], ins.Args[2]
	}
	if src.Kind != OpReg || dst.Kind != OpReg {
		return fmt.Errorf("arm %s source and destination must be registers: %q", op, ins.Raw)
	}
	srcValue, err := c.loadReg(src.Reg)
	if err != nil {
		return err
	}
	if _, err := c.loadReg(dst.Reg); err != nil {
		return err
	}

	execute := "true"
	if cond != "" && !strings.EqualFold(cond, "AL") {
		execute, err = c.condValue(cond)
		if err != nil {
			return err
		}
	}

	var result, carry string
	switch shift.Kind {
	case OpImm:
		if shift.Imm < 0 || uint64(shift.Imm) > uint64(^uint32(0)) || !armRotatedImmediateEncodable(uint32(shift.Imm)) {
			return fmt.Errorf("arm %s immediate is not a Go ARM rotated immediate: %q", op, ins.Raw)
		}
		result, carry = c.emitARMImmediateShift(op, srcValue, uint32(shift.Imm)&31)
	case OpReg:
		shiftValue, loadErr := c.loadReg(shift.Reg)
		if loadErr != nil {
			return loadErr
		}
		result, carry = c.emitARMRegisterShift(op, srcValue, shiftValue)
	default:
		return fmt.Errorf("arm %s shift must be an immediate or register: %q", op, ins.Raw)
	}
	if err := c.selectRegWrite(dst.Reg, cond, result); err != nil {
		return err
	}
	if setFlags {
		return c.setARMShiftFlags(execute, result, carry)
	}
	return nil
}

func (c *armCtx) emitARMImmediateShift(op, value string, encodedAmount uint32) (result, carry string) {
	amount := encodedAmount
	if (op == "SRL" || op == "SRA") && amount == 0 {
		amount = 32
	}
	switch op {
	case "SLL":
		if amount == 0 {
			result = value
			carry = c.loadFlagValue(c.flagsCSlot)
			return result, carry
		}
		result = c.emitARMConstantShift("shl", value, amount)
		carry = c.emitARMShiftBit(value, 32-amount)
	case "SRL":
		if amount == 32 {
			result = "0"
		} else {
			result = c.emitARMConstantShift("lshr", value, amount)
		}
		carry = c.emitARMShiftBit(value, amount-1)
	case "SRA":
		if amount == 32 {
			result = c.emitARMConstantShift("ashr", value, 31)
		} else {
			result = c.emitARMConstantShift("ashr", value, amount)
		}
		carry = c.emitARMShiftBit(value, amount-1)
	}
	return result, carry
}

func (c *armCtx) emitARMRegisterShift(op, value, rawAmount string) (result, carry string) {
	amount := c.newTmp()
	safeAmount := c.newTmp()
	isZero := c.newTmp()
	isAbove32 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and i32 %s, 255\n", amount, rawAmount)
	fmt.Fprintf(c.b, "  %%%s = and i32 %%%s, 31\n", safeAmount, amount)
	fmt.Fprintf(c.b, "  %%%s = icmp eq i32 %%%s, 0\n", isZero, amount)
	fmt.Fprintf(c.b, "  %%%s = icmp ugt i32 %%%s, 32\n", isAbove32, amount)

	shifted := c.newTmp()
	llvmOp := map[string]string{"SLL": "shl", "SRL": "lshr", "SRA": "ashr"}[op]
	fmt.Fprintf(c.b, "  %%%s = %s i32 %s, %%%s\n", shifted, llvmOp, value, safeAmount)
	overflowResult := "0"
	if op == "SRA" {
		overflowResult = c.emitARMConstantShift("ashr", value, 31)
	}
	overflowSelected := c.newTmp()
	zeroSelected := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i32 %s, i32 %%%s\n", overflowSelected, isAbove32, overflowResult, shifted)
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i32 %s, i32 %%%s\n", zeroSelected, isZero, value, overflowSelected)
	result = "%" + zeroSelected

	position := c.newTmp()
	if op == "SLL" {
		fmt.Fprintf(c.b, "  %%%s = sub i32 32, %%%s\n", position, amount)
	} else {
		fmt.Fprintf(c.b, "  %%%s = sub i32 %%%s, 1\n", position, amount)
	}
	safePosition := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and i32 %%%s, 31\n", safePosition, position)
	candidateCarry := c.emitARMVariableShiftBit(value, "%"+safePosition)
	overflowCarry := "false"
	if op == "SRA" {
		overflowCarry = c.emitARMShiftBit(value, 31)
	}
	overflowCarrySelected := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i1 %s, i1 %s\n", overflowCarrySelected, isAbove32, overflowCarry, candidateCarry)
	oldCarry := c.loadFlagValue(c.flagsCSlot)
	zeroCarrySelected := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i1 %s, i1 %%%s\n", zeroCarrySelected, isZero, oldCarry, overflowCarrySelected)
	return result, "%" + zeroCarrySelected
}

func (c *armCtx) emitARMConstantShift(op, value string, amount uint32) string {
	tmp := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s i32 %s, %d\n", tmp, op, value, amount)
	return "%" + tmp
}

func (c *armCtx) emitARMShiftBit(value string, position uint32) string {
	return c.emitARMVariableShiftBit(value, fmt.Sprintf("%d", position))
}

func (c *armCtx) emitARMVariableShiftBit(value, position string) string {
	shifted := c.newTmp()
	bit := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = lshr i32 %s, %s\n", shifted, value, position)
	fmt.Fprintf(c.b, "  %%%s = trunc i32 %%%s to i1\n", bit, shifted)
	return "%" + bit
}

func (c *armCtx) loadFlagValue(slot string) string {
	tmp := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i1, ptr %s\n", tmp, slot)
	return "%" + tmp
}

func (c *armCtx) setARMShiftFlags(execute, result, carry string) error {
	c.flagsWritten = true
	zero := c.newTmp()
	negative := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq i32 %s, 0\n", zero, result)
	fmt.Fprintf(c.b, "  %%%s = icmp slt i32 %s, 0\n", negative, result)
	c.storeFlagPredicate(c.flagsZSlot, "%"+zero, execute)
	c.storeFlagPredicate(c.flagsNSlot, "%"+negative, execute)
	c.storeFlagPredicate(c.flagsCSlot, carry, execute)
	return nil
}

func (c *armCtx) storeFlagPredicate(slot, value, execute string) {
	if execute == "true" {
		c.storeFlag(slot, value)
		return
	}
	old := c.loadFlagValue(slot)
	selected := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, i1 %s, i1 %s\n", selected, execute, value, old)
	c.storeFlag(slot, "%"+selected)
}

func (c *armCtx) lowerARMALU(op, cond string, setFlags bool, ins Instr) error {
	if len(ins.Args) != 2 && len(ins.Args) != 3 {
		return fmt.Errorf("arm %s expects 2 or 3 operands: %q", op, ins.Raw)
	}
	var src, lhs string
	dst := Operand{}
	var err error
	if len(ins.Args) == 2 {
		dst = ins.Args[1]
		if dst.Kind != OpReg {
			return fmt.Errorf("arm %s dst must be reg: %q", op, ins.Raw)
		}
		src, err = c.eval32(ins.Args[0], false)
		if err != nil {
			return err
		}
		lhs, err = c.loadReg(dst.Reg)
		if err != nil {
			return err
		}
	} else {
		dst = ins.Args[2]
		if dst.Kind != OpReg {
			return fmt.Errorf("arm %s dst must be reg: %q", op, ins.Raw)
		}
		src, err = c.eval32(ins.Args[0], false)
		if err != nil {
			return err
		}
		lhs, err = c.eval32(ins.Args[1], false)
		if err != nil {
			return err
		}
	}
	t := c.newTmp()
	switch op {
	case "ADD":
		fmt.Fprintf(c.b, "  %%%s = add i32 %s, %s\n", t, lhs, src)
	case "SUB":
		fmt.Fprintf(c.b, "  %%%s = sub i32 %s, %s\n", t, lhs, src)
	case "AND":
		fmt.Fprintf(c.b, "  %%%s = and i32 %s, %s\n", t, lhs, src)
	case "ORR":
		fmt.Fprintf(c.b, "  %%%s = or i32 %s, %s\n", t, lhs, src)
	case "EOR":
		fmt.Fprintf(c.b, "  %%%s = xor i32 %s, %s\n", t, lhs, src)
	case "RSB":
		fmt.Fprintf(c.b, "  %%%s = sub i32 %s, %s\n", t, src, lhs)
	case "BIC":
		n := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i32 %s, -1\n", n, src)
		fmt.Fprintf(c.b, "  %%%s = and i32 %s, %%%s\n", t, lhs, n)
	}
	if err := c.selectRegWrite(dst.Reg, cond, "%"+t); err != nil {
		return err
	}
	if !setFlags {
		return nil
	}
	switch op {
	case "ADD":
		return c.setFlagsAdd(cond, lhs, src, "%"+t)
	case "SUB":
		return c.setFlagsSub(cond, lhs, src, "%"+t)
	case "RSB":
		return c.setFlagsSub(cond, src, lhs, "%"+t)
	case "AND", "ORR", "EOR", "BIC":
		return c.setFlagsLogic(cond, "%"+t)
	default:
		return nil
	}
}

func (c *armCtx) lowerARMCompare(op string, ins Instr) error {
	if len(ins.Args) != 2 {
		return fmt.Errorf("arm %s expects 2 operands: %q", op, ins.Raw)
	}
	src, err := c.eval32(ins.Args[0], false)
	if err != nil {
		return err
	}
	lhs, err := c.eval32(ins.Args[1], false)
	if err != nil {
		return err
	}
	res := c.newTmp()
	switch op {
	case "CMP":
		fmt.Fprintf(c.b, "  %%%s = sub i32 %s, %s\n", res, lhs, src)
		if err := c.setFlagsSub("", lhs, src, "%"+res); err != nil {
			return err
		}
	case "CMN":
		fmt.Fprintf(c.b, "  %%%s = add i32 %s, %s\n", res, lhs, src)
		if err := c.setFlagsAdd("", lhs, src, "%"+res); err != nil {
			return err
		}
	case "TST":
		fmt.Fprintf(c.b, "  %%%s = and i32 %s, %s\n", res, lhs, src)
		if err := c.setFlagsLogic("", "%"+res); err != nil {
			return err
		}
	case "TEQ":
		fmt.Fprintf(c.b, "  %%%s = xor i32 %s, %s\n", res, lhs, src)
		if err := c.setFlagsLogic("", "%"+res); err != nil {
			return err
		}
	}
	return nil
}

func (c *armCtx) lowerARMMVN(cond string, setFlags bool, ins Instr) error {
	if len(ins.Args) != 2 && len(ins.Args) != 3 {
		return fmt.Errorf("arm MVN expects 2 or 3 operands: %q", ins.Raw)
	}
	var src string
	var dst Operand
	var err error
	if len(ins.Args) == 2 {
		src, err = c.eval32(ins.Args[0], false)
		if err != nil {
			return err
		}
		dst = ins.Args[1]
	} else {
		src, err = c.eval32(ins.Args[1], false)
		if err != nil {
			return err
		}
		dst = ins.Args[2]
	}
	if dst.Kind != OpReg {
		return fmt.Errorf("arm MVN dst must be reg: %q", ins.Raw)
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor i32 %s, -1\n", t, src)
	if err := c.selectRegWrite(dst.Reg, cond, "%"+t); err != nil {
		return err
	}
	if setFlags {
		return c.setFlagsLogic(cond, "%"+t)
	}
	return nil
}

func (c *armCtx) lowerARMADCSBC(op, cond string, setFlags bool, ins Instr) error {
	if len(ins.Args) != 2 && len(ins.Args) != 3 {
		return fmt.Errorf("arm %s expects 2 or 3 operands: %q", op, ins.Raw)
	}
	if op == "RSC" {
		source := ins.Args[0]
		sourceOK := source.Kind == OpImm ||
			source.Kind == OpReg && isARMGeneralReg(source.Reg) ||
			source.Kind == OpRegShift && isARMGeneralReg(source.Reg)
		if !sourceOK {
			return fmt.Errorf("arm RSC source must be an immediate, general register, or shifted general register: %q", ins.Raw)
		}
		for _, operand := range ins.Args[1:] {
			if operand.Kind != OpReg || !isARMGeneralReg(operand.Reg) {
				return fmt.Errorf("arm RSC input and destination must be general registers: %q", ins.Raw)
			}
		}
	}
	var src, lhs string
	dst := Operand{}
	var err error
	if len(ins.Args) == 2 {
		dst = ins.Args[1]
		if dst.Kind != OpReg {
			return fmt.Errorf("arm %s dst must be reg: %q", op, ins.Raw)
		}
		src, err = c.eval32(ins.Args[0], false)
		if err != nil {
			return err
		}
		lhs, err = c.loadReg(dst.Reg)
		if err != nil {
			return err
		}
	} else {
		dst = ins.Args[2]
		if dst.Kind != OpReg {
			return fmt.Errorf("arm %s dst must be reg: %q", op, ins.Raw)
		}
		src, err = c.eval32(ins.Args[0], false)
		if err != nil {
			return err
		}
		lhs, err = c.eval32(ins.Args[1], false)
		if err != nil {
			return err
		}
	}
	cf := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i1, ptr %s\n", cf, c.flagsCSlot)
	cin := c.newTmp()
	if op == "SBC" || op == "RSC" {
		ncf := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, true\n", ncf, cf)
		fmt.Fprintf(c.b, "  %%%s = zext i1 %%%s to i32\n", cin, ncf)
	} else {
		fmt.Fprintf(c.b, "  %%%s = zext i1 %%%s to i32\n", cin, cf)
	}
	t0 := c.newTmp()
	if op == "SBC" {
		fmt.Fprintf(c.b, "  %%%s = sub i32 %s, %s\n", t0, lhs, src)
	} else if op == "RSC" {
		fmt.Fprintf(c.b, "  %%%s = sub i32 %s, %s\n", t0, src, lhs)
	} else {
		fmt.Fprintf(c.b, "  %%%s = add i32 %s, %s\n", t0, lhs, src)
	}
	res := c.newTmp()
	if op == "SBC" || op == "RSC" {
		fmt.Fprintf(c.b, "  %%%s = sub i32 %%%s, %%%s\n", res, t0, cin)
	} else {
		fmt.Fprintf(c.b, "  %%%s = add i32 %%%s, %%%s\n", res, t0, cin)
	}
	if err := c.selectRegWrite(dst.Reg, cond, "%"+res); err != nil {
		return err
	}
	if setFlags {
		if op == "ADC" {
			l64 := c.newTmp()
			s64 := c.newTmp()
			c64 := c.newTmp()
			total1 := c.newTmp()
			total2 := c.newTmp()
			carry := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", l64, lhs)
			fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", s64, src)
			fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", c64, cin)
			fmt.Fprintf(c.b, "  %%%s = add i64 %%%s, %%%s\n", total1, l64, s64)
			fmt.Fprintf(c.b, "  %%%s = add i64 %%%s, %%%s\n", total2, total1, c64)
			fmt.Fprintf(c.b, "  %%%s = icmp ugt i64 %%%s, 4294967295\n", carry, total2)
			if err := c.setFlagsAdd(cond, lhs, src, "%"+res); err != nil {
				return err
			}
			if err := c.storeFlagCond(cond, c.flagsCSlot, "%"+carry); err != nil {
				return err
			}
		} else {
			minuend, subtrahend := lhs, src
			if op == "RSC" {
				minuend, subtrahend = src, lhs
			}
			l64 := c.newTmp()
			s64 := c.newTmp()
			b64 := c.newTmp()
			subtr := c.newTmp()
			borrow := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", l64, minuend)
			fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", s64, subtrahend)
			fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", b64, cin)
			fmt.Fprintf(c.b, "  %%%s = add i64 %%%s, %%%s\n", subtr, s64, b64)
			fmt.Fprintf(c.b, "  %%%s = icmp ult i64 %%%s, %%%s\n", borrow, l64, subtr)
			if err := c.setFlagsSub(cond, minuend, subtrahend, "%"+res); err != nil {
				return err
			}
			nb := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, true\n", nb, borrow)
			if err := c.storeFlagCond(cond, c.flagsCSlot, "%"+nb); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *armCtx) selectRegPairWrite(hi, lo Reg, cond, newHi, newLo string) error {
	if cond == "" {
		if err := c.storeReg(hi, newHi); err != nil {
			return err
		}
		return c.storeReg(lo, newLo)
	}
	cv, err := c.condValue(cond)
	if err != nil {
		return err
	}
	oldHi, err := c.loadReg(hi)
	if err != nil {
		return err
	}
	oldLo, err := c.loadReg(lo)
	if err != nil {
		return err
	}
	selHi := c.newTmp()
	selLo := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, i32 %s, i32 %s\n", selHi, cv, newHi, oldHi)
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, i32 %s, i32 %s\n", selLo, cv, newLo, oldLo)
	if err := c.storeReg(hi, "%"+selHi); err != nil {
		return err
	}
	return c.storeReg(lo, "%"+selLo)
}

func (c *armCtx) lowerARMMUL(cond string, ins Instr) error {
	if len(ins.Args) != 2 && len(ins.Args) != 3 {
		return fmt.Errorf("arm MUL expects 2 or 3 operands: %q", ins.Raw)
	}
	var a, b string
	var dst Operand
	var err error
	if len(ins.Args) == 2 {
		dst = ins.Args[1]
		if dst.Kind != OpReg {
			return fmt.Errorf("arm MUL dst must be reg: %q", ins.Raw)
		}
		a, err = c.eval32(ins.Args[0], false)
		if err != nil {
			return err
		}
		b, err = c.loadReg(dst.Reg)
		if err != nil {
			return err
		}
	} else {
		dst = ins.Args[2]
		if dst.Kind != OpReg {
			return fmt.Errorf("arm MUL dst must be reg: %q", ins.Raw)
		}
		a, err = c.eval32(ins.Args[0], false)
		if err != nil {
			return err
		}
		b, err = c.eval32(ins.Args[1], false)
		if err != nil {
			return err
		}
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = mul i32 %s, %s\n", t, a, b)
	return c.selectRegWrite(dst.Reg, cond, "%"+t)
}

func (c *armCtx) lowerARMMULLU(cond string, ins Instr) error {
	if len(ins.Args) != 3 || ins.Args[2].Kind != OpRegList || len(ins.Args[2].RegList) != 2 {
		return fmt.Errorf("arm MULLU expects src, lhs, (hi,lo): %q", ins.Raw)
	}
	a, err := c.eval32(ins.Args[0], false)
	if err != nil {
		return err
	}
	b, err := c.eval32(ins.Args[1], false)
	if err != nil {
		return err
	}
	a64 := c.zextI32ToI64(a)
	b64 := c.zextI32ToI64(b)
	prod := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = mul i64 %s, %s\n", prod, a64, b64)
	lo := c.newTmp()
	hiShift := c.newTmp()
	hi := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", lo, prod)
	fmt.Fprintf(c.b, "  %%%s = lshr i64 %%%s, 32\n", hiShift, prod)
	fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", hi, hiShift)
	return c.selectRegPairWrite(ins.Args[2].RegList[0], ins.Args[2].RegList[1], cond, "%"+hi, "%"+lo)
}

func (c *armCtx) lowerARMMULA(cond string, ins Instr) error {
	if len(ins.Args) != 4 || ins.Args[3].Kind != OpReg {
		return fmt.Errorf("arm MULA expects a, b, acc, dst: %q", ins.Raw)
	}
	a, err := c.eval32(ins.Args[0], false)
	if err != nil {
		return err
	}
	b, err := c.eval32(ins.Args[1], false)
	if err != nil {
		return err
	}
	acc, err := c.eval32(ins.Args[2], false)
	if err != nil {
		return err
	}
	mul := c.newTmp()
	res := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = mul i32 %s, %s\n", mul, a, b)
	fmt.Fprintf(c.b, "  %%%s = add i32 %%%s, %s\n", res, mul, acc)
	return c.selectRegWrite(ins.Args[3].Reg, cond, "%"+res)
}

func (c *armCtx) lowerARMMULAL(cond string, ins Instr) error {
	if len(ins.Args) != 3 || ins.Args[2].Kind != OpRegList || len(ins.Args[2].RegList) != 2 {
		return fmt.Errorf("arm MULAL expects a, b, (hi,lo): %q", ins.Raw)
	}
	hiReg := ins.Args[2].RegList[0]
	loReg := ins.Args[2].RegList[1]
	a, err := c.eval32(ins.Args[0], false)
	if err != nil {
		return err
	}
	b, err := c.eval32(ins.Args[1], false)
	if err != nil {
		return err
	}
	oldHi, err := c.loadReg(hiReg)
	if err != nil {
		return err
	}
	oldLo, err := c.loadReg(loReg)
	if err != nil {
		return err
	}
	oldHi64 := c.zextI32ToI64(oldHi)
	oldLo64 := c.zextI32ToI64(oldLo)
	hiSh := c.newTmp()
	old64 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shl i64 %s, 32\n", hiSh, oldHi64)
	fmt.Fprintf(c.b, "  %%%s = or i64 %%%s, %s\n", old64, hiSh, oldLo64)
	prod := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = mul i64 %s, %s\n", prod, c.zextI32ToI64(a), c.zextI32ToI64(b))
	sum := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add i64 %%%s, %%%s\n", sum, old64, prod)
	lo := c.newTmp()
	hiShift := c.newTmp()
	hi := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", lo, sum)
	fmt.Fprintf(c.b, "  %%%s = lshr i64 %%%s, 32\n", hiShift, sum)
	fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", hi, hiShift)
	return c.selectRegPairWrite(hiReg, loReg, cond, "%"+hi, "%"+lo)
}

func (c *armCtx) lowerARMMULAWT(cond string, ins Instr) error {
	return c.lowerARMSignedMultiply("MULAWT", cond, false, ins)
}

func (c *armCtx) lowerARMDIVUHW(cond string, ins Instr) error {
	return c.lowerARMDivMod("DIVUHW", cond, false, ins)
}

func (c *armCtx) lowerARMCLZ(cond string, ins Instr) error {
	if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
		return fmt.Errorf("arm CLZ expects src, dst: %q", ins.Raw)
	}
	src, err := c.eval32(ins.Args[0], false)
	if err != nil {
		return err
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.ctlz.i32(i32 %s, i1 false)\n", t, src)
	return c.selectRegWrite(ins.Args[1].Reg, cond, "%"+t)
}

func (c *armCtx) lowerARMMRC(ins Instr) error {
	if len(ins.Args) != 6 || ins.Args[2].Kind != OpReg {
		return fmt.Errorf("arm MRC expects coproc, opc1, dst, CRn, CRm, opc2: %q", ins.Raw)
	}
	part := func(op Operand) string {
		s := strings.ToLower(strings.TrimSpace(op.String()))
		s = strings.TrimPrefix(s, "$")
		return strings.TrimPrefix(s, "c")
	}
	// LLVM inline asm refers to the single output register via $0.
	asm := fmt.Sprintf("mrc p%s, #%s, $0, c%s, c%s, #%s",
		part(ins.Args[0]), part(ins.Args[1]), part(ins.Args[3]), part(ins.Args[4]), part(ins.Args[5]))
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call i32 asm sideeffect %q, %q()\n", t, asm, "=r,~{memory}")
	return c.storeReg(ins.Args[2].Reg, "%"+t)
}

func (c *armCtx) lowerARMMCR(ins Instr) error {
	if len(ins.Args) != 6 || ins.Args[2].Kind != OpReg || !isARMGeneralReg(ins.Args[2].Reg) {
		return fmt.Errorf("arm MCR expects coprocessor, operation, source register, CRn, CRm, information: %q", ins.Raw)
	}
	for _, suffix := range armInstructionSuffixes(ins) {
		if suffix != "" && suffix != "S" && !armCondCodes[suffix] {
			return fmt.Errorf("arm MCR suffix %q is absent from the Go 1.27 optab: %q", suffix, ins.Raw)
		}
	}
	part := func(op Operand) string {
		s := strings.ToLower(strings.TrimSpace(op.String()))
		s = strings.TrimPrefix(s, "$")
		return strings.TrimPrefix(s, "c")
	}
	value, err := c.loadReg(ins.Args[2].Reg)
	if err != nil {
		return err
	}
	asm := fmt.Sprintf("mcr p%s, #%s, $0, c%s, c%s, #%s", part(ins.Args[0]), part(ins.Args[1]), part(ins.Args[3]), part(ins.Args[4]), part(ins.Args[5]))
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(i32 %s)\n", asm, "r,~{memory}", value)
	return nil
}
