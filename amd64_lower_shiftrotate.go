package plan9asm

import (
	"fmt"
	"strings"
)

// lowerScalarShiftRotate implements the complete Go 1.27 yshb/yshl family:
// RCL/RCR/ROL/ROR/SAR/SAL/SHL/SHR at B/W/L/Q widths, plus the special
// three-operand SHL/SHR W/L/Q double-shift table.
func (c *amd64Ctx) lowerScalarShiftRotate(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	stem, bits, recognized := amd64ScalarShiftRotateProperties(baseOp)
	if !recognized {
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("%s %s does not accept instruction suffixes: %q", c.goarch, baseOp, ins.Raw)
	}
	if c.goarch == "386" && bits == 64 {
		return true, false, fmt.Errorf("386 %s is illegal in 32-bit mode: %q", baseOp, ins.Raw)
	}
	if len(ins.Args) == 3 {
		if (stem != "SHL" && stem != "SHR") || bits == 8 {
			return true, false, fmt.Errorf("%s %s has no three-operand form in Go 1.27: %q", c.goarch, baseOp, ins.Raw)
		}
		return c.lowerScalarDoubleShift(baseOp, stem == "SHL", bits, ins)
	}
	if len(ins.Args) != 2 {
		return true, false, fmt.Errorf("%s %s expects count, destination: %q", c.goarch, baseOp, ins.Raw)
	}
	count, err := c.scalarShiftCount(ins.Args[0], bits, false)
	if err != nil {
		return true, false, fmt.Errorf("%s %s count: %w", c.goarch, baseOp, err)
	}
	dst := ins.Args[1]
	if !c.scalarShiftDestination(dst, bits) {
		return true, false, fmt.Errorf("%s %s destination is outside Go 1.27's Ymb/Yml class: %q", c.goarch, baseOp, ins.Raw)
	}
	ty := amd64IntegerTypeForBits(bits)
	value, err := c.evalIntSized(dst, ty)
	if err != nil {
		return true, false, err
	}
	var result string
	if stem == "RCL" || stem == "RCR" {
		result = c.emitScalarCarryRotate(stem, bits, value, count)
	} else {
		result = c.emitScalarShiftRotate(stem, bits, value, count)
	}
	if err := c.storeScalarIntegerOperand(dst, ty, result); err != nil {
		return true, false, err
	}
	return true, false, nil
}

func amd64ScalarShiftRotateProperties(op string) (stem string, bits int, ok bool) {
	switch op {
	case "RCLB", "RCRB", "ROLB", "RORB", "SARB", "SALB", "SHLB", "SHRB":
		bits = 8
	case "RCLW", "RCRW", "ROLW", "RORW", "SARW", "SALW", "SHLW", "SHRW":
		bits = 16
	case "RCLL", "RCRL", "ROLL", "RORL", "SARL", "SALL", "SHLL", "SHRL":
		bits = 32
	case "RCLQ", "RCRQ", "ROLQ", "RORQ", "SARQ", "SALQ", "SHLQ", "SHRQ":
		bits = 64
	default:
		return "", 0, false
	}
	return op[:len(op)-1], bits, true
}

func (c *amd64Ctx) emitScalarCarryRotate(stem string, bits int, value, count64 string) string {
	// Model RCL/RCR as a rotate of the destination plus CF. Intel masks the
	// count to five (six for Q) bits first; scalarShiftCount already did that.
	// B/W then reduce it modulo 9/17, while L/Q values are already below 33/65.
	totalBits := bits + 1
	effective64 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = urem i64 %s, %d\n", effective64, count64, totalBits)

	wideType := LLVMType(fmt.Sprintf("i%d", totalBits))
	valueWide := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext %s %s to %s\n", valueWide, amd64IntegerTypeForBits(bits), value, wideType)
	oldCF := c.loadFlag(c.flagsCFSlot)
	cfWide := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext i1 %s to %s\n", cfWide, oldCF, wideType)
	cfHigh := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shl %s %%%s, %d\n", cfHigh, wideType, cfWide, bits)
	combined := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = or %s %%%s, %%%s\n", combined, wideType, valueWide, cfHigh)

	toWideCount := func(value string) string {
		converted := c.newTmp()
		if totalBits <= 64 {
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", converted, value, wideType)
		} else {
			fmt.Fprintf(c.b, "  %%%s = zext i64 %s to %s\n", converted, value, wideType)
		}
		return "%" + converted
	}
	effective := toWideCount("%" + effective64)
	inverseRaw := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sub i64 %d, %%%s\n", inverseRaw, totalBits, effective64)
	inverse64 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = urem i64 %%%s, %d\n", inverse64, inverseRaw, totalBits)
	inverse := toWideCount("%" + inverse64)

	left := c.newTmp()
	right := c.newTmp()
	if stem == "RCL" {
		fmt.Fprintf(c.b, "  %%%s = shl %s %%%s, %s\n", left, wideType, combined, effective)
		fmt.Fprintf(c.b, "  %%%s = lshr %s %%%s, %s\n", right, wideType, combined, inverse)
	} else {
		fmt.Fprintf(c.b, "  %%%s = lshr %s %%%s, %s\n", right, wideType, combined, effective)
		fmt.Fprintf(c.b, "  %%%s = shl %s %%%s, %s\n", left, wideType, combined, inverse)
	}
	rotated := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = or %s %%%s, %%%s\n", rotated, wideType, left, right)

	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to %s\n", result, wideType, rotated, amd64IntegerTypeForBits(bits))
	cfShifted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = lshr %s %%%s, %d\n", cfShifted, wideType, rotated, bits)
	newCF := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to i1\n", newCF, wideType, cfShifted)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", newCF, c.flagsCFSlot)

	// OF is defined only for a one-bit rotate. Preserve its prior value for
	// the architecturally undefined cases, including an effective count of 0.
	msbShifted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = lshr %s %%%s, %d\n", msbShifted, amd64IntegerTypeForBits(bits), result, bits-1)
	msb := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to i1\n", msb, amd64IntegerTypeForBits(bits), msbShifted)
	definedOF := c.newTmp()
	if stem == "RCL" {
		fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, %%%s\n", definedOF, msb, newCF)
	} else {
		nextShifted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr %s %%%s, %d\n", nextShifted, amd64IntegerTypeForBits(bits), result, bits-2)
		nextMSB := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to i1\n", nextMSB, amd64IntegerTypeForBits(bits), nextShifted)
		fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, %%%s\n", definedOF, msb, nextMSB)
	}
	isOne := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq i64 %%%s, 1\n", isOne, effective64)
	oldOF := c.loadFlag(c.flagsOFSlot)
	newOF := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i1 %%%s, i1 %s\n", newOF, isOne, definedOF, oldOF)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", newOF, c.flagsOFSlot)
	return "%" + result
}

func (c *amd64Ctx) scalarShiftCount(count Operand, bits int, doubleShift bool) (string, error) {
	mask := int64(31)
	if bits == 64 {
		mask = 63
	}
	switch count.Kind {
	case OpImm:
		if doubleShift {
			if count.Imm < -128 || count.Imm > 127 {
				return "", fmt.Errorf("immediate is outside Go 1.27's signed-imm8 class")
			}
		} else if count.Imm < 0 || count.Imm > 255 {
			return "", fmt.Errorf("immediate is outside Go 1.27's unsigned-imm8 class")
		}
		return fmt.Sprintf("%d", count.Imm&mask), nil
	case OpReg:
		if count.Reg != CL && count.Reg != CX {
			return "", fmt.Errorf("register count must be CL or CX")
		}
		value, err := c.loadReg(count.Reg)
		if err != nil {
			return "", err
		}
		masked := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %s, %d\n", masked, value, mask)
		return "%" + masked, nil
	default:
		return "", fmt.Errorf("count must be an immediate, CL, or CX")
	}
}

func (c *amd64Ctx) scalarShiftDestination(dst Operand, bits int) bool {
	if dst.Kind == OpReg {
		if bits == 8 {
			return isGoYmbRegisterForArch(dst.Reg, c.goarch)
		}
		return isX86YrlRegisterForArch(dst.Reg, c.goarch)
	}
	return isAMD64MemoryOperand(dst)
}

func (c *amd64Ctx) emitScalarShiftRotate(stem string, bits int, value, count64 string) string {
	ty := amd64IntegerTypeForBits(bits)
	amount64 := count64
	if stem == "ROL" || stem == "ROR" {
		masked := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %s, %d\n", masked, count64, bits-1)
		amount64 = "%" + masked
	}
	amount := amount64
	if bits != 64 {
		truncated := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", truncated, amount64, ty)
		amount = "%" + truncated
	}

	if stem == "ROL" || stem == "ROR" {
		inverseNeg := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub %s 0, %s\n", inverseNeg, ty, amount)
		inverse := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %d\n", inverse, ty, inverseNeg, bits-1)
		left := c.newTmp()
		right := c.newTmp()
		if stem == "ROL" {
			fmt.Fprintf(c.b, "  %%%s = shl %s %s, %s\n", left, ty, value, amount)
			fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %%%s\n", right, ty, value, inverse)
		} else {
			fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %s\n", right, ty, value, amount)
			fmt.Fprintf(c.b, "  %%%s = shl %s %s, %%%s\n", left, ty, value, inverse)
		}
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or %s %%%s, %%%s\n", result, ty, left, right)
		return "%" + result
	}

	inRange := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ult i64 %s, %d\n", inRange, count64, bits)
	safe64 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 %s, i64 %d\n", safe64, inRange, count64, bits-1)
	safe := "%" + safe64
	if bits != 64 {
		truncated := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to %s\n", truncated, safe64, ty)
		safe = "%" + truncated
	}
	shifted := c.newTmp()
	switch stem {
	case "SHL", "SAL":
		fmt.Fprintf(c.b, "  %%%s = shl %s %s, %s\n", shifted, ty, value, safe)
	case "SHR":
		fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %s\n", shifted, ty, value, safe)
	case "SAR":
		fmt.Fprintf(c.b, "  %%%s = ashr %s %s, %s\n", shifted, ty, value, safe)
		return "%" + shifted
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s %%%s, %s 0\n", result, inRange, ty, shifted, ty)
	return "%" + result
}

func (c *amd64Ctx) lowerScalarDoubleShift(baseOp string, left bool, bits int, ins Instr) (bool, bool, error) {
	count, err := c.scalarShiftCount(ins.Args[0], bits, true)
	if err != nil {
		return true, false, fmt.Errorf("%s %s count: %w", c.goarch, baseOp, err)
	}
	if ins.Args[1].Kind != OpReg || !isX86YrlRegisterForArch(ins.Args[1].Reg, c.goarch) {
		return true, false, fmt.Errorf("%s %s source must be a Yrl GP register: %q", c.goarch, baseOp, ins.Raw)
	}
	if !c.scalarShiftDestination(ins.Args[2], bits) {
		return true, false, fmt.Errorf("%s %s destination must be a Yml GP register or memory: %q", c.goarch, baseOp, ins.Raw)
	}
	ty := amd64IntegerTypeForBits(bits)
	source, err := c.evalIntSized(ins.Args[1], ty)
	if err != nil {
		return true, false, err
	}
	destination, err := c.evalIntSized(ins.Args[2], ty)
	if err != nil {
		return true, false, err
	}

	// W double shifts mask the hardware count to five bits, leaving counts
	// 16-31 architecturally undefined. Reduce that undefined region modulo the
	// lane width so generated LLVM never shifts by the type width.
	effective64 := count
	if bits == 16 {
		masked := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %s, 15\n", masked, count)
		effective64 = "%" + masked
	}
	effective := effective64
	if bits != 64 {
		truncated := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", truncated, effective64, ty)
		effective = "%" + truncated
	}
	inverseNeg := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sub %s 0, %s\n", inverseNeg, ty, effective)
	inverse := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %d\n", inverse, ty, inverseNeg, bits-1)
	first := c.newTmp()
	second := c.newTmp()
	if left {
		fmt.Fprintf(c.b, "  %%%s = shl %s %s, %s\n", first, ty, destination, effective)
		fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %%%s\n", second, ty, source, inverse)
	} else {
		fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %s\n", first, ty, destination, effective)
		fmt.Fprintf(c.b, "  %%%s = shl %s %s, %%%s\n", second, ty, source, inverse)
	}
	merged := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = or %s %%%s, %%%s\n", merged, ty, first, second)
	zero := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, 0\n", zero, ty, effective)
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s %s, %s %%%s\n", result, zero, ty, destination, ty, merged)
	if err := c.storeScalarIntegerOperand(ins.Args[2], ty, "%"+result); err != nil {
		return true, false, err
	}
	return true, false, nil
}

func (c *amd64Ctx) storeScalarIntegerOperand(dst Operand, ty LLVMType, value string) error {
	switch dst.Kind {
	case OpReg:
		return c.storeRegSized(dst.Reg, ty, value)
	case OpMem:
		ptr, ptrType, err := c.ptrFromMem(dst.Mem)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store %s %s, %s %s, align 1\n", ty, value, ptrType, ptr)
		return nil
	case OpSym:
		ptr, err := c.ptrFromSB(dst.Sym)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store %s %s, ptr %s, align 1\n", ty, value, ptr)
		return nil
	case OpFP:
		return c.storeFPResult(dst.FPOffset, ty, value)
	default:
		return fmt.Errorf("expected GP register or memory destination, got %s", dst.String())
	}
}
