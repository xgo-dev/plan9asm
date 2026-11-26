package x86

import (
	"fmt"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

func x86MinSignedLiteral(ty asm.LLVMType) string {
	switch ty {
	case asm.I8:
		return "-128"
	case asm.I16:
		return "-32768"
	case asm.I32:
		return "-2147483648"
	default:
		return "-9223372036854775808"
	}
}

func x86WideIntType(ty asm.LLVMType) (wideTy asm.LLVMType, maxUnsigned string) {
	switch ty {
	case asm.I8:
		return asm.I16, "255"
	case asm.I16:
		return asm.I32, "65535"
	case asm.I32:
		return asm.I64, "4294967295"
	default:
		return asm.LLVMType("i128"), "18446744073709551615"
	}
}

// computeParityFlag computes the architectural x86 Parity Flag (PF):
// 1 iff the low 8 bits of val contain an even number of set bits.
func (c *amd64Ctx) computeParityFlag(ty asm.LLVMType, val string) string {
	b := val
	if ty != asm.I8 {
		tr := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc %s %s to i8\n", tr, ty, val)
		b = "%" + tr
	}
	s4, p4, s2, p2, s1, p1, lsb, pf := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = lshr i8 %s, 4\n", s4, b)
	fmt.Fprintf(c.b, "  %%%s = xor i8 %s, %%%s\n", p4, b, s4)
	fmt.Fprintf(c.b, "  %%%s = lshr i8 %%%s, 2\n", s2, p4)
	fmt.Fprintf(c.b, "  %%%s = xor i8 %%%s, %%%s\n", p2, p4, s2)
	fmt.Fprintf(c.b, "  %%%s = lshr i8 %%%s, 1\n", s1, p2)
	fmt.Fprintf(c.b, "  %%%s = xor i8 %%%s, %%%s\n", p1, p2, s1)
	fmt.Fprintf(c.b, "  %%%s = and i8 %%%s, 1\n", lsb, p1)
	fmt.Fprintf(c.b, "  %%%s = icmp eq i8 %%%s, 0\n", pf, lsb)
	return "%" + pf
}

// setZSPFlagsSized updates ZF, SF, and PF from an integer result of type ty.
func (c *amd64Ctx) setZSPFlagsSized(ty asm.LLVMType, val string) {
	zf, sf := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, 0\n", zf, ty, val)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zf, c.flagsZSlot)
	fmt.Fprintf(c.b, "  %%%s = icmp slt %s %s, 0\n", sf, ty, val)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", sf, c.flagsSltSlot)
	pf := c.computeParityFlag(ty, val)
	fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", pf, c.flagsPFSlot)
}

// setLogicFlagsSized sets flags for AND/OR/XOR/TEST: CF=0, OF=0, ZF/SF/PF from res.
func (c *amd64Ctx) setLogicFlagsSized(ty asm.LLVMType, res string) {
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsCFSlot)
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
	c.setZSPFlagsSized(ty, res)
}

// setAddFlagsSized sets architectural CF, OF, ZF, SF, PF for res = dst + src.
func (c *amd64Ctx) setAddFlagsSized(ty asm.LLVMType, dst, src, res string) {
	cf := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ult %s %s, %s\n", cf, ty, res, dst)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)
	// Signed overflow on addition: dst and src have the same sign, and res has the opposite sign.
	xab, sameSign, xdr, ovAnd, of := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor %s %s, %s\n", xab, ty, dst, src)
	fmt.Fprintf(c.b, "  %%%s = xor %s %%%s, -1\n", sameSign, ty, xab)
	fmt.Fprintf(c.b, "  %%%s = xor %s %s, %s\n", xdr, ty, dst, res)
	fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %%%s\n", ovAnd, ty, sameSign, xdr)
	fmt.Fprintf(c.b, "  %%%s = icmp slt %s %%%s, 0\n", of, ty, ovAnd)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", of, c.flagsOFSlot)
	c.setZSPFlagsSized(ty, res)
}

// setSubFlagsSized sets architectural CF, OF, ZF, SF, PF for diff = a - b.
func (c *amd64Ctx) setSubFlagsSized(ty asm.LLVMType, a, b, diff string) {
	cf := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ult %s %s, %s\n", cf, ty, a, b)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)
	// Signed overflow on subtraction: a and b have opposite signs, and diff has opposite sign to a.
	xab, xad, ovAnd, of := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor %s %s, %s\n", xab, ty, a, b)
	fmt.Fprintf(c.b, "  %%%s = xor %s %s, %s\n", xad, ty, a, diff)
	fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %%%s\n", ovAnd, ty, xab, xad)
	fmt.Fprintf(c.b, "  %%%s = icmp slt %s %%%s, 0\n", of, ty, ovAnd)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", of, c.flagsOFSlot)
	c.setZSPFlagsSized(ty, diff)
}

// setAddCarryFlagsSized sets architectural CF, OF, ZF, SF, PF for res = dst + src + carryIn.
func (c *amd64Ctx) setAddCarryFlagsSized(ty asm.LLVMType, dst, src, carryIn, res string) {
	wTy, maxU := x86WideIntType(ty)
	du, su, cu, u1, u2, cf := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext %s %s to %s\n", du, ty, dst, wTy)
	fmt.Fprintf(c.b, "  %%%s = zext %s %s to %s\n", su, ty, src, wTy)
	fmt.Fprintf(c.b, "  %%%s = zext i1 %s to %s\n", cu, carryIn, wTy)
	fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %%%s\n", u1, wTy, du, su)
	fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %%%s\n", u2, wTy, u1, cu)
	fmt.Fprintf(c.b, "  %%%s = icmp ugt %s %%%s, %s\n", cf, wTy, u2, maxU)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)

	ds, ss, s1, s2, rs, of := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sext %s %s to %s\n", ds, ty, dst, wTy)
	fmt.Fprintf(c.b, "  %%%s = sext %s %s to %s\n", ss, ty, src, wTy)
	fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %%%s\n", s1, wTy, ds, ss)
	fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %%%s\n", s2, wTy, s1, cu)
	fmt.Fprintf(c.b, "  %%%s = sext %s %s to %s\n", rs, ty, res, wTy)
	fmt.Fprintf(c.b, "  %%%s = icmp ne %s %%%s, %%%s\n", of, wTy, rs, s2)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", of, c.flagsOFSlot)

	c.setZSPFlagsSized(ty, res)
}

// setSubBorrowFlagsSized sets architectural CF, OF, ZF, SF, PF for res = dst - src - borrowIn.
func (c *amd64Ctx) setSubBorrowFlagsSized(ty asm.LLVMType, dst, src, borrowIn, res string) {
	wTy, _ := x86WideIntType(ty)
	du, su, cu, subtr, cf := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext %s %s to %s\n", du, ty, dst, wTy)
	fmt.Fprintf(c.b, "  %%%s = zext %s %s to %s\n", su, ty, src, wTy)
	fmt.Fprintf(c.b, "  %%%s = zext i1 %s to %s\n", cu, borrowIn, wTy)
	fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %%%s\n", subtr, wTy, su, cu)
	fmt.Fprintf(c.b, "  %%%s = icmp ult %s %%%s, %%%s\n", cf, wTy, du, subtr)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)

	ds, ss, s1, s2, rs, of := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sext %s %s to %s\n", ds, ty, dst, wTy)
	fmt.Fprintf(c.b, "  %%%s = sext %s %s to %s\n", ss, ty, src, wTy)
	fmt.Fprintf(c.b, "  %%%s = sub %s %%%s, %%%s\n", s1, wTy, ds, ss)
	fmt.Fprintf(c.b, "  %%%s = sub %s %%%s, %%%s\n", s2, wTy, s1, cu)
	fmt.Fprintf(c.b, "  %%%s = sext %s %s to %s\n", rs, ty, res, wTy)
	fmt.Fprintf(c.b, "  %%%s = icmp ne %s %%%s, %%%s\n", of, wTy, rs, s2)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", of, c.flagsOFSlot)

	c.setZSPFlagsSized(ty, res)
}

// setIncDecFlagsSized sets architectural OF, ZF, SF, PF for INC/DEC (preserving CF).
func (c *amd64Ctx) setIncDecFlagsSized(ty asm.LLVMType, oldVal, res string, isDec bool) {
	of := c.newTmp()
	minLit := x86MinSignedLiteral(ty)
	if isDec {
		fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, %s\n", of, ty, oldVal, minLit)
	} else {
		fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, %s\n", of, ty, res, minLit)
	}
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", of, c.flagsOFSlot)
	c.setZSPFlagsSized(ty, res)
}

// setNegFlagsSized sets architectural CF, OF, ZF, SF, PF for res = -oldVal.
func (c *amd64Ctx) setNegFlagsSized(ty asm.LLVMType, oldVal, res string) {
	cf, of := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ne %s %s, 0\n", cf, ty, oldVal)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)
	fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, %s\n", of, ty, oldVal, x86MinSignedLiteral(ty))
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", of, c.flagsOFSlot)
	c.setZSPFlagsSized(ty, res)
}

// setUnsignedMulFlags sets architectural CF = OF = (hi != 0) for MUL*.
func (c *amd64Ctx) setUnsignedMulFlags(ty asm.LLVMType, hi string) {
	ov := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ne %s %s, 0\n", ov, ty, hi)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", ov, c.flagsCFSlot)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", ov, c.flagsOFSlot)
}

// setSignedMulFlags sets architectural CF = OF = (sext(lo) != prod) for IMUL*.
func (c *amd64Ctx) setSignedMulFlags(ty, wideTy asm.LLVMType, lo, prod string) {
	se, ov := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sext %s %s to %s\n", se, ty, lo, wideTy)
	fmt.Fprintf(c.b, "  %%%s = icmp ne %s %%%s, %s\n", ov, wideTy, se, prod)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", ov, c.flagsCFSlot)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", ov, c.flagsOFSlot)
}

// setShiftFlagsSized updates CF, OF, ZF, SF, PF for SHL/SAL/SHR/SAR of width 8/16/32/64.
// maskedCnt is already masked by the architectural count mask (31 for 8/16/32-bit, 63 for 64-bit)
// and has type cntTy (i64). immCount >= 0 indicates a known immediate masked count.
// Per Intel SDM, effective count 0 preserves all status flags unchanged.
func (c *amd64Ctx) setShiftFlagsSized(ty asm.LLVMType, width int, kind string, oldVal, res, maskedCntI64 string, immCount int64) {
	if immCount == 0 {
		return
	}
	var isZero, safeCnt64 string
	if immCount < 0 {
		zTmp := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq i64 %s, 0\n", zTmp, maskedCntI64)
		isZero = "%" + zTmp
		sTmp := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %s, i64 1, i64 %s\n", sTmp, isZero, maskedCntI64)
		safeCnt64 = "%" + sTmp
	} else {
		safeCnt64 = fmt.Sprintf("%d", immCount)
	}

	// Compute last bit shifted out for CF without ever shifting by >= width (poison-free).
	var newCFVal string
	inRange := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ule i64 %s, %d\n", inRange, safeCnt64, width)
	clamped64 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 %s, i64 %d\n", clamped64, inRange, safeCnt64, width)
	bitPos64 := c.newTmp()
	if kind == "shl" {
		fmt.Fprintf(c.b, "  %%%s = sub i64 %d, %%%s\n", bitPos64, width, clamped64)
	} else {
		fmt.Fprintf(c.b, "  %%%s = sub i64 %%%s, 1\n", bitPos64, clamped64)
	}
	bitPos := "%" + bitPos64
	if ty != asm.I64 {
		tr := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to %s\n", tr, bitPos64, ty)
		bitPos = "%" + tr
	}
	cfSh, cfBit, cfRaw := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %s\n", cfSh, ty, oldVal, bitPos)
	fmt.Fprintf(c.b, "  %%%s = and %s %%%s, 1\n", cfBit, ty, cfSh)
	fmt.Fprintf(c.b, "  %%%s = icmp ne %s %%%s, 0\n", cfRaw, ty, cfBit)
	if kind == "ashr" {
		// For SAR with count >= width, every bit shifted out equals MSB(oldVal).
		oldSign, cfSel := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp slt %s %s, 0\n", oldSign, ty, oldVal)
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i1 %%%s, i1 %%%s\n", cfSel, inRange, cfRaw, oldSign)
		newCFVal = "%" + cfSel
	} else {
		newCFVal = "%" + cfRaw
	}

	newZF, newSF := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, 0\n", newZF, ty, res)
	fmt.Fprintf(c.b, "  %%%s = icmp slt %s %s, 0\n", newSF, ty, res)
	newPFVal := c.computeParityFlag(ty, res)

	var newOFVal string
	switch kind {
	case "shl":
		ofTmp := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, %s\n", ofTmp, newSF, newCFVal)
		newOFVal = "%" + ofTmp
	case "ashr":
		newOFVal = "false"
	default: // lshr
		ofTmp := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp slt %s %s, 0\n", ofTmp, ty, oldVal)
		newOFVal = "%" + ofTmp
	}

	if immCount < 0 {
		oldZF := c.loadFlag(c.flagsZSlot)
		oldSF := c.loadFlag(c.flagsSltSlot)
		oldPF := c.loadFlag(c.flagsPFSlot)
		oldCF := c.loadFlag(c.flagsCFSlot)
		oldOF := c.loadFlag(c.flagsOFSlot)
		selZF, selSF, selPF, selCF, selOF := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %s, i1 %s, i1 %%%s\n", selZF, isZero, oldZF, newZF)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", selZF, c.flagsZSlot)
		fmt.Fprintf(c.b, "  %%%s = select i1 %s, i1 %s, i1 %%%s\n", selSF, isZero, oldSF, newSF)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", selSF, c.flagsSltSlot)
		fmt.Fprintf(c.b, "  %%%s = select i1 %s, i1 %s, i1 %s\n", selPF, isZero, oldPF, newPFVal)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", selPF, c.flagsPFSlot)
		fmt.Fprintf(c.b, "  %%%s = select i1 %s, i1 %s, i1 %s\n", selCF, isZero, oldCF, newCFVal)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", selCF, c.flagsCFSlot)
		fmt.Fprintf(c.b, "  %%%s = select i1 %s, i1 %s, i1 %s\n", selOF, isZero, oldOF, newOFVal)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", selOF, c.flagsOFSlot)
		return
	}
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", newZF, c.flagsZSlot)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", newSF, c.flagsSltSlot)
	fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", newPFVal, c.flagsPFSlot)
	fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", newCFVal, c.flagsCFSlot)
	fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", newOFVal, c.flagsOFSlot)
}

// setDoubleShiftFlagsSized updates CF, OF, ZF, SF, PF for SHLD/SHRD of width 16/32/64.
// Per Intel SDM, effective count 0 preserves all flags; for count == 1, OF = sign change.
func (c *amd64Ctx) setDoubleShiftFlagsSized(ty asm.LLVMType, width int, isLeft bool, oldDst, res, maskedCntI64 string, immCount int64) {
	if immCount == 0 {
		return
	}
	var isZero, safeCnt64 string
	if immCount < 0 {
		zTmp := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq i64 %s, 0\n", zTmp, maskedCntI64)
		isZero = "%" + zTmp
		sTmp := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %s, i64 1, i64 %s\n", sTmp, isZero, maskedCntI64)
		safeCnt64 = "%" + sTmp
	} else {
		safeCnt64 = fmt.Sprintf("%d", immCount)
	}
	inRange := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ule i64 %s, %d\n", inRange, safeCnt64, width)
	clamped64 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 %s, i64 %d\n", clamped64, inRange, safeCnt64, width)
	bitPos64 := c.newTmp()
	if isLeft {
		fmt.Fprintf(c.b, "  %%%s = sub i64 %d, %%%s\n", bitPos64, width, clamped64)
	} else {
		fmt.Fprintf(c.b, "  %%%s = sub i64 %%%s, 1\n", bitPos64, clamped64)
	}
	bitPos := "%" + bitPos64
	if ty != asm.I64 {
		tr := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to %s\n", tr, bitPos64, ty)
		bitPos = "%" + tr
	}
	cfSh, cfBit, newCF := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %s\n", cfSh, ty, oldDst, bitPos)
	fmt.Fprintf(c.b, "  %%%s = and %s %%%s, 1\n", cfBit, ty, cfSh)
	fmt.Fprintf(c.b, "  %%%s = icmp ne %s %%%s, 0\n", newCF, ty, cfBit)
	newZF, newSF, oldSF, newOF := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, 0\n", newZF, ty, res)
	fmt.Fprintf(c.b, "  %%%s = icmp slt %s %s, 0\n", newSF, ty, res)
	fmt.Fprintf(c.b, "  %%%s = icmp slt %s %s, 0\n", oldSF, ty, oldDst)
	fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, %%%s\n", newOF, newSF, oldSF)
	newPFVal := c.computeParityFlag(ty, res)
	if immCount < 0 {
		oldZF := c.loadFlag(c.flagsZSlot)
		oldSign := c.loadFlag(c.flagsSltSlot)
		oldPF := c.loadFlag(c.flagsPFSlot)
		oldCF := c.loadFlag(c.flagsCFSlot)
		oldOF := c.loadFlag(c.flagsOFSlot)
		selZF, selSF, selPF, selCF, selOF := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %s, i1 %s, i1 %%%s\n", selZF, isZero, oldZF, newZF)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", selZF, c.flagsZSlot)
		fmt.Fprintf(c.b, "  %%%s = select i1 %s, i1 %s, i1 %%%s\n", selSF, isZero, oldSign, newSF)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", selSF, c.flagsSltSlot)
		fmt.Fprintf(c.b, "  %%%s = select i1 %s, i1 %s, i1 %s\n", selPF, isZero, oldPF, newPFVal)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", selPF, c.flagsPFSlot)
		fmt.Fprintf(c.b, "  %%%s = select i1 %s, i1 %s, i1 %%%s\n", selCF, isZero, oldCF, newCF)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", selCF, c.flagsCFSlot)
		fmt.Fprintf(c.b, "  %%%s = select i1 %s, i1 %s, i1 %%%s\n", selOF, isZero, oldOF, newOF)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", selOF, c.flagsOFSlot)
		return
	}
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", newZF, c.flagsZSlot)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", newSF, c.flagsSltSlot)
	fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", newPFVal, c.flagsPFSlot)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", newCF, c.flagsCFSlot)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", newOF, c.flagsOFSlot)
}

// setRotateFlagsSized updates CF (and OF for count == 1) for ROL/ROR of width 8/16/32/64.
// Per Intel SDM:
//   - maskedCnt == 0 leaves CF and OF untouched.
//   - ZF, SF, PF are always untouched.
//   - ROL: CF = LSB(res), OF (count == 1) = MSB(res) ^ CF.
//   - ROR: CF = MSB(res), OF (count == 1) = MSB(res) ^ bit(width-2)(res).
func (c *amd64Ctx) setRotateFlagsSized(ty asm.LLVMType, width int, isLeft bool, res, maskedCntI64 string, immCount int64) {
	if immCount == 0 {
		return
	}
	var newCFVal, newOFVal string
	msb := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt %s %s, 0\n", msb, ty, res)
	if isLeft {
		lsb, cf, of := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and %s %s, 1\n", lsb, ty, res)
		fmt.Fprintf(c.b, "  %%%s = icmp ne %s %%%s, 0\n", cf, ty, lsb)
		fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, %%%s\n", of, msb, cf)
		newCFVal = "%" + cf
		newOFVal = "%" + of
	} else {
		newCFVal = "%" + msb
		sh2, b2, bit2, of := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %d\n", sh2, ty, res, width-2)
		fmt.Fprintf(c.b, "  %%%s = and %s %%%s, 1\n", b2, ty, sh2)
		fmt.Fprintf(c.b, "  %%%s = icmp ne %s %%%s, 0\n", bit2, ty, b2)
		fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, %%%s\n", of, msb, bit2)
		newOFVal = "%" + of
	}
	if immCount < 0 {
		isZero := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq i64 %s, 0\n", isZero, maskedCntI64)
		oldCF := c.loadFlag(c.flagsCFSlot)
		oldOF := c.loadFlag(c.flagsOFSlot)
		selCF, selOF := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i1 %s, i1 %s\n", selCF, isZero, oldCF, newCFVal)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", selCF, c.flagsCFSlot)
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i1 %s, i1 %s\n", selOF, isZero, oldOF, newOFVal)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", selOF, c.flagsOFSlot)
		return
	}
	fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", newCFVal, c.flagsCFSlot)
	fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", newOFVal, c.flagsOFSlot)
}
