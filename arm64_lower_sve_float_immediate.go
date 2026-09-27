package plan9asm

import (
	"fmt"
	"math"
	"strings"
)

func (c *arm64Ctx) lowerARM64SVEFloatImmediate(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZFCPY" && op != "ZFDUP" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) {
		return true, false, fmt.Errorf("arm64 %s does not accept a mnemonic suffix: %q", op, ins.Raw)
	}
	wantArgs := 2
	if op == "ZFCPY" {
		wantArgs = 3
	}
	if len(ins.Args) != wantArgs || !arm64SVEFloatImmediateRepresentable(ins.Args[0]) {
		return true, false, fmt.Errorf("arm64 %s requires an encodable floating immediate and its complete Go 1.27 operand form: %q", op, ins.Raw)
	}
	destinationOperand := ins.Args[wantArgs-1]
	destination, elementBits, destinationOK := arm64SVEFloatElementReg(destinationOperand)
	if !destinationOK {
		return true, false, fmt.Errorf("arm64 %s destination must use H, S, or D elements: %q", op, ins.Raw)
	}
	value := math.Float64frombits(uint64(ins.Args[0].Imm))
	splat, err := c.arm64SVEFloatSplat(value, elementBits)
	if err != nil {
		return true, false, err
	}
	_, vectorType, _, err := arm64SVEFloatType(elementBits)
	if err != nil {
		return true, false, err
	}
	if op == "ZFDUP" {
		return true, false, c.storeRawSVEFloatVector(destination, elementBits, splat, vectorType)
	}
	predicate, predicateOK := arm64ParseSVEPredicateMode(ins.Args[1], "M", 15)
	if !predicateOK {
		return true, false, fmt.Errorf("arm64 ZFCPY requires P0..P15/M: %q", ins.Raw)
	}
	oldDestination, _, err := c.loadRawSVEFloatVector(destination, elementBits)
	if err != nil {
		return true, false, err
	}
	predicateValue, predicateType, err := c.loadPRegElements(predicate, elementBits)
	if err != nil {
		return true, false, err
	}
	selected := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select %s %s, %s %s, %s %s\n", selected, predicateType, predicateValue, vectorType, splat, vectorType, oldDestination)
	return true, false, c.storeRawSVEFloatVector(destination, elementBits, "%"+selected, vectorType)
}

// arm64SVEFloatImmediateRepresentable mirrors Go's chipfloat7 acceptance
// check: one sign bit, a 3-bit exponent, and four fractional bits expanded to
// an exact binary64 value. That is the full 256-value immediate domain shared
// by ZFCPY and ZFDUP.
func arm64SVEFloatImmediateRepresentable(operand Operand) bool {
	if operand.Kind != OpImm || operand.ImmRaw != "" || !operand.ImmIsFloat {
		return false
	}
	bits := math.Float64bits(math.Float64frombits(uint64(operand.Imm)))
	low := uint32(bits)
	high := uint32(bits >> 32)
	if low != 0 || high&0xffff != 0 {
		return false
	}
	exponent := high & 0x7fc00000
	return exponent == 0x40000000 || exponent == 0x3fc00000
}
