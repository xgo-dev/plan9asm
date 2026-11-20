package plan9asm

import (
	"fmt"
)

// lowerPackedByteShift implements Go 1.27's PSLLO/PSRLO aliases and
// PSLLDQ/PSRLDQ vector family. Every operation shifts bytes independently
// within each 128-bit lane and fills vacated bytes with zero.
func (c *amd64Ctx) lowerPackedByteShift(op Op, ins Instr) (bool, bool, error) {
	return c.lowerX86PackedShift(op, ins)
}

func amd64SignedImmediate(operand Operand, bits int) bool {
	if operand.Kind != OpImm || operand.ImmIsFloat || operand.ImmRaw != "" || bits <= 0 || bits >= 63 {
		return false
	}
	limit := int64(1) << (bits - 1)
	return operand.Imm >= -limit && operand.Imm < limit
}

func amd64VectorByteShiftImmediate(operand Operand) bool {
	return operand.Kind == OpImm && !operand.ImmIsFloat && operand.ImmRaw == "" && operand.Imm >= -128 && operand.Imm <= 255
}

func amd64PackedByteShiftRequiresEVEX(source, destination Operand, byteWidth int) bool {
	if byteWidth == 64 || isAMD64MemoryOperand(source) {
		return true
	}
	for _, operand := range []Operand{source, destination} {
		index, ok := amd64VectorRegisterIndex(operand.Reg, byteWidth)
		if !ok || index >= 16 {
			return true
		}
	}
	return false
}

func (c *amd64Ctx) emitPackedByteShift(byteWidth int, source string, count uint8, left bool) string {
	if count >= 16 {
		return "zeroinitializer"
	}
	result := "zeroinitializer"
	for laneBase := 0; laneBase < byteWidth; laneBase += 16 {
		for destinationByte := 0; destinationByte < 16; destinationByte++ {
			sourceByte := destinationByte + int(count)
			if left {
				sourceByte = destinationByte - int(count)
			}
			if sourceByte < 0 || sourceByte >= 16 {
				continue
			}
			extracted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i8> %s, i32 %d\n", extracted, byteWidth, source, laneBase+sourceByte)
			inserted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i8> %s, i8 %%%s, i32 %d\n", inserted, byteWidth, result, extracted, laneBase+destinationByte)
			result = "%" + inserted
		}
	}
	return result
}
