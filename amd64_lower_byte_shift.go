package plan9asm

import (
	"fmt"
	"strings"
)

// lowerPackedByteShift implements Go 1.27's PSLLO/PSRLO aliases and
// PSLLDQ/PSRLDQ vector family. Every operation shifts bytes independently
// within each 128-bit lane and fills vacated bytes with zero.
func (c *amd64Ctx) lowerPackedByteShift(rawOp Op, ins Instr) (ok bool, terminated bool, err error) {
	raw := strings.ToUpper(string(rawOp))
	if strings.Contains(raw, ".") {
		base := strings.SplitN(raw, ".", 2)[0]
		switch base {
		case "PSLLO", "PSLLDQ", "PSRLO", "PSRLDQ", "VPSLLDQ", "VPSRLDQ":
			return true, false, fmt.Errorf("amd64 %s does not accept instruction suffixes: %q", base, ins.Raw)
		}
		return false, false, nil
	}
	left := raw == "PSLLO" || raw == "PSLLDQ" || raw == "VPSLLDQ"
	switch raw {
	case "PSLLO", "PSLLDQ", "PSRLO", "PSRLDQ":
		if len(ins.Args) != 2 || !amd64SignedImmediate(ins.Args[0], 8) {
			return true, false, fmt.Errorf("amd64 %s expects $signed-imm8, X: %q", raw, ins.Raw)
		}
		destination := ins.Args[1]
		if !c.isGoVEXVectorRegister(destination, 16, false) {
			return true, false, fmt.Errorf("amd64 %s destination is outside Go 1.27's X register class: %q", raw, ins.Raw)
		}
		source, err := c.loadX(destination.Reg)
		if err != nil {
			return true, false, err
		}
		result := c.emitPackedByteShift(16, source, uint8(ins.Args[0].Imm), left)
		return true, false, c.storeX(destination.Reg, result)

	case "VPSLLDQ", "VPSRLDQ":
		if len(ins.Args) != 3 || !amd64VectorByteShiftImmediate(ins.Args[0]) {
			return true, false, fmt.Errorf("amd64 %s expects $imm8, X|Y|Z/mem, X|Y|Z: %q", raw, ins.Raw)
		}
		source, destination := ins.Args[1], ins.Args[2]
		byteWidth := amd64VectorByteWidth(destination.Reg)
		if destination.Kind != OpReg || byteWidth != 16 && byteWidth != 32 && byteWidth != 64 || !c.isGoEVEXVectorRegister(destination, byteWidth) {
			return true, false, fmt.Errorf("amd64 %s destination is outside Go 1.27's X/Y/Z register classes: %q", raw, ins.Raw)
		}
		if source.Kind == OpReg {
			if !c.isGoEVEXVectorRegister(source, byteWidth) {
				return true, false, fmt.Errorf("amd64 %s source must match its destination width: %q", raw, ins.Raw)
			}
		} else if !isAMD64MemoryOperand(source) {
			return true, false, fmt.Errorf("amd64 %s source must be a vector register or memory: %q", raw, ins.Raw)
		}

		// The VEX rows admit signed or unsigned imm8 only for X/Y register
		// sources. Memory, Z width, or a high vector register selects an EVEX
		// row, whose immediate class is unsigned imm8.
		if ins.Args[0].Imm < 0 && amd64PackedByteShiftRequiresEVEX(source, destination, byteWidth) {
			return true, false, fmt.Errorf("amd64 %s EVEX form requires an unsigned imm8: %q", raw, ins.Raw)
		}
		value, err := c.loadPackedCompareBytes(source, byteWidth)
		if err != nil {
			return true, false, err
		}
		result := c.emitPackedByteShift(byteWidth, value, uint8(ins.Args[0].Imm), left)
		return true, false, c.storeVectorBytes(destination.Reg, byteWidth, result)
	default:
		return false, false, nil
	}
}

func amd64SignedImmediate(operand Operand, bits int) bool {
	if operand.Kind != OpImm || bits <= 0 || bits >= 63 {
		return false
	}
	limit := int64(1) << (bits - 1)
	return operand.Imm >= -limit && operand.Imm < limit
}

func amd64VectorByteShiftImmediate(operand Operand) bool {
	return operand.Kind == OpImm && operand.Imm >= -128 && operand.Imm <= 255
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
