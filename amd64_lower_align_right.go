package plan9asm

import (
	"fmt"
	"strings"
)

// lowerPackedAlignRight implements the complete Go 1.27 PALIGNR and
// VPALIGNR tables. Each 128-bit lane is formed from the first Plan 9 source
// as its low half and the second source (or the legacy destination) as its
// high half, then shifted right by the immediate byte count.
func (c *amd64Ctx) lowerPackedAlignRight(rawOp Op, ins Instr) (ok bool, terminated bool, err error) {
	raw := strings.ToUpper(string(rawOp))
	parts := strings.Split(raw, ".")
	baseOp := Op(parts[0])
	if baseOp != "PALIGNR" && baseOp != "VPALIGNR" {
		return false, false, nil
	}
	if len(parts) > 2 || len(parts) == 2 && parts[1] != "Z" {
		return true, false, fmt.Errorf("amd64 %s has a suffix outside Go 1.27's align-right tables: %q", baseOp, ins.Raw)
	}
	zeroing := len(parts) == 2

	if baseOp == "PALIGNR" {
		if zeroing {
			return true, false, fmt.Errorf("amd64 PALIGNR does not accept instruction suffixes: %q", ins.Raw)
		}
		if len(ins.Args) != 3 || !amd64UnsignedImmediate(ins.Args[0], 8) {
			return true, false, fmt.Errorf("amd64 PALIGNR expects $imm8, X/m128, X: %q", ins.Raw)
		}
		source, destination := ins.Args[1], ins.Args[2]
		if !c.isGoVEXVectorRegister(destination, 16, false) {
			return true, false, fmt.Errorf("amd64 PALIGNR destination is outside Go 1.27's X register class: %q", ins.Raw)
		}
		if !c.isGoVEXVectorRegister(source, 16, true) {
			return true, false, fmt.Errorf("amd64 PALIGNR source is outside Go 1.27's X/m128 class: %q", ins.Raw)
		}
		low, err := c.loadPackedCompareBytes(source, 16)
		if err != nil {
			return true, false, err
		}
		high, err := c.loadX(destination.Reg)
		if err != nil {
			return true, false, err
		}
		result := c.emitPackedAlignRightBytes(16, low, high, ins.Args[0].Imm)
		return true, false, c.storeX(destination.Reg, result)
	}

	// cmd/asm's 386 parser cannot represent VPALIGNR's four- and five-
	// operand spellings, even though the shared encoder table is present.
	if c.goarch == "386" {
		return true, false, fmt.Errorf("386 VPALIGNR is outside Go 1.27's accepted instruction forms: %q", ins.Raw)
	}
	masked := len(ins.Args) == 5
	if len(ins.Args) != 4 && !masked || !amd64UnsignedImmediate(ins.Args[0], 8) {
		return true, false, fmt.Errorf("amd64 VPALIGNR expects $imm8, X|Y|Z/mem, X|Y|Z, [K,] X|Y|Z: %q", ins.Raw)
	}
	if zeroing && !masked {
		return true, false, fmt.Errorf("amd64 VPALIGNR.Z requires a writemask: %q", ins.Raw)
	}
	destination := ins.Args[len(ins.Args)-1]
	byteWidth := amd64VectorByteWidth(destination.Reg)
	if destination.Kind != OpReg || byteWidth != 16 && byteWidth != 32 && byteWidth != 64 || !c.isGoEVEXVectorRegister(destination, byteWidth) {
		return true, false, fmt.Errorf("amd64 VPALIGNR destination is outside Go 1.27's X/Y/Z register classes: %q", ins.Raw)
	}
	first, second := ins.Args[1], ins.Args[2]
	if first.Kind == OpReg {
		if !c.isGoEVEXVectorRegister(first, byteWidth) {
			return true, false, fmt.Errorf("amd64 VPALIGNR first source must match its destination width: %q", ins.Raw)
		}
	} else if !isAMD64MemoryOperand(first) {
		return true, false, fmt.Errorf("amd64 VPALIGNR first source must be a vector register or memory: %q", ins.Raw)
	}
	if !c.isGoEVEXVectorRegister(second, byteWidth) {
		return true, false, fmt.Errorf("amd64 VPALIGNR second source must match its destination width: %q", ins.Raw)
	}

	maskValue := ""
	if masked {
		mask := ins.Args[3]
		maskIndex, validMask := amd64ParseKReg(mask.Reg)
		if mask.Kind != OpReg || !validMask || maskIndex == 0 {
			return true, false, fmt.Errorf("amd64 VPALIGNR masked form requires K1..K7: %q", ins.Raw)
		}
		maskValue, err = c.loadK(mask.Reg)
		if err != nil {
			return true, false, err
		}
	}
	low, err := c.loadPackedCompareBytes(first, byteWidth)
	if err != nil {
		return true, false, err
	}
	high, err := c.loadPackedCompareBytes(second, byteWidth)
	if err != nil {
		return true, false, err
	}
	result := c.emitPackedAlignRightBytes(byteWidth, low, high, ins.Args[0].Imm)
	if masked {
		old, err := c.loadPackedCompareBytes(destination, byteWidth)
		if err != nil {
			return true, false, err
		}
		result = amd64ApplyIntegerLaneMask(c, byteWidth, 8, result, old, maskValue, zeroing)
	}
	return true, false, c.storeVectorBytes(destination.Reg, byteWidth, result)
}

func amd64UnsignedImmediate(operand Operand, bits int) bool {
	if operand.Kind != OpImm || bits <= 0 || bits >= 63 {
		return false
	}
	return operand.Imm >= 0 && operand.Imm < int64(uint64(1)<<bits)
}

func (c *amd64Ctx) emitPackedAlignRightBytes(byteWidth int, low, high string, count int64) string {
	if count >= 32 {
		return "zeroinitializer"
	}
	result := "zeroinitializer"
	for laneBase := 0; laneBase < byteWidth; laneBase += 16 {
		for destinationByte := 0; destinationByte < 16; destinationByte++ {
			sourceByte := int64(destinationByte) + count
			if sourceByte >= 32 {
				continue
			}
			source := low
			if sourceByte >= 16 {
				source = high
				sourceByte -= 16
			}
			extracted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i8> %s, i32 %d\n", extracted, byteWidth, source, laneBase+int(sourceByte))
			inserted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i8> %s, i8 %%%s, i32 %d\n", inserted, byteWidth, result, extracted, laneBase+destinationByte)
			result = "%" + inserted
		}
	}
	return result
}
