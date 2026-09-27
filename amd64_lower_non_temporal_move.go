package plan9asm

import (
	"fmt"
	"strings"
)

// lowerNonTemporalVectorMove implements Go 1.27's complete vector
// non-temporal move family. The VEX/EVEX store table is shared by VMOVNTDQ,
// VMOVNTPD, and VMOVNTPS and accepts X/Y/Z register-to-memory forms. Its
// VMOVNTDQA counterpart accepts the inverse memory-to-X/Y/Z forms. The legacy
// instructions are the same directions at X width; Go spells MOVNTDQ as
// MOVNTO so that VMOVNTDQ remains available for the VEX/EVEX instruction.
func (c *amd64Ctx) lowerNonTemporalVectorMove(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	vectorStore, vectorLoad := false, false
	legacyStore := false
	switch baseOp {
	case "VMOVNTDQ", "VMOVNTPD", "VMOVNTPS":
		vectorStore = true
	case "VMOVNTDQA":
		vectorLoad = true
	case "MOVNTO", "MOVNTPD", "MOVNTPS":
		legacyStore = true
	case "MOVNTDQA":
	default:
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("%s %s has no suffixed forms in Go 1.27's non-temporal vector-move tables: %q", c.goarch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 2 {
		return true, false, fmt.Errorf("%s %s expects exactly two operands: %q", c.goarch, baseOp, ins.Raw)
	}

	if vectorStore {
		source, destination := ins.Args[0], ins.Args[1]
		byteWidth := 0
		if source.Kind == OpReg {
			byteWidth = amd64VectorByteWidth(source.Reg)
		}
		if byteWidth == 0 || !c.isGoPackedVectorMoveRegister(source, byteWidth) {
			return true, false, fmt.Errorf("%s %s source must be an in-range X, Y, or Z register: %q", c.goarch, baseOp, ins.Raw)
		}
		if !isAMD64MemoryOperand(destination) {
			return true, false, fmt.Errorf("%s %s destination must be memory: %q", c.goarch, baseOp, ins.Raw)
		}
		value, loadErr := c.loadPackedCompareBytes(source, byteWidth)
		if loadErr != nil {
			return true, false, loadErr
		}
		return true, false, c.storeVectorBytesOperandWithMetadata(destination, byteWidth, value, x86NonTemporalMetadata)
	}

	if vectorLoad {
		source, destination := ins.Args[0], ins.Args[1]
		if !isAMD64MemoryOperand(source) || destination.Kind != OpReg {
			return true, false, fmt.Errorf("%s %s expects a memory source and X, Y, or Z destination: %q", c.goarch, baseOp, ins.Raw)
		}
		byteWidth := amd64VectorByteWidth(destination.Reg)
		if byteWidth == 0 || !c.isGoPackedVectorMoveRegister(destination, byteWidth) {
			return true, false, fmt.Errorf("%s %s destination must be an in-range X, Y, or Z register: %q", c.goarch, baseOp, ins.Raw)
		}
		value, loadErr := c.loadPackedCompareBytes(source, byteWidth)
		if loadErr != nil {
			return true, false, loadErr
		}
		return true, false, c.storeVectorBytesOperand(destination, byteWidth, value)
	}

	if legacyStore {
		source, destination := ins.Args[0], ins.Args[1]
		if !c.isGoLegacyNonTemporalVectorRegister(source) || !isAMD64MemoryOperand(destination) {
			return true, false, fmt.Errorf("%s %s expects an in-range X source and memory destination: %q", c.goarch, baseOp, ins.Raw)
		}
		value, loadErr := c.loadPackedCompareBytes(source, 16)
		if loadErr != nil {
			return true, false, loadErr
		}
		return true, false, c.storeVectorBytesOperandWithMetadata(destination, 16, value, x86NonTemporalMetadata)
	}

	source, destination := ins.Args[0], ins.Args[1]
	if !isAMD64MemoryOperand(source) || !c.isGoLegacyNonTemporalVectorRegister(destination) {
		return true, false, fmt.Errorf("%s %s expects a memory source and in-range X destination: %q", c.goarch, baseOp, ins.Raw)
	}
	value, loadErr := c.loadPackedCompareBytes(source, 16)
	if loadErr != nil {
		return true, false, loadErr
	}
	return true, false, c.storeVectorBytesOperand(destination, 16, value)
}

func (c *amd64Ctx) isGoLegacyNonTemporalVectorRegister(operand Operand) bool {
	if !amd64VEXVectorRegister(operand, 16) {
		return false
	}
	index, _ := amd64ParseXReg(operand.Reg)
	return c.goarch != "386" || index < 8
}
