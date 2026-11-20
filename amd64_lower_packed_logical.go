package plan9asm

import "fmt"

type amd64PackedLogicalMode uint8

const (
	amd64PackedLogicalAnd amd64PackedLogicalMode = iota
	amd64PackedLogicalAndNot
	amd64PackedLogicalOr
	amd64PackedLogicalXor
)

type amd64PackedLogicalSpec struct {
	laneBits int
	mode     amd64PackedLogicalMode
}

// Compatibility helper entry points all use the same dispatch identity and
// complete typed grammar; none has a separate permissive operand fallback.
func (c *amd64Ctx) lowerPackedFloatingLogical(op Op, ins Instr) (bool, bool, error) {
	return c.lowerPackedLogicalFamily(op, ins)
}

func (c *amd64Ctx) lowerEVEXPackedLogical(op Op, ins Instr) (bool, bool, error) {
	return c.lowerPackedLogicalFamily(op, ins)
}

func (c *amd64Ctx) lowerPackedAndNot(op Op, ins Instr) (bool, bool, error) {
	return c.lowerPackedLogicalFamily(op, ins)
}

func (c *amd64Ctx) emitPackedLogical(lanes int, spec amd64PackedLogicalSpec, first, second string) string {
	vectorType := fmt.Sprintf("<%d x i%d>", lanes, spec.laneBits)
	if spec.mode == amd64PackedLogicalAndNot {
		inverted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor %s %s, %s\n", inverted, vectorType, second, llvmSplatInteger(lanes, spec.laneBits, ^uint64(0)))
		second = "%" + inverted
	}
	result := c.newTmp()
	op := "and"
	switch spec.mode {
	case amd64PackedLogicalOr:
		op = "or"
	case amd64PackedLogicalXor:
		op = "xor"
	}
	fmt.Fprintf(c.b, "  %%%s = %s %s %s, %s\n", result, op, vectorType, second, first)
	return "%" + result
}

func (c *amd64Ctx) isGoEVEXVectorRegister(op Operand, byteWidth int) bool {
	return amd64GoPackedVectorMoveRegister(op, byteWidth, c.goarch)
}

func amd64VectorByteWidth(r Reg) int {
	switch {
	case isAMD64XReg(r):
		return 16
	case isAMD64YReg(r):
		return 32
	case isAMD64ZReg(r):
		return 64
	default:
		return 0
	}
}

func amd64VectorRegisterHasWidth(op Operand, byteWidth int) bool {
	return op.Kind == OpReg && amd64VectorByteWidth(op.Reg) == byteWidth
}

func (c *amd64Ctx) bitcastVectorBytesToIntegerLanes(byteWidth, lanes, laneBits int, value string) string {
	cast := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to <%d x i%d>\n", cast, byteWidth, value, lanes, laneBits)
	return "%" + cast
}

func (c *amd64Ctx) storeVectorBytes(dst Reg, byteWidth int, value string) error {
	switch byteWidth {
	case 16:
		return c.storeX(dst, value)
	case 32:
		return c.storeY(dst, value)
	case 64:
		return c.storeZ(dst, value)
	default:
		return fmt.Errorf("unsupported packed vector width %d", byteWidth)
	}
}
