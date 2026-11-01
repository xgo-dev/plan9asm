package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
)

// lowerARM64FloatPair implements the single floating-point register-pair
// family described by Go 1.27's arm64 optab: FLDPS/FLDPD/FLDPQ and
// FSTPS/FSTPD/FSTPQ, including ordinary, pre-indexed, and post-indexed memory.
func (c *arm64Ctx) lowerARM64FloatPair(op Op, ins Instr) (ok bool, terminated bool, err error) {
	elementBytes := map[Op]int{
		"FLDPS": 4, "FSTPS": 4,
		"FLDPD": 8, "FSTPD": 8,
		"FLDPQ": 16, "FSTPQ": 16,
	}[op]
	if elementBytes == 0 {
		return false, false, nil
	}

	rawOp := strings.ToUpper(string(ins.Op))
	preIndex, postIndex := false, false
	switch rawOp {
	case string(op):
	case string(op) + ".W":
		preIndex = true
	case string(op) + ".P":
		postIndex = true
	default:
		return true, false, fmt.Errorf("arm64 %s accepts only .P or .W memory suffixes: %q", op, ins.Raw)
	}

	load := strings.HasPrefix(string(op), "FLDP")
	if len(ins.Args) != 2 {
		return true, false, fmt.Errorf("arm64 %s expects exactly 2 operands: %q", op, ins.Raw)
	}
	memory, pair := ins.Args[0], ins.Args[1]
	if !load {
		pair, memory = ins.Args[0], ins.Args[1]
	}
	if pair.Kind != OpRegList || len(pair.RegList) != 2 {
		return true, false, fmt.Errorf("arm64 %s expects a pair of floating-point registers: %q", op, ins.Raw)
	}
	for _, reg := range pair.RegList {
		if _, valid := arm64ParseFReg(reg); !valid {
			return true, false, fmt.Errorf("arm64 %s expects a pair of floating-point registers: %q", op, ins.Raw)
		}
	}
	if load && pair.RegList[0] == pair.RegList[1] {
		return true, false, fmt.Errorf("arm64 %s destination pair has constrained unpredictable behavior: %q", op, ins.Raw)
	}

	ptr, base, increment, update, err := c.arm64FloatPairMemoryPointer(memory, elementBytes, preIndex, postIndex)
	if err != nil {
		return true, false, fmt.Errorf("arm64 %s: %w: %q", op, err, ins.Raw)
	}
	for index, reg := range pair.RegList {
		elementPtr := ptr
		if index != 0 {
			next := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = getelementptr i8, ptr %s, i64 %d\n", next, ptr, elementBytes)
			elementPtr = "%" + next
		}
		if load {
			if err := c.loadARM64FloatPairElement(reg, elementPtr, elementBytes); err != nil {
				return true, false, err
			}
		} else if err := c.storeARM64FloatPairElement(reg, elementPtr, elementBytes); err != nil {
			return true, false, err
		}
	}
	if update {
		if err := c.updatePostInc(base, increment); err != nil {
			return true, false, err
		}
	}
	return true, false, nil
}

func (c *arm64Ctx) arm64FloatPairMemoryPointer(op Operand, elementBytes int, preIndex, postIndex bool) (ptr string, base Reg, increment int64, update bool, err error) {
	if preIndex && postIndex {
		return "", "", 0, false, fmt.Errorf("memory operand cannot be both pre- and post-indexed")
	}
	if op.Kind == OpSym {
		if preIndex || postIndex {
			return "", "", 0, false, fmt.Errorf("symbol operand cannot be pre- or post-indexed")
		}
		ptr, err := c.ptrFromSB(op.Sym)
		return ptr, "", 0, false, err
	}
	if op.Kind != OpMem {
		return "", "", 0, false, fmt.Errorf("expected a memory operand")
	}
	if op.Mem.Index != "" {
		return "", "", 0, false, fmt.Errorf("register-indexed memory is absent from the Go 1.27 floating pair optab")
	}
	if !isARM64FloatPairMemoryBase(op.Mem.Base) {
		return "", "", 0, false, fmt.Errorf("memory base must be R0-R30, RSP, SP, or ZR")
	}
	if preIndex || postIndex {
		limit := int64(64*elementBytes - elementBytes)
		if op.Mem.Off < -int64(64*elementBytes) || op.Mem.Off > limit || op.Mem.Off%int64(elementBytes) != 0 {
			return "", "", 0, false, fmt.Errorf("pre/post-index offset %d must be aligned to %d and in [%d,%d]", op.Mem.Off, elementBytes, -64*elementBytes, limit)
		}
	}
	addr, base, increment, err := c.addrI64(op.Mem, postIndex)
	if err != nil {
		return "", "", 0, false, err
	}
	if preIndex {
		if err := c.storeReg(base, addr); err != nil {
			return "", "", 0, false, err
		}
	}
	name := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", name, addr)
	return "%" + name, base, increment, postIndex, nil
}

func isARM64FloatPairMemoryBase(reg Reg) bool {
	if reg == SP || reg == Reg("RSP") || reg == ZR {
		return true
	}
	s := strings.ToUpper(strings.TrimSpace(string(reg)))
	if !strings.HasPrefix(s, "R") {
		return false
	}
	n, err := strconv.Atoi(strings.TrimPrefix(s, "R"))
	return err == nil && n >= 0 && n <= 30
}

func (c *arm64Ctx) loadARM64FloatPairElement(reg Reg, ptr string, elementBytes int) error {
	if elementBytes == 16 {
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load <16 x i8>, ptr %s, align 1\n", value, ptr)
		return c.storeVReg(reg, "%"+value)
	}
	bits := elementBytes * 8
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i%d, ptr %s, align 1\n", value, bits, ptr)
	value64 := "%" + value
	if bits != 64 {
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i%d %%%s to i64\n", wide, bits, value)
		value64 = "%" + wide
	}
	return c.storeReg(reg, value64)
}

func (c *arm64Ctx) storeARM64FloatPairElement(reg Reg, ptr string, elementBytes int) error {
	if elementBytes == 16 {
		value, err := c.loadVReg(reg)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store <16 x i8> %s, ptr %s, align 1\n", value, ptr)
		return nil
	}
	value, err := c.loadReg(reg)
	if err != nil {
		return err
	}
	bits := elementBytes * 8
	if bits == 64 {
		fmt.Fprintf(c.b, "  store i64 %s, ptr %s, align 1\n", value, ptr)
		return nil
	}
	narrow := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i%d\n", narrow, value, bits)
	fmt.Fprintf(c.b, "  store i%d %%%s, ptr %s, align 1\n", bits, narrow, ptr)
	return nil
}
