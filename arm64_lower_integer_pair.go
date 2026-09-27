package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) lowerARM64IntegerPair(op Op, ins Instr) (ok bool, terminated bool, err error) {
	switch op {
	case "LDP", "LDPW", "LDPSW", "STP", "STPW":
	default:
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
		return true, false, fmt.Errorf("arm64 %s accepts only .W or .P memory suffixes: %q", op, ins.Raw)
	}
	if len(ins.Args) != 2 {
		return true, false, fmt.Errorf("arm64 %s expects exactly 2 operands: %q", op, ins.Raw)
	}
	load := strings.HasPrefix(string(op), "LDP")
	memory, pair := ins.Args[0], ins.Args[1]
	if !load {
		pair, memory = ins.Args[0], ins.Args[1]
	}
	if pair.Kind != OpRegList || len(pair.RegList) != 2 {
		return true, false, fmt.Errorf("arm64 %s expects a pair of general registers: %q", op, ins.Raw)
	}
	for _, reg := range pair.RegList {
		if !isARM64GeneralOrZeroReg(reg) {
			return true, false, fmt.Errorf("arm64 %s expects a pair of general registers: %q", op, ins.Raw)
		}
	}
	if memory.Kind == OpFP {
		if op != "LDP" || preIndex || postIndex {
			return true, false, fmt.Errorf("arm64 %s does not support this FP-relative pair form: %q", op, ins.Raw)
		}
		// Preserve the established ABI-frame behavior: the first register
		// receives the modeled frame slot and the unavailable adjacent slot is
		// materialized as zero.
		value, err := c.eval64(memory, false)
		if err != nil {
			return true, false, err
		}
		if err := c.storeReg(pair.RegList[0], value); err != nil {
			return true, false, err
		}
		return true, false, c.storeReg(pair.RegList[1], "0")
	}
	ptr, base, increment, update, err := c.arm64IntegerPairPointer(memory, preIndex, postIndex)
	if err != nil {
		return true, false, fmt.Errorf("arm64 %s: %w: %q", op, err, ins.Raw)
	}
	elementBytes := 8
	if op == "LDPW" || op == "LDPSW" || op == "STPW" {
		elementBytes = 4
	}
	for index, reg := range pair.RegList {
		elementPtr := ptr
		if index != 0 {
			next := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = getelementptr i8, ptr %s, i64 %d\n", next, ptr, elementBytes)
			elementPtr = "%" + next
		}
		if load {
			if err := c.loadARM64IntegerPairElement(reg, elementPtr, elementBytes, op == "LDPSW"); err != nil {
				return true, false, err
			}
		} else if err := c.storeARM64IntegerPairElement(reg, elementPtr, elementBytes); err != nil {
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

func (c *arm64Ctx) arm64IntegerPairPointer(operand Operand, preIndex, postIndex bool) (ptr string, base Reg, increment int64, update bool, err error) {
	if operand.Kind == OpSym {
		if preIndex || postIndex {
			return "", "", 0, false, fmt.Errorf("symbol operand cannot be pre- or post-indexed")
		}
		ptr, err := c.ptrFromSB(operand.Sym)
		return ptr, "", 0, false, err
	}
	if operand.Kind != OpMem {
		return "", "", 0, false, fmt.Errorf("expected a memory operand")
	}
	if operand.Mem.Index != "" {
		return "", "", 0, false, fmt.Errorf("register-indexed memory is absent from the Go 1.27 integer-pair optab")
	}
	if !isARM64FloatPairMemoryBase(operand.Mem.Base) {
		return "", "", 0, false, fmt.Errorf("memory base must be R0-R30, RSP, SP, or ZR")
	}
	addr, base, increment, err := c.addrI64(operand.Mem, postIndex)
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

func (c *arm64Ctx) loadARM64IntegerPairElement(reg Reg, ptr string, elementBytes int, signed bool) error {
	bits := elementBytes * 8
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i%d, ptr %s, align 1\n", value, bits, ptr)
	result := "%" + value
	if bits == 32 {
		wide := c.newTmp()
		extension := "zext"
		if signed {
			extension = "sext"
		}
		fmt.Fprintf(c.b, "  %%%s = %s i32 %%%s to i64\n", wide, extension, value)
		result = "%" + wide
	}
	return c.storeReg(reg, result)
}

func (c *arm64Ctx) storeARM64IntegerPairElement(reg Reg, ptr string, elementBytes int) error {
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
	fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", narrow, value)
	fmt.Fprintf(c.b, "  store i32 %%%s, ptr %s, align 1\n", narrow, ptr)
	return nil
}
