package plan9asm

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// lowerScalarFloatMove implements the full Go 1.27 FMOVS/FMOVD shape family:
// floating constants, F<->F, general/zero-register<->F, and F<->memory for
// stack, symbol, immediate-offset, register-offset, post-index, and pre-index
// addresses.
func (c *arm64Ctx) lowerScalarFloatMove(op Op, ins Instr) (ok bool, terminated bool, err error) {
	bits := 64
	switch op {
	case "FMOVB":
		bits = 8
	case "FMOVH":
		bits = 16
	case "FMOVS":
		bits = 32
	}
	rawOp := strings.ToUpper(string(ins.Op))
	postIndex := false
	preIndex := false
	switch rawOp {
	case string(op):
	case string(op) + ".P":
		postIndex = true
	case string(op) + ".W":
		preIndex = true
	default:
		return true, false, fmt.Errorf("arm64 %s accepts only .P or .W memory suffixes: %q", op, ins.Raw)
	}
	if len(ins.Args) != 2 {
		return true, false, fmt.Errorf("arm64 %s expects exactly 2 operands: %q", op, ins.Raw)
	}
	src, dst := ins.Args[0], ins.Args[1]
	srcF := src.Kind == OpReg && isARM64FReg(src.Reg)
	dstF := dst.Kind == OpReg && isARM64FReg(dst.Reg)
	srcGP := src.Kind == OpReg && isARM64GeneralOrZeroReg(src.Reg)
	dstGP := dst.Kind == OpReg && isARM64GeneralOrZeroReg(dst.Reg)
	srcMem := isARM64ScalarFloatMemory(src)
	dstMem := isARM64ScalarFloatMemory(dst)

	valid := false
	switch {
	case src.Kind == OpImm:
		valid = dstF
	case srcF:
		valid = dstF || dstGP || dstMem
	case srcGP:
		valid = dstF
	case srcMem:
		valid = dstF
	}
	if !valid {
		return true, false, fmt.Errorf("arm64 %s operands are absent from the Go 1.27 optab: %q", op, ins.Raw)
	}

	indexedMemory := Operand{}
	if src.Kind == OpMem {
		indexedMemory = src
	} else if dst.Kind == OpMem {
		indexedMemory = dst
	}
	if postIndex || preIndex {
		if indexedMemory.Kind != OpMem || indexedMemory.Mem.Index != "" {
			return true, false, fmt.Errorf("arm64 %s .P/.W requires one immediate-offset register memory operand: %q", op, ins.Raw)
		}
	}

	var value string
	switch {
	case src.Kind == OpImm:
		value, err = arm64FloatImmediateBits(src, bits)
	case srcF || srcGP:
		value, err = c.loadReg(src.Reg)
	case srcMem:
		value, err = c.loadScalarFloatMemory(src, bits, postIndex, preIndex)
	}
	if err != nil {
		return true, false, err
	}
	value = c.normalizeScalarFloatBits(value, bits)

	switch {
	case dstF || dstGP:
		err = c.storeReg(dst.Reg, value)
	case dstMem:
		err = c.storeScalarFloatMemory(dst, bits, postIndex, preIndex, value)
	}
	return true, false, err
}

func isARM64FReg(r Reg) bool {
	_, ok := arm64ParseFReg(r)
	return ok
}

func isARM64GeneralOrZeroReg(r Reg) bool {
	if r == ZR {
		return true
	}
	s := strings.ToUpper(strings.TrimSpace(string(r)))
	if !strings.HasPrefix(s, "R") {
		return false
	}
	n, err := strconv.Atoi(strings.TrimPrefix(s, "R"))
	return err == nil && n >= 0 && n <= 30
}

func isARM64ScalarFloatMemory(op Operand) bool {
	switch op.Kind {
	case OpFP, OpMem, OpSym:
		return op.Kind != OpSym || !strings.HasPrefix(strings.TrimSpace(op.Sym), "$")
	default:
		return false
	}
}

func arm64FloatImmediateBits(op Operand, bits int) (string, error) {
	if op.ImmRaw != "" {
		return "", fmt.Errorf("arm64: unresolved floating immediate %s", op.String())
	}
	if op.Imm == 0 {
		return "0", nil
	}
	value := math.Float64frombits(uint64(op.Imm))
	if bits == 32 {
		return strconv.FormatUint(uint64(math.Float32bits(float32(value))), 10), nil
	}
	return strconv.FormatUint(uint64(op.Imm), 10), nil
}

func (c *arm64Ctx) normalizeScalarFloatBits(value string, bits int) string {
	if bits == 64 {
		return value
	}
	narrow := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i%d\n", narrow, value, bits)
	wide := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext i%d %%%s to i64\n", wide, bits, narrow)
	return "%" + wide
}

func (c *arm64Ctx) loadScalarFloatMemory(op Operand, bits int, postIndex, preIndex bool) (string, error) {
	switch op.Kind {
	case OpFP:
		return c.evalFPValue64(op)
	case OpSym:
		ptr, err := c.ptrFromSB(op.Sym)
		if err != nil {
			return "", err
		}
		loaded := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load i%d, ptr %s, align 1\n", loaded, bits, ptr)
		if bits == 64 {
			return "%" + loaded, nil
		}
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i%d %%%s to i64\n", wide, bits, loaded)
		return "%" + wide, nil
	case OpMem:
		value, err := c.loadMem(op.Mem, bits, postIndex)
		if err != nil {
			return "", err
		}
		if preIndex {
			if err := c.updatePostInc(op.Mem.Base, op.Mem.Off); err != nil {
				return "", err
			}
		}
		return value, nil
	default:
		return "", fmt.Errorf("arm64: unsupported scalar floating load %s", op.String())
	}
}

func (c *arm64Ctx) storeScalarFloatMemory(op Operand, bits int, postIndex, preIndex bool, value string) error {
	switch op.Kind {
	case OpFP:
		return c.storeFPResult64(op.FPOffset, value)
	case OpSym:
		ptr, err := c.ptrFromSB(op.Sym)
		if err != nil {
			return err
		}
		if bits == 64 {
			fmt.Fprintf(c.b, "  store i64 %s, ptr %s, align 1\n", value, ptr)
			return nil
		}
		narrow := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i%d\n", narrow, value, bits)
		fmt.Fprintf(c.b, "  store i%d %%%s, ptr %s, align 1\n", bits, narrow, ptr)
		return nil
	case OpMem:
		if err := c.storeMem(op.Mem, bits, postIndex, value); err != nil {
			return err
		}
		if preIndex {
			return c.updatePostInc(op.Mem.Base, op.Mem.Off)
		}
		return nil
	default:
		return fmt.Errorf("arm64: unsupported scalar floating store %s", op.String())
	}
}
