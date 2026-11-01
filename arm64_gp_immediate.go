package plan9asm

import (
	"fmt"
	"strings"
)

type arm64GPImmediateForm struct {
	left, destination Operand
	value             uint64
	operation         string
	word, flags       bool
	compare, scratch  bool
	trailingUDF       bool
}

// The ADD/AND/CMP/TST optabs select cases 2/48/53 or materialize the
// immediate in R27 in cases 13/28/62. Register classes affect that choice:
// a ZR CMP input and a non-flag logical ZR destination require the fallback.
func parseARM64GPImmediateForm(op Op, ins Instr) (f arm64GPImmediateForm, handled bool, err error) {
	if ins.arm64Encoded {
		return f, false, nil
	}
	base := strings.TrimSuffix(string(op), "W")
	switch base {
	case "ADD", "ADDS", "SUB", "SUBS", "CMP", "CMN", "AND", "ANDS", "BIC", "BICS", "ORR", "ORN", "EOR", "EON", "TST":
	default:
		return f, false, nil
	}
	if len(ins.Args) == 0 || ins.Args[0].Kind != OpImm {
		return f, false, nil
	}
	invalid := func() (arm64GPImmediateForm, bool, error) {
		return f, true, fmt.Errorf("arm64 %s immediate is outside its Go GP encoder rows: %q", op, ins.Raw)
	}
	f.word = strings.HasSuffix(string(op), "W")
	f.compare = base == "CMP" || base == "CMN" || base == "TST"
	f.flags = f.compare || base == "ADDS" || base == "SUBS" || base == "ANDS" || base == "BICS"
	if string(ins.Op) != string(op) || len(ins.Args) != 2 && (f.compare || len(ins.Args) != 3) ||
		ins.Args[0].ImmRaw != "" || ins.Args[0].ImmIsFloat {
		return invalid()
	}
	f.value = uint64(ins.Args[0].Imm)
	if f.word {
		f.value = uint64(uint32(f.value))
	}
	f.left = ins.Args[1]
	if !f.compare {
		f.destination = ins.Args[len(ins.Args)-1]
		if f.destination.Kind != OpReg || !arm64AddressReg(f.destination.Reg) && f.destination.Reg != ZR {
			return invalid()
		}
	}
	if f.left.Kind != OpReg || !arm64AddressReg(f.left.Reg) && f.left.Reg != ZR {
		return invalid()
	}
	add := base == "ADD" || base == "ADDS" || base == "SUB" || base == "SUBS" || base == "CMP" || base == "CMN"
	bitmask := f.value
	if f.word {
		bitmask *= 0x100000001
	}
	logicalImmediate := arm64LogicalBitmaskImmediate(bitmask)
	if add {
		f.operation = "add"
		if base == "SUB" || base == "SUBS" || base == "CMP" {
			f.operation = "sub"
		}
		if !f.compare && (f.left.Reg == ZR || f.destination.Reg == ZR || f.flags && arm64StackReg(f.destination.Reg)) {
			return invalid()
		}
		value := int64(f.value)
		addImmediate := value >= 0 && (value <= 0xfff || value&0xfff == 0 && value>>12 <= 0xfff)
		movImmediate := arm64GPImmediateMoveWide(f.value, f.word)
		splitImmediate := value >= 0 && value <= 0xffffff && !movImmediate && !logicalImmediate
		f.scratch = f.left.Reg == ZR || !addImmediate && !(splitImmediate && !f.flags)
		// X case 13's MOV-wide expansion rejects all-zero/all-one values;
		// W case 13 emits its two MOV words even for those values.
		if f.compare && (f.left.Reg == ZR && !f.word && (f.value == 0 || f.value == ^uint64(0)) ||
			arm64StackReg(f.left.Reg) && f.scratch && !movImmediate && !logicalImmediate) {
			return invalid()
		}
		// The X CMP/CMN ZR fallback has a fixed three-word case-13
		// width. A one-word MOV-wide materialization leaves its last word
		// zero after the compare: that is a reachable UDF, not padding.
		f.trailingUDF = f.compare && f.left.Reg == ZR && !f.word && movImmediate
	} else {
		f.operation = "and"
		if base == "ORR" || base == "ORN" {
			f.operation = "or"
		} else if base == "EOR" || base == "EON" {
			f.operation = "xor"
		}
		if arm64StackReg(f.left.Reg) || !f.compare && arm64StackReg(f.destination.Reg) &&
			(f.flags || len(ins.Args) != 3 || !logicalImmediate) {
			return invalid()
		}
		f.scratch = !logicalImmediate || !f.compare && !f.flags && f.destination.Reg == ZR
		// C_ABCON (>12-bit shifted ADDCON and also a logical mask) is
		// not compatible with MOVCON. A nonflag ZR destination therefore
		// selects case 28's three-word fallback instead of case 62.
		value := int64(f.value)
		f.trailingUDF = !f.word && !f.compare && !f.flags && f.destination.Reg == ZR &&
			logicalImmediate && value > 0xfff && value&0xfff == 0 && value>>12 <= 0xfff &&
			arm64GPImmediateMoveWide(f.value, false)
	}
	if f.scratch && f.left.Reg == "R27" && (f.compare || len(ins.Args) == 3) {
		return invalid() // Go diagnoses an explicit REGTMP source before encoding.
	}
	zeroFallback := f.compare && add && f.left.Reg == ZR || !f.compare && !f.flags && f.destination.Reg == ZR
	if !f.word && zeroFallback && logicalImmediate && arm64GPImmediateLegacyMoves(f.value) > 2 {
		// Go 1.20's fixed case-13/28 width can truncate the MOV sequence
		// before the operation. Newer Go encoders use ORR-mask+MOVK. Source
		// encoder identity is not part of the current public transport;
		// neither library-build Go version nor opcode spelling supplies it.
		return f, true, fmt.Errorf("%w: arm64 %s ZR fallback needs its original Go constant encoder", ErrProbeNeedsContext, op)
	}
	return f, true, nil
}

func arm64GPImmediateLegacyMoves(value uint64) int {
	zero, ones := 0, 0
	for shift := uint(0); shift < 64; shift += 16 {
		switch uint16(value >> shift) {
		case 0:
			zero++
		case 0xffff:
			ones++
		}
	}
	if ones > zero {
		zero = ones
	}
	return 4 - zero
}

func arm64GPImmediateMoveWide(value uint64, word bool) bool {
	inverted := ^value
	if word {
		inverted = uint64(uint32(inverted))
	}
	for shift := uint(0); shift < 64; shift += 16 {
		mask := uint64(0xffff) << shift
		if value&^mask == 0 || inverted&^mask == 0 {
			return true
		}
	}
	return false
}

func (c *arm64Ctx) lowerARM64GPImmediate(op Op, ins Instr) (bool, bool, error) {
	f, handled, err := parseARM64GPImmediateForm(op, ins)
	if !handled || err != nil {
		return handled, false, err
	}
	if f.scratch {
		if err := c.storeReg("R27", c.imm64(int64(f.value))); err != nil {
			return true, false, err
		}
	}
	var left string
	typeName, right := "i64", c.imm64(int64(f.value))
	if f.word {
		left, err = c.eval32(f.left)
		typeName, right = "i32", fmt.Sprint(uint32(f.value))
	} else {
		left, err = c.eval64(f.left, false)
	}
	if err != nil {
		return true, false, err
	}
	base := strings.TrimSuffix(string(op), "W")
	if base == "BIC" || base == "BICS" || base == "ORN" || base == "EON" {
		inverted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor %s %s, -1\n", inverted, typeName, right)
		right = "%" + inverted
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s %s %s, %s\n", result, f.operation, typeName, left, right)
	if f.flags {
		if f.operation == "add" {
			if f.word {
				c.setFlagsAdd32(left, right, "%"+result)
			} else {
				c.setFlagsAdd(left, right, "%"+result)
			}
		} else if f.operation == "sub" {
			if f.word {
				c.setFlagsSub32(left, right, "%"+result)
			} else {
				c.setFlagsSub(left, right, "%"+result)
			}
		} else if f.word {
			c.setFlagsLogic32("%" + result)
		} else {
			c.setFlagsLogic("%" + result)
		}
	}
	if f.compare {
		return c.finishARM64GPImmediate(f)
	}
	value := "%" + result
	if f.word {
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", wide, value)
		value = "%" + wide
	}
	if err := c.storeReg(f.destination.Reg, value); err != nil {
		return true, false, err
	}
	return c.finishARM64GPImmediate(f)
}

func (c *arm64Ctx) finishARM64GPImmediate(f arm64GPImmediateForm) (bool, bool, error) {
	if f.trailingUDF {
		c.emitARM64Exception("udf", 0)
		c.b.WriteString("  unreachable\n")
		return true, true, nil
	}
	return true, false, nil
}
