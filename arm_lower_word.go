package plan9asm

import (
	"fmt"
	"math/bits"
)

type armRawVFPCompare struct {
	lhs       int
	rhs       int
	zeroRHS   bool
	bits      int
	condition string
}

func decodeARMRawVFPCompare(word uint32) (armRawVFPCompare, bool) {
	// VCMP/VCMPE.{F32,F64} Vd,Vm and Vd,#0 share this encoding shape.
	// E (quiet/signaling), precision, Vd, Vm, D/M extension bits, zero, and the
	// ARM condition field are the variable bits. For F32, D/M select the odd
	// half of a D register; for F64 they extend D0..D15 to D16..D31.
	const variable = uint32(0xf0000000 | 0x00400000 | 0x00010000 | 0x0000f000 | 0x00000100 | 0x00000080 | 0x00000020 | 0x0000000f)
	const base = uint32(0x0eb40a40)
	if word&^variable != base {
		return armRawVFPCompare{}, false
	}
	zero := word&(1<<16) != 0
	if zero && word&0x2f != 0 {
		return armRawVFPCompare{}, false
	}
	condition, ok := armRawCondition(word >> 28)
	if !ok {
		return armRawVFPCompare{}, false
	}
	bits := 32
	if word&(1<<8) != 0 {
		bits = 64
	}
	lhs := int((word >> 12) & 0xf)
	rhs := int(word & 0xf)
	if bits == 32 {
		lhs = lhs*2 + int((word>>22)&1)
		rhs = rhs*2 + int((word>>5)&1)
	} else {
		lhs += int((word>>22)&1) * 16
		rhs += int((word>>5)&1) * 16
	}
	return armRawVFPCompare{
		lhs:       lhs,
		rhs:       rhs,
		zeroRHS:   zero,
		bits:      bits,
		condition: condition,
	}, true
}

func armRawVFPBackingReg(number, bits int) Reg {
	if bits == 32 {
		number /= 2
	}
	return Reg(fmt.Sprintf("F%d", number))
}

func (c *armCtx) loadARMRawVFPRegValue(number, bits int) (string, error) {
	reg := armRawVFPBackingReg(number, bits)
	if bits == 64 || number%2 == 0 {
		return c.loadARMFloatRegValue(reg, bits)
	}
	wide, err := c.loadFReg(reg)
	if err != nil {
		return "", err
	}
	shifted := c.newTmp()
	narrow := c.newTmp()
	converted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = lshr i64 %s, 32\n", shifted, wide)
	fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", narrow, shifted)
	fmt.Fprintf(c.b, "  %%%s = bitcast i32 %%%s to float\n", converted, narrow)
	return "%" + converted, nil
}

func armRawCondition(value uint32) (string, bool) {
	conditions := []string{"EQ", "NE", "CS", "CC", "MI", "PL", "VS", "VC", "HI", "LS", "GE", "LT", "GT", "LE", "AL"}
	if value >= uint32(len(conditions)) {
		return "", false
	}
	return conditions[value], true
}

// lowerRawWord recognizes ARM instructions that older assembly used as raw
// encodings because the contemporary Go assembler could not spell them. Keep
// the decoder deliberately narrow: an unknown word remains an opaque directive.
func (c *armCtx) lowerRawWord(ins Instr) (bool, error) {
	if len(ins.Args) != 1 || ins.Args[0].Kind != OpImm {
		return false, nil
	}
	word := uint32(ins.Args[0].Imm)
	switch word {
	case 0xe320f001: // YIELD, encoded explicitly so it remains a NOP before ARMv6K.
		c.b.WriteString("  call void asm sideeffect \".long 0xe320f001\", \"~{memory}\"()\n")
		return true, nil
	}
	if immediate, ok := decodeARMRawVFPImmediate(word); ok {
		return true, c.lowerRawVFPImmediate(immediate)
	}
	if compare, ok := decodeARMRawVFPCompare(word); ok {
		lhs, err := c.loadARMRawVFPRegValue(compare.lhs, compare.bits)
		if err != nil {
			return true, err
		}
		rhs := "0.000000e+00"
		if !compare.zeroRHS {
			rhs, err = c.loadARMRawVFPRegValue(compare.rhs, compare.bits)
			if err != nil {
				return true, err
			}
		}
		floatType := "float"
		if compare.bits == 64 {
			floatType = "double"
		}
		return true, c.setARMFloatCompareFlags(lhs, rhs, floatType, compare.condition)
	}
	if word>>28 != 0xe || word&(3<<26) != 0 || (word>>21)&0xf != 8 || word&(1<<20) == 0 {
		return false, nil
	}
	rn := Reg(fmt.Sprintf("R%d", (word>>16)&0xf))
	operand2 := word & 0xfff
	var src Operand
	if word&(1<<25) != 0 {
		rotate := int(((operand2 >> 8) & 0xf) * 2)
		value := bits.RotateLeft32(operand2&0xff, -rotate)
		src = Operand{Kind: OpImm, Imm: int64(value)}
	} else {
		if operand2&0xff0 != 0 {
			return false, nil
		}
		src = Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("R%d", operand2&0xf))}
	}
	decoded := Instr{
		Op:   "TST",
		Args: []Operand{src, {Kind: OpReg, Reg: rn}},
		Raw:  ins.Raw,
	}
	return true, c.lowerARMCompare("TST", decoded)
}
