package plan9asm

import (
	"fmt"
	"strings"
)

type x86DecimalKind uint8

const (
	x86DecimalASCIIAdjust x86DecimalKind = iota
	x86DecimalPackedAdjust
	x86DecimalMergeDigits
	x86DecimalSplitDigits
)

type x86DecimalSpec struct {
	kind     x86DecimalKind
	subtract bool
}

// Go's IA-32 encoder admits only zero-operand names. The two radix
// instructions encode base ten in named form and retain the byte in raw form.
var x86DecimalSpecs = map[Op]x86DecimalSpec{
	"AAA": {kind: x86DecimalASCIIAdjust},
	"AAS": {kind: x86DecimalASCIIAdjust, subtract: true},
	"DAA": {kind: x86DecimalPackedAdjust},
	"DAS": {kind: x86DecimalPackedAdjust, subtract: true},
	"AAD": {kind: x86DecimalMergeDigits},
	"AAM": {kind: x86DecimalSplitDigits},
}

type x86DecimalForm struct {
	spec  x86DecimalSpec
	radix int64
}

func x86DecimalProperties(op Op, ins Instr, arch string) (x86DecimalForm, bool, error) {
	name, _, suffix := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := x86DecimalSpecs[Op(name)]
	form := x86DecimalForm{spec: spec, radix: 10}
	if !known {
		return form, false, nil
	}
	if arch != "386" || suffix || !strings.EqualFold(string(ins.Op), name) {
		return form, true, fmt.Errorf("%s %s requires the exact 386 opcode without a suffix: %q", arch, op, ins.Raw)
	}
	if len(ins.Args) == 0 {
		return form, true, nil
	}
	origin := ins.x86SourceRaw
	if (spec.kind == x86DecimalMergeDigits || spec.kind == x86DecimalSplitDigits) &&
		len(ins.Args) == 1 && origin != nil && origin.op == ins.Op && len(origin.args) == 1 {
		arg, original := ins.Args[0], origin.args[0]
		if arg.Kind == OpImm && original.Kind == OpImm && arg.Imm == original.Imm &&
			arg.ImmRaw == "" && !arg.ImmIsFloat && arg.Imm >= 0 && arg.Imm <= 255 {
			form.radix = arg.Imm
			return form, true, nil
		}
	}
	return form, true, fmt.Errorf("%s %s expects no named operands: %q", arch, op, ins.Raw)
}

func x86TypedDecimalEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	form, known, err := x86DecimalProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	effect := x86TypedByteEffect{requiresResultProof: true, flagsKilled: x86ByteFlagsAll}
	if form.divideError() {
		return effect, true, nil
	}
	ax := Operand{Kind: OpReg, Reg: AX}
	al := Operand{Kind: OpReg, Reg: AL}
	effect.flagsDefined = x86ByteFlagSF | x86ByteFlagZF | x86ByteFlagPF
	switch form.spec.kind {
	case x86DecimalASCIIAdjust:
		effect.flagsRead = x86ByteFlagAF
		effect.flagsDefined = x86ByteFlagAF | x86ByteFlagCF
		effect.operands = []x86TypedByteOperand{{index: -1, operand: ax, width: 2, read: true, write: true}}
	case x86DecimalPackedAdjust:
		effect.flagsRead = x86ByteFlagAF | x86ByteFlagCF
		effect.flagsDefined |= effect.flagsRead
		effect.operands = []x86TypedByteOperand{{index: -1, operand: al, width: 1, read: true, write: true}}
	case x86DecimalMergeDigits:
		effect.operands = []x86TypedByteOperand{{index: -1, operand: ax, width: 2, read: true, write: true}}
	case x86DecimalSplitDigits:
		effect.operands = []x86TypedByteOperand{
			{index: -1, operand: al, width: 1, read: true},
			{index: -1, operand: ax, width: 2, write: true},
		}
	}
	return effect, true, nil
}

func (form x86DecimalForm) divideError() bool {
	return form.spec.kind == x86DecimalSplitDigits && form.radix == 0
}

func x86DecimalDivideError(ins Instr, arch string) bool {
	if ins.Op != "AAM" {
		return false
	}
	form, known, err := x86DecimalProperties(ins.Op, ins, arch)
	return known && err == nil && form.divideError()
}

func (c *amd64Ctx) lowerX86Decimal(form x86DecimalForm) error {
	low, err := c.evalIntSized(Operand{Kind: OpReg, Reg: AL}, I8)
	if err != nil {
		return err
	}
	value := func(operation string, args ...any) string {
		name := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ", name)
		fmt.Fprintf(c.b, operation, args...)
		c.b.WriteByte('\n')
		return "%" + name
	}

	switch form.spec.kind {
	case x86DecimalASCIIAdjust, x86DecimalPackedAdjust:
		nibble := value("and i8 %s, 15", low)
		badDigit := value("icmp ugt i8 %s, 9", nibble)
		adjustLow := value("or i1 %s, %s", badDigit, c.loadFlag(c.flagsAFSlot))
		fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", adjustLow, c.flagsAFSlot)
		if form.spec.kind == x86DecimalASCIIAdjust {
			ax, err := c.evalIntSized(Operand{Kind: OpReg, Reg: AX}, I16)
			if err != nil {
				return err
			}
			delta := 0x106
			if form.spec.subtract {
				delta = -delta
			}
			amount := value("select i1 %s, i16 %d, i16 0", adjustLow, delta)
			adjusted := value("add i16 %s, %s", ax, amount)
			result := value("and i16 %s, 65295", adjusted)
			fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", adjustLow, c.flagsCFSlot)
			return c.storeRegSized(AX, I16, result)
		}

		// The upper-digit decision uses the original AL and CF.
		oldCF := c.loadFlag(c.flagsCFSlot)
		above99 := value("icmp ugt i8 %s, 153", low)
		adjustHigh := value("or i1 %s, %s", above99, oldCF)
		carry := adjustHigh
		lowDelta, highDelta := 6, 0x60
		if form.spec.subtract {
			lowDelta, highDelta = -lowDelta, -highDelta
			belowSix := value("icmp ult i8 %s, 6", low)
			borrow := value("and i1 %s, %s", adjustLow, belowSix)
			carry = value("or i1 %s, %s", adjustHigh, borrow)
		}
		smaller := value("select i1 %s, i8 %d, i8 0", adjustLow, lowDelta)
		larger := value("select i1 %s, i8 %d, i8 0", adjustHigh, highDelta)
		adjusted := value("add i8 %s, %s", low, smaller)
		low = value("add i8 %s, %s", adjusted, larger)
		fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", carry, c.flagsCFSlot)
		if err := c.storeRegSized(AL, I8, low); err != nil {
			return err
		}
	case x86DecimalMergeDigits, x86DecimalSplitDigits:
		var result string
		if form.spec.kind == x86DecimalMergeDigits {
			high, err := c.evalIntSized(Operand{Kind: OpReg, Reg: AH}, I8)
			if err != nil {
				return err
			}
			upper := value("mul i8 %s, %d", high, form.radix)
			low = value("add i8 %s, %s", low, upper)
			result = value("zext i8 %s to i16", low)
		} else {
			quotient := value("udiv i8 %s, %d", low, form.radix)
			low = value("urem i8 %s, %d", low, form.radix)
			extended := value("zext i8 %s to i16", quotient)
			high := value("shl i16 %s, 8", extended)
			extended = value("zext i8 %s to i16", low)
			result = value("or i16 %s, %s", high, extended)
		}
		if err := c.storeRegSized(AX, I16, result); err != nil {
			return err
		}
	}
	zero := value("icmp eq i8 %s, 0", low)
	sign := value("icmp slt i8 %s, 0", low)
	fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", zero, c.flagsZSlot)
	fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", sign, c.flagsSltSlot)
	c.setParityFlagSized(I8, low)
	return nil
}
