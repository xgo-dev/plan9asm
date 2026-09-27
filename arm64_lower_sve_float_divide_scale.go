package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVEFloatDivideScaleSpec struct {
	intrinsic     string
	integerSecond bool
	rawBase       uint32
}

var arm64SVEFloatDivideScaleSpecs = map[Op]arm64SVEFloatDivideScaleSpec{
	"ZFDIV":   {intrinsic: "fdiv", rawBase: 0x650d8000},
	"ZFDIVR":  {intrinsic: "fdivr", rawBase: 0x650c8000},
	"ZFSCALE": {intrinsic: "fscale", integerSecond: true, rawBase: 0x65098000},
}

var arm64SVEFloatDivideScaleRawOps = func() map[uint32]Op {
	ops := make(map[uint32]Op, len(arm64SVEFloatDivideScaleSpecs))
	for op, spec := range arm64SVEFloatDivideScaleSpecs {
		ops[spec.rawBase] = op
	}
	return ops
}()

func decodeARM64RawSVEFloatDivideScale(word uint32) (Instr, bool) {
	op, ok := arm64SVEFloatDivideScaleRawOps[word&0xff3fe000]
	size := word >> 22 & 3
	if !ok || size == 0 {
		return Instr{}, false
	}
	register := func(number uint32) Operand {
		return Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", number, "BHSD"[size]))}
	}
	destination := register(word & 31)
	return Instr{Op: op, Raw: fmt.Sprintf("WORD $%#08x", word), Args: []Operand{
		register(word >> 5 & 31), destination,
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d.M", word>>10&7))}, destination,
	}}, true
}

func (c *arm64Ctx) lowerARM64SVEFloatDivideScale(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, supported := arm64SVEFloatDivideScaleSpecs[op]
	if !supported {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 4 {
		return true, false, fmt.Errorf("arm64 %s expects Zm.H|S|D, Zdn.H|S|D, P0..P7/M, Zdn.H|S|D without a suffix: %q", op, ins.Raw)
	}
	second, secondBits, secondOK := arm64SVEFloatElementReg(ins.Args[0])
	first, firstBits, firstOK := arm64SVEFloatElementReg(ins.Args[1])
	predicate, predicateOK := arm64ParseSVEPredicateMode(ins.Args[2], "M", 7)
	destination, destinationBits, destinationOK := arm64SVEFloatElementReg(ins.Args[3])
	if !secondOK || !firstOK || !predicateOK || !destinationOK || secondBits != firstBits || destinationBits != firstBits || destination != first {
		return true, false, fmt.Errorf("arm64 %s requires matching-width destructive H/S/D operands and P0..P7/M: %q", op, ins.Raw)
	}
	firstValue, vectorType, err := c.loadRawSVEFloatVector(first, firstBits)
	if err != nil {
		return true, false, err
	}
	predicateValue, predicateType, err := c.loadPRegElements(predicate, firstBits)
	if err != nil {
		return true, false, err
	}
	_, _, lanes, err := arm64SVEFloatType(firstBits)
	if err != nil {
		return true, false, err
	}
	mangle := map[int]string{16: "f16", 32: "f32", 64: "f64"}[firstBits]
	result := c.newTmp()
	if spec.integerSecond {
		secondValue, integerType, err := c.loadZRegElements(second, secondBits)
		if err != nil {
			return true, false, err
		}
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.fscale.nxv%d%s(%s %s, %s %s, %s %s)\n", result, vectorType, lanes, mangle, predicateType, predicateValue, vectorType, firstValue, integerType, secondValue)
	} else {
		secondValue, _, err := c.loadRawSVEFloatVector(second, secondBits)
		if err != nil {
			return true, false, err
		}
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%d%s(%s %s, %s %s, %s %s)\n", result, vectorType, spec.intrinsic, lanes, mangle, predicateType, predicateValue, vectorType, firstValue, vectorType, secondValue)
	}
	selected := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select %s %s, %s %%%s, %s %s\n", selected, predicateType, predicateValue, vectorType, result, vectorType, firstValue)
	return true, false, c.storeRawSVEFloatVector(destination, firstBits, "%"+selected, vectorType)
}
