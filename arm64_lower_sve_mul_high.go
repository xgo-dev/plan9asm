package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVEMultiplyHighSpec struct {
	intrinsic       string
	predicatedRaw   uint32
	unpredicatedRaw uint32
}

var arm64SVEMultiplyHighIntrinsics = map[Op]arm64SVEMultiplyHighSpec{
	"ZSMULH": {intrinsic: "smulh", predicatedRaw: 0x04120000, unpredicatedRaw: 0x04206800},
	"ZUMULH": {intrinsic: "umulh", predicatedRaw: 0x04130000, unpredicatedRaw: 0x04206c00},
}

var arm64SVEMultiplyHighPredicatedRaw, arm64SVEMultiplyHighUnpredicatedRaw = arm64SVEMultiplyHighRawTables()

func arm64SVEMultiplyHighRawTables() (map[uint32]Op, map[uint32]Op) {
	predicated, unpredicated := make(map[uint32]Op), make(map[uint32]Op)
	for op, spec := range arm64SVEMultiplyHighIntrinsics {
		predicated[spec.predicatedRaw], unpredicated[spec.unpredicatedRaw] = op, op
	}
	return predicated, unpredicated
}

func decodeARM64RawSVEMultiplyHigh(word uint32) (Instr, bool) {
	op, predicated := arm64SVEMultiplyHighPredicatedRaw[word&0xff3fe000]
	first, second := word>>5&31, word>>16&31
	if predicated {
		first, second = word&31, first
	} else {
		var ok bool
		op, ok = arm64SVEMultiplyHighUnpredicatedRaw[word&0xff20fc00]
		if !ok {
			return Instr{}, false
		}
	}
	width := "BHSD"[word>>22&3]
	reg := func(number uint32) Operand {
		return Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", number, width))}
	}
	args := []Operand{reg(second), reg(first)}
	if predicated {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d.M", word>>10&7))})
	}
	args = append(args, reg(word&31))
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("WORD $%#08x", word)}, true
}

func arm64SVEMultiplyHighNeedsSVE2(ins Instr) bool {
	return len(ins.Args) == 3
}

func (c *arm64Ctx) lowerARM64SVEMultiplyHigh(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVEMultiplyHighIntrinsics[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || (len(ins.Args) != 3 && len(ins.Args) != 4) {
		return true, false, fmt.Errorf("arm64 %s expects one complete Go 1.27 vector form without a suffix: %q", op, ins.Raw)
	}
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
	first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
	if !secondOK || !firstOK || secondBits != firstBits {
		return true, false, fmt.Errorf("arm64 %s sources must use one B/H/S/D width: %q", op, ins.Raw)
	}
	destinationIndex := 2
	predicate := 0
	predicated := len(ins.Args) == 4
	if predicated {
		var predicateOK bool
		predicate, predicateOK = arm64ParseSVEPredicateMode(ins.Args[2], "M", 7)
		if !predicateOK {
			return true, false, fmt.Errorf("arm64 %s predicated form requires P0..P7.M: %q", op, ins.Raw)
		}
		destinationIndex = 3
	}
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[destinationIndex])
	if !destinationOK || destinationBits != firstBits || (predicated && destination != first) {
		return true, false, fmt.Errorf("arm64 %s destination width and destructive operands do not match: %q", op, ins.Raw)
	}
	firstValue, vectorType, err := c.loadZRegElements(first, firstBits)
	if err != nil {
		return true, false, err
	}
	secondValue, _, err := c.loadZRegElements(second, firstBits)
	if err != nil {
		return true, false, err
	}
	intrinsic := spec.intrinsic
	var predicateValue, predicateType string
	if predicated {
		predicateValue, predicateType, err = c.loadPRegElements(predicate, firstBits)
	} else {
		predicateValue, predicateType, err = c.allTruePRegElements(firstBits)
		intrinsic += ".u"
	}
	if err != nil {
		return true, false, err
	}
	_, lanes, err := arm64SVEVectorType(firstBits)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s, %s %s)\n",
		result, vectorType, intrinsic, lanes, firstBits, predicateType, predicateValue, vectorType, firstValue, vectorType, secondValue)
	return true, false, c.storeZRegElements(destination, firstBits, "%"+result)
}
