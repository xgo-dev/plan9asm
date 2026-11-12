package plan9asm

import (
	"fmt"
	"strings"
)

var arm64SVECharacterMatchIntrinsics = map[Op]string{
	"ZMATCH":  "match",
	"ZNMATCH": "nmatch",
}

// decodeARM64RawSVECharacterMatch mirrors Go 1.27's ZMATCH/ZNMATCH B/H
// encoder rows. Only the two element sizes and the predicate/register fields
// vary; the remaining bits must match the architecture encoding exactly.
func decodeARM64RawSVECharacterMatch(word uint32) (Instr, bool) {
	const (
		base        = uint32(0x45208000)
		operandBits = uint32(0x005f1fff)
		negativeBit = uint32(1 << 4)
		halfwordBit = uint32(1 << 22)
	)
	if word&^operandBits != base {
		return Instr{}, false
	}

	op := Op("ZMATCH")
	if word&negativeBit != 0 {
		op = "ZNMATCH"
	}
	element := "B"
	if word&halfwordBit != 0 {
		element = "H"
	}
	second := int(word>>16) & 31
	first := int(word>>5) & 31
	governing := int(word>>10) & 7
	destination := int(word) & 15
	args := []Operand{
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%s", second, element))},
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%s", first, element))},
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d.Z", governing))},
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d.%s", destination, element))},
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("WORD $%#08x", word)}, true
}

func (c *arm64Ctx) lowerARM64SVECharacterMatch(op Op, ins Instr) (ok bool, terminated bool, err error) {
	intrinsic, ok := arm64SVECharacterMatchIntrinsics[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 4 {
		return true, false, fmt.Errorf("arm64 %s expects Zm.B|H, Zn.B|H, Pg/Z, Pd.B|H without a suffix: %q", op, ins.Raw)
	}
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
	first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
	governing, governingOK := arm64ParseSVEPredicateMode(ins.Args[2], "Z", 7)
	destination, destinationBits, destinationOK := arm64ParseSVEPredicateElement(ins.Args[3])
	if !secondOK || !firstOK || !governingOK || !destinationOK || (firstBits != 8 && firstBits != 16) || secondBits != firstBits || destinationBits != firstBits {
		return true, false, fmt.Errorf("arm64 %s requires matching B/H vectors and result predicate under P0..P7/Z: %q", op, ins.Raw)
	}
	governingValue, predicateType, err := c.loadPRegElements(governing, firstBits)
	if err != nil {
		return true, false, err
	}
	firstValue, vectorType, err := c.loadZRegElements(first, firstBits)
	if err != nil {
		return true, false, err
	}
	secondValue, _, err := c.loadZRegElements(second, secondBits)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / firstBits
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s, %s %s)\n", result, predicateType, intrinsic, lanes, firstBits, predicateType, governingValue, vectorType, firstValue, vectorType, secondValue)
	return true, false, c.storePRegElements(destination, destinationBits, "%"+result)
}
