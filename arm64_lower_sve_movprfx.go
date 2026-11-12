package plan9asm

import (
	"fmt"
	"strings"
)

// decodeARM64RawSVEMOVPRFX covers Go 1.27's bare-vector and predicated
// B/H/S/D M/Z MOVPRFX rows with their exact fixed-bit masks.
func decodeARM64RawSVEMOVPRFX(word uint32) (Instr, bool) {
	const (
		bareBits       = uint32(0x000003ff)
		predicatedBits = uint32(0x00c11fff)
	)
	var args []Operand
	switch {
	case word&^bareBits == 0x0420bc00:
		args = []Operand{
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d", word>>5&31))},
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d", word&31))},
		}
	case word&^predicatedBits == 0x04102000:
		width := [...]string{"B", "H", "S", "D"}[word>>22&3]
		mode := "Z"
		if word&(1<<16) != 0 {
			mode = "M"
		}
		args = []Operand{
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%s", word>>5&31, width))},
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d.%s", word>>10&7, mode))},
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%s", word&31, width))},
		}
	default:
		return Instr{}, false
	}
	return Instr{Op: "ZMOVPRFX", Args: args, Raw: fmt.Sprintf("WORD $%#08x", word)}, true
}

func (c *arm64Ctx) lowerARM64SVEMOVPRFX(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZMOVPRFX" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) {
		return true, false, fmt.Errorf("arm64 ZMOVPRFX does not accept an instruction suffix: %q", ins.Raw)
	}
	if len(ins.Args) == 2 {
		source, sourceOK := arm64ParseSVEBareZReg(ins.Args[0])
		destination, destinationOK := arm64ParseSVEBareZReg(ins.Args[1])
		if !sourceOK || !destinationOK {
			return true, false, fmt.Errorf("arm64 ZMOVPRFX two-operand form requires bare Z registers: %q", ins.Raw)
		}
		value, err := c.loadZReg(source)
		if err != nil {
			return true, false, err
		}
		return true, false, c.storeZReg(destination, value)
	}
	if len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 ZMOVPRFX expects Zn, Zd or Zn.T, Pg.M/Z, Zd.T: %q", ins.Raw)
	}
	source, sourceBits, sourceOK := arm64ParseSVEZElementReg(ins.Args[0])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	predicate, merge := arm64ParseSVEPredicateMode(ins.Args[1], "M", 7)
	if !merge {
		predicate, _ = arm64ParseSVEPredicateMode(ins.Args[1], "Z", 7)
	}
	_, zero := arm64ParseSVEPredicateMode(ins.Args[1], "Z", 7)
	if !sourceOK || !destinationOK || sourceBits != destinationBits || !merge && !zero {
		return true, false, fmt.Errorf("arm64 ZMOVPRFX predicated form requires matching vectors and P0..P7.M/Z: %q", ins.Raw)
	}
	predicateValue, predicateType, err := c.loadPRegElements(predicate, sourceBits)
	if err != nil {
		return true, false, err
	}
	sourceValue, vectorType, err := c.loadZRegElements(source, sourceBits)
	if err != nil {
		return true, false, err
	}
	fallback := "zeroinitializer"
	if merge {
		fallback, _, err = c.loadZRegElements(destination, sourceBits)
		if err != nil {
			return true, false, err
		}
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select %s %s, %s %s, %s %s\n",
		result, predicateType, predicateValue, vectorType, sourceValue, vectorType, fallback)
	return true, false, c.storeZRegElements(destination, sourceBits, "%"+result)
}
