package plan9asm

import (
	"fmt"
	"math/bits"
	"strings"
)

func decodeARM64RawSVEXAR(word uint32) (Instr, bool) {
	if word&0xff20fc00 != 0x04203400 {
		return Instr{}, false
	}
	encoded := int(word>>16&31 | word>>17&96)
	if encoded < 8 { // tsize=0000 is unallocated.
		return Instr{}, false
	}
	size := bits.Len(uint(encoded)) - 4
	elementBits := 8 << size
	width := "BHSD"[size]
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", word&31, width))}
	return Instr{Op: "ZXAR", Raw: fmt.Sprintf("WORD $%#08x", word), Args: []Operand{
		{Kind: OpImm, Imm: int64(2*elementBits - encoded)},
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", word>>5&31, width))},
		destination, destination,
	}}, true
}

func (c *arm64Ctx) lowerARM64RawSVEXAR(ins Instr) error {
	second, width, _ := arm64ParseSVEZElementReg(ins.Args[1])
	destination, _, _ := arm64ParseSVEZElementReg(ins.Args[2])
	return c.lowerARM64SVEXARForm(destination, second, width, ins.Args[0].Imm)
}

func (c *arm64Ctx) lowerARM64SVEXAR(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZXAR" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 4 || ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" {
		return true, false, fmt.Errorf("arm64 ZXAR expects $shift, Zm.T, Zdn.T, Zdn.T without a suffix: %q", ins.Raw)
	}
	shift := ins.Args[0].Imm
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[1])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	repeatedDestination, repeatedBits, repeatedOK := arm64ParseSVEZElementReg(ins.Args[3])
	if !secondOK || !destinationOK || !repeatedOK || secondBits != destinationBits || repeatedBits != destinationBits || repeatedDestination != destination || shift < 1 || shift >= int64(destinationBits) {
		return true, false, fmt.Errorf("arm64 ZXAR requires matching destructive B/H/S/D operands and shift $1..$elementBits-1: %q", ins.Raw)
	}
	return true, false, c.lowerARM64SVEXARForm(destination, second, destinationBits, shift)
}

func (c *arm64Ctx) lowerARM64SVEXARForm(destination, second, destinationBits int, shift int64) error {
	destinationValue, vectorType, err := c.loadZRegElements(destination, destinationBits)
	if err != nil {
		return err
	}
	secondValue, _, err := c.loadZRegElements(second, destinationBits)
	if err != nil {
		return err
	}
	lanes := 128 / destinationBits
	result := c.newTmp()
	if shift == int64(destinationBits) {
		// Architectural WORD encodings include a full-width rotation. Go's
		// named encoder rejects this spelling; preserve that frontend boundary.
		fmt.Fprintf(c.b, "  %%%s = xor %s %s, %s\n", result, vectorType, destinationValue, secondValue)
	} else {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.xar.nxv%di%d(%s %s, %s %s, i32 %d)\n", result, vectorType, lanes, destinationBits, vectorType, destinationValue, vectorType, secondValue, shift)
	}
	return c.storeZRegElements(destination, destinationBits, "%"+result)
}
