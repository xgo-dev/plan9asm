package plan9asm

import (
	"fmt"
	"strings"
)

func decodeARM64RawSVESplice(word uint32) (Instr, bool) {
	base := word & 0xff3fe000
	if base != 0x052c8000 && base != 0x052d8000 {
		return Instr{}, false
	}
	width := "BHSD"[word>>22&3]
	vector := func(index uint32) Operand {
		return Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", index&31, width))}
	}
	destination, source := vector(word), vector(word>>5)
	predicate := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d", word>>10&7))}
	args := []Operand{source, destination, predicate, destination}
	if base == 0x052d8000 {
		list := Operand{Kind: OpRegList, RegList: []Reg{source.Reg, vector((word >> 5 & 31) + 1).Reg}}
		args = []Operand{list, predicate, destination}
	}
	return Instr{Op: "ZSPLICE", Args: args, Raw: fmt.Sprintf("WORD $%#08x", word)}, true
}

func (c *arm64Ctx) lowerARM64RawSVESplice(ins Instr) error {
	var first, second, predicate, destination, width int
	if len(ins.Args) == 3 {
		// The architecture wraps Z31's second register to Z0, unlike the
		// named Go grammar. Both paths share the same semantic form lowerer.
		first, width, _ = arm64ParseSVEZElementReg(Operand{Kind: OpReg, Reg: ins.Args[0].RegList[0]})
		second = (first + 1) % 32
		predicate, _ = arm64ParseSVEPredicateBare(ins.Args[1], 7)
		destination, _, _ = arm64ParseSVEZElementReg(ins.Args[2])
	} else {
		second, width, _ = arm64ParseSVEZElementReg(ins.Args[0])
		destination, _, _ = arm64ParseSVEZElementReg(ins.Args[1])
		first = destination
		predicate, _ = arm64ParseSVEPredicateBare(ins.Args[2], 7)
	}
	return c.lowerARM64SVESpliceForm(first, second, predicate, destination, width)
}

func (c *arm64Ctx) lowerARM64SVESplice(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZSPLICE" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) < 3 || len(ins.Args) > 4 {
		return true, false, fmt.Errorf("arm64 ZSPLICE expects one Go 1.27 vector form without a suffix: %q", ins.Raw)
	}

	var first, second, predicate, destination, elementBits int
	if len(ins.Args) == 4 {
		var firstOK, secondOK, predicateOK, destinationOK bool
		second, elementBits, secondOK = arm64ParseSVEZElementReg(ins.Args[0])
		first, _, firstOK = arm64ParseSVEZElementReg(ins.Args[1])
		predicate, predicateOK = arm64ParseSVEPredicateBare(ins.Args[2], 15)
		destination, _, destinationOK = arm64ParseSVEZElementReg(ins.Args[3])
		_, firstBits, _ := arm64ParseSVEZElementReg(ins.Args[1])
		_, destinationBits, _ := arm64ParseSVEZElementReg(ins.Args[3])
		if !firstOK || !secondOK || !predicateOK || !destinationOK ||
			firstBits != elementBits || destinationBits != elementBits || first != destination {
			return true, false, fmt.Errorf("arm64 ZSPLICE destructive form requires Zm.T, Zdn.T, P0..P15, Zdn.T with one B/H/S/D width: %q", ins.Raw)
		}
	} else {
		if ins.Args[0].Kind != OpRegList || len(ins.Args[0].RegList) != 2 {
			return true, false, fmt.Errorf("arm64 ZSPLICE list form requires exactly two consecutive vectors: %q", ins.Raw)
		}
		var firstOK, secondOK, predicateOK, destinationOK bool
		first, elementBits, firstOK = arm64ParseSVEZElementReg(Operand{Kind: OpReg, Reg: ins.Args[0].RegList[0]})
		second, _, secondOK = arm64ParseSVEZElementReg(Operand{Kind: OpReg, Reg: ins.Args[0].RegList[1]})
		predicate, predicateOK = arm64ParseSVEPredicateBare(ins.Args[1], 15)
		destination, _, destinationOK = arm64ParseSVEZElementReg(ins.Args[2])
		_, secondBits, _ := arm64ParseSVEZElementReg(Operand{Kind: OpReg, Reg: ins.Args[0].RegList[1]})
		_, destinationBits, _ := arm64ParseSVEZElementReg(ins.Args[2])
		if !firstOK || !secondOK || !predicateOK || !destinationOK || first == 31 || second != first+1 ||
			secondBits != elementBits || destinationBits != elementBits {
			return true, false, fmt.Errorf("arm64 ZSPLICE list form requires [Zn.T, Z(n+1).T], P0..P15, Zd.T with one B/H/S/D width: %q", ins.Raw)
		}
	}

	return true, false, c.lowerARM64SVESpliceForm(first, second, predicate, destination, elementBits)
}

func (c *arm64Ctx) lowerARM64SVESpliceForm(first, second, predicate, destination, elementBits int) error {
	predicateValue, predicateType, err := c.loadPRegElements(predicate, elementBits)
	if err != nil {
		return err
	}
	firstValue, vectorType, err := c.loadZRegElements(first, elementBits)
	if err != nil {
		return err
	}
	secondValue, _, err := c.loadZRegElements(second, elementBits)
	if err != nil {
		return err
	}
	_, lanes, err := arm64SVEVectorType(elementBits)
	if err != nil {
		return err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.splice.nxv%di%d(%s %s, %s %s, %s %s)\n",
		result, vectorType, lanes, elementBits, predicateType, predicateValue, vectorType, firstValue, vectorType, secondValue)
	return c.storeZRegElements(destination, elementBits, "%"+result)
}
