package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
)

type arm64RawSVESelect struct {
	elementBits int
	falseValue  int
	trueValue   int
	predicate   int
	destination int
}

func decodeARM64RawSVESelect(word uint32) (arm64RawSVESelect, bool) {
	if word&0xff20c000 != 0x0520c000 {
		return arm64RawSVESelect{}, false
	}
	return arm64RawSVESelect{
		elementBits: 8 << (int(word>>22) & 3),
		falseValue:  int(word>>16) & 31,
		trueValue:   int(word>>5) & 31,
		predicate:   int(word>>10) & 15,
		destination: int(word) & 31,
	}, true
}

func arm64ParseSVEPredicate(operand Operand) (int, bool) {
	if operand.Kind != OpReg {
		return 0, false
	}
	name := strings.ToUpper(strings.TrimSpace(string(operand.Reg)))
	if strings.Contains(name, ".") || !strings.HasPrefix(name, "P") {
		return 0, false
	}
	index, err := strconv.Atoi(strings.TrimPrefix(name, "P"))
	return index, err == nil && index >= 0 && index < 16
}

func (c *arm64Ctx) lowerARM64SVESelect(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZSEL" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 4 {
		return true, false, fmt.Errorf("arm64 ZSEL expects Zm.T, Zn.T, Pv, Zd.T: %q", ins.Raw)
	}
	falseValue, falseBits, falseOK := arm64ParseSVEZElementReg(ins.Args[0])
	trueValue, trueBits, trueOK := arm64ParseSVEZElementReg(ins.Args[1])
	predicate, predicateOK := arm64ParseSVEPredicate(ins.Args[2])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[3])
	if !falseOK || !trueOK || !predicateOK || !destinationOK || falseBits != trueBits || trueBits != destinationBits {
		return true, false, fmt.Errorf("arm64 ZSEL operands must share one element width and use a bare P0..P15 predicate: %q", ins.Raw)
	}
	return true, false, c.lowerRawSVESelect(arm64RawSVESelect{
		elementBits: falseBits,
		falseValue:  falseValue,
		trueValue:   trueValue,
		predicate:   predicate,
		destination: destination,
	})
}

func (c *arm64Ctx) lowerRawSVESelect(form arm64RawSVESelect) error {
	falseValue, vectorType, err := c.loadZRegElements(form.falseValue, form.elementBits)
	if err != nil {
		return err
	}
	trueValue, _, err := c.loadZRegElements(form.trueValue, form.elementBits)
	if err != nil {
		return err
	}
	predicate, predicateType, err := c.loadPRegElements(form.predicate, form.elementBits)
	if err != nil {
		return err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select %s %s, %s %s, %s %s\n", result, predicateType, predicate, vectorType, trueValue, vectorType, falseValue)
	return c.storeZRegElements(form.destination, form.elementBits, "%"+result)
}
