package plan9asm

import (
	"fmt"
)

type amd64HorizontalFloatingSpec struct {
	laneBits int
	subtract bool
	vector   bool
}

// amd64HorizontalFloatingSpecs is the complete Go 1.27 horizontal
// floating-point add/subtract family. Legacy forms use yxm; V-prefixed forms
// use _yvaddsubpd and are deliberately limited to VEX X/Y registers.
var amd64HorizontalFloatingSpecs = map[Op]amd64HorizontalFloatingSpec{
	"HADDPS":  {laneBits: 32},
	"HADDPD":  {laneBits: 64},
	"HSUBPS":  {laneBits: 32, subtract: true},
	"HSUBPD":  {laneBits: 64, subtract: true},
	"VHADDPS": {laneBits: 32, vector: true},
	"VHADDPD": {laneBits: 64, vector: true},
	"VHSUBPS": {laneBits: 32, subtract: true, vector: true},
	"VHSUBPD": {laneBits: 64, subtract: true, vector: true},
}

func (c *amd64Ctx) lowerHorizontalFloating(op Op, ins Instr) (ok bool, terminated bool, err error) {
	return c.lowerNativePackedReduction(op, ins)
}

func (c *amd64Ctx) loadHorizontalFloatingOperand(operand Operand, byteWidth, laneBits int) (string, error) {
	bytesValue, err := c.loadPackedCompareBytes(operand, byteWidth)
	if err != nil {
		return "", err
	}
	lanes := byteWidth * 8 / laneBits
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to %s\n", result, byteWidth, bytesValue, amd64FMA3LLVMType(lanes, laneBits))
	return "%" + result, nil
}
