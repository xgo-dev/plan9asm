package plan9asm

import (
	"fmt"
	"strings"
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
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	spec, recognized := amd64HorizontalFloatingSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("%s %s has no suffixed forms in Go 1.27: %q", c.goarch, baseOp, ins.Raw)
	}
	if spec.vector {
		return c.lowerVectorHorizontalFloating(baseOp, spec, ins)
	}
	return c.lowerLegacyHorizontalFloating(baseOp, spec, ins)
}

func (c *amd64Ctx) lowerLegacyHorizontalFloating(baseOp string, spec amd64HorizontalFloatingSpec, ins Instr) (bool, bool, error) {
	if len(ins.Args) != 2 || !amd64VEXVectorRegister(ins.Args[1], 16) {
		return true, false, fmt.Errorf("%s %s expects X/m128, X using Go 1.27's yxm table: %q", c.goarch, baseOp, ins.Raw)
	}
	if ins.Args[0].Kind == OpReg {
		if !amd64VEXVectorRegister(ins.Args[0], 16) {
			return true, false, fmt.Errorf("%s %s source is outside Go 1.27's X register class: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(ins.Args[0]) {
		return true, false, fmt.Errorf("%s %s source must be X or memory: %q", c.goarch, baseOp, ins.Raw)
	}
	first, err := c.loadHorizontalFloatingOperand(ins.Args[0], 16, spec.laneBits)
	if err != nil {
		return true, false, err
	}
	second, err := c.loadHorizontalFloatingOperand(ins.Args[1], 16, spec.laneBits)
	if err != nil {
		return true, false, err
	}
	result := c.emitHorizontalFloating(spec, 16, first, second)
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <16 x i8>\n", out, amd64FMA3LLVMType(128/spec.laneBits, spec.laneBits), result)
	return true, false, c.storeX(ins.Args[1].Reg, "%"+out)
}

func (c *amd64Ctx) lowerVectorHorizontalFloating(baseOp string, spec amd64HorizontalFloatingSpec, ins Instr) (bool, bool, error) {
	if len(ins.Args) != 3 || ins.Args[2].Kind != OpReg {
		return true, false, fmt.Errorf("%s %s expects src1, src2, destination: %q", c.goarch, baseOp, ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(ins.Args[2].Reg)
	if byteWidth != 16 && byteWidth != 32 {
		return true, false, fmt.Errorf("%s %s destination must be a VEX X or Y register: %q", c.goarch, baseOp, ins.Raw)
	}
	if !amd64VEXVectorRegister(ins.Args[2], byteWidth) || !amd64VEXVectorRegister(ins.Args[1], byteWidth) {
		return true, false, fmt.Errorf("%s %s second source and destination must be same-width Go 1.27 VEX registers: %q", c.goarch, baseOp, ins.Raw)
	}
	if ins.Args[0].Kind == OpReg {
		if !amd64VEXVectorRegister(ins.Args[0], byteWidth) {
			return true, false, fmt.Errorf("%s %s first source must match the destination's VEX register class: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(ins.Args[0]) {
		return true, false, fmt.Errorf("%s %s first source must be a vector register or memory: %q", c.goarch, baseOp, ins.Raw)
	}
	first, err := c.loadHorizontalFloatingOperand(ins.Args[0], byteWidth, spec.laneBits)
	if err != nil {
		return true, false, err
	}
	second, err := c.loadHorizontalFloatingOperand(ins.Args[1], byteWidth, spec.laneBits)
	if err != nil {
		return true, false, err
	}
	result := c.emitHorizontalFloating(spec, byteWidth, first, second)
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <%d x i8>\n", out, amd64FMA3LLVMType(byteWidth*8/spec.laneBits, spec.laneBits), result, byteWidth)
	return true, false, c.storeVectorBytes(ins.Args[2].Reg, byteWidth, "%"+out)
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

func (c *amd64Ctx) emitHorizontalFloating(spec amd64HorizontalFloatingSpec, byteWidth int, first, second string) string {
	lanes := byteWidth * 8 / spec.laneBits
	lanesPer128 := 128 / spec.laneBits
	typeName := amd64FMA3LLVMType(lanes, spec.laneBits)
	elementType := amd64FMA3LLVMType(1, spec.laneBits)
	result := "poison"
	for lane := 0; lane < lanes; lane++ {
		position := lane % lanesPer128
		block := lane - position
		source := second
		pair := position
		if position >= lanesPer128/2 {
			source = first
			pair -= lanesPer128 / 2
		}
		leftIndex := block + 2*pair
		rightIndex := leftIndex + 1
		left := c.newTmp()
		right := c.newTmp()
		value := c.newTmp()
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", left, typeName, source, leftIndex)
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", right, typeName, source, rightIndex)
		operation := "fadd"
		if spec.subtract {
			operation = "fsub"
		}
		fmt.Fprintf(c.b, "  %%%s = %s %s %%%s, %%%s\n", value, operation, elementType, left, right)
		fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, %s %%%s, i32 %d\n", inserted, typeName, result, elementType, value, lane)
		result = "%" + inserted
	}
	return result
}
