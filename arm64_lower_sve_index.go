package plan9asm

import (
	"fmt"
	"strings"
)

// The two operand-class bits describe the complete INDEX family independently
// of element size: immediate/immediate, register/immediate, immediate/register,
// and register/register. Unlike Go's ZINDEX spelling, raw register forms do not
// force D elements; select ZINDEXW for their B/H/S encodings.
func decodeARM64RawSVEIndex(word uint32) (Instr, bool) {
	const operands = uint32(3<<22 | 31<<16 | 3<<10 | 31<<5 | 31)
	if word&^operands != 0x04204000 {
		return Instr{}, false
	}
	scalar := func(value uint32, register bool) Operand {
		if !register {
			return Operand{Kind: OpImm, Imm: int64(int32(value<<27) >> 27)}
		}
		if value == 31 {
			return Operand{Kind: OpReg, Reg: ZR}
		}
		return Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("R%d", value))}
	}
	size := word >> 22 & 3
	form := word >> 10 & 3
	op := Op("ZINDEX")
	if form != 0 && size != 3 {
		op = "ZINDEXW"
	}
	return Instr{Op: op, Raw: fmt.Sprintf("decoded ARM64 WORD %#08x as %s", word, op), Args: []Operand{
		scalar(word>>16&31, form&2 != 0),
		scalar(word>>5&31, form&1 != 0),
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", word&31, "BHSD"[size]))},
	}}, true
}

func (c *arm64Ctx) lowerARM64SVEIndex(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZINDEX" && op != "ZINDEXW" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects step, start, Zd.B/H/S/D without a suffix: %q", op, ins.Raw)
	}
	destination, writtenBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	if !destinationOK {
		return true, false, fmt.Errorf("arm64 %s destination must be Z0..Z31.B/H/S/D: %q", op, ins.Raw)
	}
	stepIsReg := arm64SVEIndexScalarRegister(ins.Args[0])
	startIsReg := arm64SVEIndexScalarRegister(ins.Args[1])
	stepIsImm := arm64SVEIndexImmediate(ins.Args[0])
	startIsImm := arm64SVEIndexImmediate(ins.Args[1])
	if !stepIsReg && !stepIsImm || !startIsReg && !startIsImm || op == "ZINDEXW" && stepIsImm && startIsImm {
		return true, false, fmt.Errorf("arm64 %s operands do not match its Go 1.27 scalar/immediate forms: %q", op, ins.Raw)
	}

	// Go's ZINDEX register encodings carry fixed D size bits. The generated
	// assembler accepts B/H/S spellings too, but ORs their size field with D;
	// preserve the resulting machine semantics rather than the written suffix.
	elementBits := writtenBits
	if op == "ZINDEX" && (stepIsReg || startIsReg) {
		elementBits = 64
	}
	step, err := c.arm64SVEIndexScalar(ins.Args[0], elementBits)
	if err != nil {
		return true, false, err
	}
	start, err := c.arm64SVEIndexScalar(ins.Args[1], elementBits)
	if err != nil {
		return true, false, err
	}
	vectorType, lanes, err := arm64SVEVectorType(elementBits)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.index.nxv%di%d(i%d %s, i%d %s)\n",
		result, vectorType, lanes, elementBits, elementBits, start, elementBits, step)
	return true, false, c.storeZRegElements(destination, elementBits, "%"+result)
}

func arm64SVEIndexScalarRegister(operand Operand) bool {
	return operand.Kind == OpReg && isARM64GeneralOrZeroReg(operand.Reg)
}

func arm64SVEIndexImmediate(operand Operand) bool {
	return operand.Kind == OpImm && operand.ImmRaw == "" && operand.Imm >= -16 && operand.Imm <= 15
}

func (c *arm64Ctx) arm64SVEIndexScalar(operand Operand, elementBits int) (string, error) {
	if arm64SVEIndexImmediate(operand) {
		return fmt.Sprintf("%d", operand.Imm), nil
	}
	if !arm64SVEIndexScalarRegister(operand) {
		return "", fmt.Errorf("arm64 SVE INDEX scalar must be R0..R30, ZR, or a signed 5-bit immediate")
	}
	value, err := c.loadReg(operand.Reg)
	if err != nil {
		return "", err
	}
	if elementBits == 64 || value == "0" {
		return value, nil
	}
	truncated := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i%d\n", truncated, value, elementBits)
	return "%" + truncated, nil
}
