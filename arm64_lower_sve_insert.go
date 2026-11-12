package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
)

var arm64SVEInsertBaseSize = map[Op]int{
	"ZINSR":  3,
	"ZINSRW": 0,
	"ZINSRB": 0,
	"ZINSRH": 1,
	"ZINSRS": 2,
	"ZINSRD": 3,
}

func (c *arm64Ctx) lowerARM64SVEInsert(op Op, ins Instr) (ok bool, terminated bool, err error) {
	baseSize, ok := arm64SVEInsertBaseSize[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 {
		return true, false, fmt.Errorf("arm64 %s expects scalar, Zdn.B/H/S/D without a suffix: %q", op, ins.Raw)
	}
	destination, writtenBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[1])
	if !destinationOK {
		return true, false, fmt.Errorf("arm64 %s destination must be Z0..Z31.B/H/S/D: %q", op, ins.Raw)
	}
	writtenSize := map[int]int{8: 0, 16: 1, 32: 2, 64: 3}[writtenBits]
	elementBits := 8 << (baseSize | writtenSize)

	var scalar string
	if op == "ZINSR" || op == "ZINSRW" {
		if !arm64SVEIndexScalarRegister(ins.Args[0]) {
			return true, false, fmt.Errorf("arm64 %s source must be R0..R30 or ZR: %q", op, ins.Raw)
		}
		scalar, err = c.loadReg(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		if elementBits != 64 && scalar != "0" {
			truncated := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i%d\n", truncated, scalar, elementBits)
			scalar = "%" + truncated
		}
	} else {
		vectorRegister, vectorOK := arm64SVEInsertVRegister(ins.Args[0])
		if !vectorOK {
			return true, false, fmt.Errorf("arm64 %s source must be a bare V0..V31 register: %q", op, ins.Raw)
		}
		scalar, err = c.arm64SVEInsertVectorScalar(vectorRegister, elementBits)
		if err != nil {
			return true, false, err
		}
	}

	oldVector, vectorType, err := c.loadZRegElements(destination, elementBits)
	if err != nil {
		return true, false, err
	}
	_, lanes, err := arm64SVEVectorType(elementBits)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.insr.nxv%di%d(%s %s, i%d %s)\n",
		result, vectorType, lanes, elementBits, vectorType, oldVector, elementBits, scalar)
	return true, false, c.storeZRegElements(destination, elementBits, "%"+result)
}

func arm64SVEInsertVRegister(operand Operand) (Reg, bool) {
	if operand.Kind != OpReg {
		return "", false
	}
	text := strings.ToUpper(strings.TrimSpace(string(operand.Reg)))
	if !strings.HasPrefix(text, "V") || strings.ContainsAny(text, ".[") {
		return "", false
	}
	index, err := strconv.Atoi(text[1:])
	return Reg(text), err == nil && index >= 0 && index <= 31
}

func (c *arm64Ctx) arm64SVEInsertVectorScalar(register Reg, elementBits int) (string, error) {
	bytes, err := c.loadVReg(register)
	if err != nil {
		return "", err
	}
	vectorType := fmt.Sprintf("<%d x i%d>", 128/elementBits, elementBits)
	vector := bytes
	if elementBits != 8 {
		converted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to %s\n", converted, bytes, vectorType)
		vector = "%" + converted
	}
	scalar := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i64 0\n", scalar, vectorType, vector)
	return "%" + scalar, nil
}
