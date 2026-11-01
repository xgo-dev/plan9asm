package plan9asm

import (
	"fmt"
	"strings"
)

var arm64SVETableExtensionIntrinsics = map[Op]string{
	"ZTBLQ": "tblq",
	"ZTBX":  "tbx",
	"ZTBXQ": "tbxq",
}

func (c *arm64Ctx) lowerARM64SVETableExtension(op Op, ins Instr) (ok bool, terminated bool, err error) {
	intrinsic, ok := arm64SVETableExtensionIntrinsics[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects one complete Go 1.27 table form without a suffix: %q", op, ins.Raw)
	}
	index, indexBits, indexOK := arm64ParseSVEZElementReg(ins.Args[0])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	var table, tableBits int
	var tableOK bool
	if op == "ZTBLQ" {
		if ins.Args[1].Kind != OpRegList || len(ins.Args[1].RegList) != 1 {
			return true, false, fmt.Errorf("arm64 ZTBLQ requires exactly one table register list element: %q", ins.Raw)
		}
		table, tableBits, tableOK = arm64ParseSVEZElementReg(Operand{Kind: OpReg, Reg: ins.Args[1].RegList[0]})
	} else {
		table, tableBits, tableOK = arm64ParseSVEZElementReg(ins.Args[1])
	}
	if !indexOK || !tableOK || !destinationOK || indexBits != tableBits || tableBits != destinationBits {
		return true, false, fmt.Errorf("arm64 %s operands must use one matching B/H/S/D width: %q", op, ins.Raw)
	}
	indexValue, vectorType, err := c.loadZRegElements(index, indexBits)
	if err != nil {
		return true, false, err
	}
	tableValue, _, err := c.loadZRegElements(table, tableBits)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / destinationBits
	result := c.newTmp()
	if op == "ZTBLQ" {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s)\n", result, vectorType, intrinsic, lanes, destinationBits, vectorType, tableValue, vectorType, indexValue)
	} else {
		old, _, err := c.loadZRegElements(destination, destinationBits)
		if err != nil {
			return true, false, err
		}
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s, %s %s)\n", result, vectorType, intrinsic, lanes, destinationBits, vectorType, old, vectorType, tableValue, vectorType, indexValue)
	}
	return true, false, c.storeZRegElements(destination, destinationBits, "%"+result)
}
