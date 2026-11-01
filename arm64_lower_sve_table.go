package plan9asm

import (
	"fmt"
	"strings"
)

type arm64RawSVETable struct {
	elementBits int
	tableCount  int
	index       int
	firstTable  int
	destination int
}

func decodeARM64RawSVETable(word uint32) (arm64RawSVETable, bool) {
	tableCount := 0
	switch word & 0xff20fc00 {
	case 0x05203000:
		tableCount = 1
	case 0x05202800:
		tableCount = 2
	default:
		return arm64RawSVETable{}, false
	}
	return arm64RawSVETable{
		elementBits: 8 << (int(word>>22) & 3),
		tableCount:  tableCount,
		index:       int(word>>16) & 31,
		firstTable:  int(word>>5) & 31,
		destination: int(word) & 31,
	}, true
}

func arm64SVETableNeedsSVE2(ins Instr) bool {
	return len(ins.Args) == 3 && ins.Args[1].Kind == OpRegList && len(ins.Args[1].RegList) == 2
}

func (c *arm64Ctx) lowerARM64SVETable(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZTBL" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 || ins.Args[1].Kind != OpRegList {
		return true, false, fmt.Errorf("arm64 ZTBL expects Zm.T, [Zn.T] or [Zn.T, Zn+1.T], Zd.T: %q", ins.Raw)
	}
	index, indexBits, indexOK := arm64ParseSVEZElementReg(ins.Args[0])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	tables := ins.Args[1].RegList
	if !indexOK || !destinationOK || indexBits != destinationBits || (len(tables) != 1 && len(tables) != 2) {
		return true, false, fmt.Errorf("arm64 ZTBL requires one width and one or two table registers: %q", ins.Raw)
	}
	firstTable, tableBits, tableOK := arm64ParseSVEZElementReg(Operand{Kind: OpReg, Reg: tables[0]})
	if !tableOK || tableBits != indexBits {
		return true, false, fmt.Errorf("arm64 ZTBL table width must match its index and destination: %q", ins.Raw)
	}
	if len(tables) == 2 {
		secondTable, secondBits, secondOK := arm64ParseSVEZElementReg(Operand{Kind: OpReg, Reg: tables[1]})
		if !secondOK || secondBits != tableBits || firstTable == 31 || secondTable != firstTable+1 {
			return true, false, fmt.Errorf("arm64 named ZTBL pair must be consecutive without wrapping, as required by Go 1.27: %q", ins.Raw)
		}
	}
	return true, false, c.lowerRawSVETable(arm64RawSVETable{
		elementBits: indexBits,
		tableCount:  len(tables),
		index:       index,
		firstTable:  firstTable,
		destination: destination,
	})
}

func (c *arm64Ctx) lowerRawSVETable(form arm64RawSVETable) error {
	index, vectorType, err := c.loadZRegElements(form.index, form.elementBits)
	if err != nil {
		return err
	}
	firstTable, _, err := c.loadZRegElements(form.firstTable, form.elementBits)
	if err != nil {
		return err
	}
	_, lanes, err := arm64SVEVectorType(form.elementBits)
	if err != nil {
		return err
	}
	result := c.newTmp()
	if form.tableCount == 1 {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.tbl.nxv%di%d(%s %s, %s %s)\n", result, vectorType, lanes, form.elementBits, vectorType, firstTable, vectorType, index)
	} else {
		secondTable, _, err := c.loadZRegElements((form.firstTable+1)%32, form.elementBits)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.tbl2.nxv%di%d(%s %s, %s %s, %s %s)\n", result, vectorType, lanes, form.elementBits, vectorType, firstTable, vectorType, secondTable, vectorType, index)
	}
	return c.storeZRegElements(form.destination, form.elementBits, "%"+result)
}
