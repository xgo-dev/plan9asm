package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
)

type arm64SVELUTIForm struct {
	op                       Op
	index, lane, destination int
	tables                   []int
	elementBits              int
}

func arm64ParseSVERawIndexedReg(operand Operand) (register, lane int, ok bool) {
	if operand.Kind != OpReg {
		return 0, 0, false
	}
	name := strings.ToUpper(strings.TrimSpace(string(operand.Reg)))
	open := strings.IndexByte(name, '[')
	if !strings.HasPrefix(name, "Z") || open <= 1 || !strings.HasSuffix(name, "]") || strings.Contains(name[:open], ".") {
		return 0, 0, false
	}
	register, registerErr := strconv.Atoi(name[1:open])
	lane, laneErr := strconv.Atoi(name[open+1 : len(name)-1])
	return register, lane, registerErr == nil && laneErr == nil && register >= 0 && register <= 31 && lane >= 0
}

func (c *arm64Ctx) lowerARM64SVELUTI(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZLUTI2" && op != "ZLUTI4" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 || ins.Args[1].Kind != OpRegList {
		return true, false, fmt.Errorf("arm64 %s expects Zm[index], [Zn.B|H] or [Zn1.H, Zn2.H], Zd.B|H without a suffix: %q", op, ins.Raw)
	}
	index, lane, indexOK := arm64ParseSVERawIndexedReg(ins.Args[0])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	if !indexOK || !destinationOK || destinationBits != 8 && destinationBits != 16 {
		return true, false, fmt.Errorf("arm64 %s requires a raw indexed Z register and a B/H destination: %q", op, ins.Raw)
	}
	tableOperands := ins.Args[1].RegList
	if len(tableOperands) != 1 && len(tableOperands) != 2 {
		return true, false, fmt.Errorf("arm64 %s requires exactly one table, or two H tables for ZLUTI4: %q", op, ins.Raw)
	}
	tables := make([]int, len(tableOperands))
	for tableIndex, tableOperand := range tableOperands {
		table, tableBits, tableOK := arm64ParseSVEZElementReg(Operand{Kind: OpReg, Reg: tableOperand})
		if !tableOK || tableBits != destinationBits {
			return true, false, fmt.Errorf("arm64 %s table and destination widths must match: %q", op, ins.Raw)
		}
		tables[tableIndex] = table
	}
	if len(tables) == 2 && tables[1] != (tables[0]+1)%32 {
		return true, false, fmt.Errorf("arm64 ZLUTI4 table pair must be consecutive, including Z31-to-Z0 wrapping, as required by Go 1.27: %q", ins.Raw)
	}
	maxLane := -1
	switch {
	case op == "ZLUTI2" && len(tables) == 1 && destinationBits == 8:
		maxLane = 3
	case op == "ZLUTI2" && len(tables) == 1 && destinationBits == 16:
		maxLane = 7
	case op == "ZLUTI4" && len(tables) == 1 && destinationBits == 8:
		maxLane = 1
	case op == "ZLUTI4" && len(tables) == 1 && destinationBits == 16:
		maxLane = 3
	case op == "ZLUTI4" && len(tables) == 2 && destinationBits == 16:
		maxLane = 3
	}
	if maxLane < 0 || lane > maxLane {
		return true, false, fmt.Errorf("arm64 %s table count, width, or lane is outside the complete Go 1.27 forms: %q", op, ins.Raw)
	}
	return true, false, c.lowerARM64SVELUTIForm(arm64SVELUTIForm{
		op: op, index: index, lane: lane, tables: tables, destination: destination, elementBits: destinationBits,
	})
}

func (c *arm64Ctx) lowerARM64SVELUTIForm(form arm64SVELUTIForm) error {
	index, indexType, err := c.loadZRegElements(form.index, 8)
	if err != nil {
		return err
	}
	tableValues := make([]string, len(form.tables))
	vectorType := ""
	for tableIndex, table := range form.tables {
		tableValue, tableType, err := c.loadZRegElements(table, form.elementBits)
		if err != nil {
			return err
		}
		tableValues[tableIndex], vectorType = tableValue, tableType
	}
	lanes := 128 / form.elementBits
	intrinsic := strings.ToLower(strings.TrimPrefix(string(form.op), "Z")) + ".lane"
	result := c.newTmp()
	if len(tableValues) == 1 {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s, i32 %d)\n", result, vectorType, intrinsic, lanes, form.elementBits, vectorType, tableValues[0], indexType, index, form.lane)
	} else {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.x2.nxv%di%d(%s %s, %s %s, %s %s, i32 %d)\n", result, vectorType, intrinsic, lanes, form.elementBits, vectorType, tableValues[0], vectorType, tableValues[1], indexType, index, form.lane)
	}
	return c.storeZRegElements(form.destination, form.elementBits, "%"+result)
}
