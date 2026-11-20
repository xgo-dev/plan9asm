package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) lowerARM64VectorTableLookup(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "VTBL" && op != "VTBX" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpRegList || ins.Args[2].Kind != OpReg {
		return true, false, fmt.Errorf("arm64 %s expects Vindex.B8/B16, [Vtable...], Vdest.B8/B16 and no suffix: %q", op, ins.Raw)
	}
	indexArrangement, indexOK := parseARM64VectorArrangement(ins.Args[0].Reg)
	destinationArrangement, destinationOK := parseARM64VectorArrangement(ins.Args[2].Reg)
	byteVector := func(a arm64VectorArrangement) bool {
		return a.elementBits == 8 && (a.lanes == 8 || a.lanes == 16)
	}
	if !indexOK || !destinationOK || indexArrangement != destinationArrangement || !byteVector(indexArrangement) {
		return true, false, fmt.Errorf("arm64 %s requires matching B8 or B16 index and destination arrangements: %q", op, ins.Raw)
	}
	tables := ins.Args[1].RegList
	if len(tables) < 1 || len(tables) > 4 {
		return true, false, fmt.Errorf("arm64 %s requires one through four table registers: %q", op, ins.Raw)
	}
	firstTableArrangement, firstArrangementOK := parseARM64VectorArrangement(tables[0])
	firstTable, firstTableOK := arm64ParseVReg(tables[0])
	if !firstArrangementOK || !firstTableOK {
		return true, false, fmt.Errorf("arm64 %s requires arranged table registers: %q", op, ins.Raw)
	}
	for i, table := range tables {
		arrangement, arrangementOK := parseARM64VectorArrangement(table)
		register, registerOK := arm64ParseVReg(table)
		if !arrangementOK || arrangement != firstTableArrangement || !registerOK || register != (firstTable+i)%32 {
			return true, false, fmt.Errorf("arm64 %s requires consecutive table registers with a consistent arrangement: %q", op, ins.Raw)
		}
	}

	index, err := c.loadARM64VectorInteger(ins.Args[0].Reg, indexArrangement)
	if err != nil {
		return true, false, err
	}
	tableBytes := len(tables) * 16
	tableType := fmt.Sprintf("<%d x i8>", tableBytes)
	tableVector := "poison"
	for tableIndex := range tables {
		register := Reg(fmt.Sprintf("V%d.B16", (firstTable+tableIndex)%32))
		loaded, err := c.loadARM64VectorInteger(register, arm64VectorArrangement{elementBits: 8, lanes: 16})
		if err != nil {
			return true, false, err
		}
		for lane := 0; lane < 16; lane++ {
			element := c.newTmp()
			inserted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement <16 x i8> %s, i32 %d\n", element, loaded, lane)
			fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, i8 %%%s, i32 %d\n", inserted, tableType, tableVector, element, tableIndex*16+lane)
			tableVector = "%" + inserted
		}
	}
	result := "zeroinitializer"
	destination := ""
	if op == "VTBX" {
		destination, err = c.loadARM64VectorInteger(ins.Args[2].Reg, destinationArrangement)
		if err != nil {
			return true, false, err
		}
	}
	for lane := 0; lane < indexArrangement.lanes; lane++ {
		indexByte := c.newTmp()
		index32 := c.newTmp()
		inRange := c.newTmp()
		safeIndex := c.newTmp()
		lookup := c.newTmp()
		selected := c.newTmp()
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i8> %s, i32 %d\n", indexByte, indexArrangement.lanes, index, lane)
		fmt.Fprintf(c.b, "  %%%s = zext i8 %%%s to i32\n", index32, indexByte)
		fmt.Fprintf(c.b, "  %%%s = icmp ult i32 %%%s, %d\n", inRange, index32, tableBytes)
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i32 %%%s, i32 0\n", safeIndex, inRange, index32)
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %%%s\n", lookup, tableType, tableVector, safeIndex)
		fallback := "0"
		if op == "VTBX" {
			old := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i8> %s, i32 %d\n", old, destinationArrangement.lanes, destination, lane)
			fallback = "%" + old
		}
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i8 %%%s, i8 %s\n", selected, inRange, lookup, fallback)
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i8> %s, i8 %%%s, i32 %d\n", inserted, destinationArrangement.lanes, result, selected, lane)
		result = "%" + inserted
	}
	return true, false, c.storeARM64VectorInteger(ins.Args[2].Reg, destinationArrangement, result)
}
