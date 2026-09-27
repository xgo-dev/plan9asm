package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) lowerARM64VectorReverse(op Op, ins Instr) (ok bool, terminated bool, err error) {
	groupBytes, handled := map[Op]int{
		"VREV16": 2,
		"VREV32": 4,
		"VREV64": 8,
	}[op]
	if !handled {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("arm64 %s expects two same-arrangement vector registers and no suffix: %q", op, ins.Raw)
	}
	sourceArrangement, sourceOK := parseARM64VectorArrangement(ins.Args[0].Reg)
	destinationArrangement, destinationOK := parseARM64VectorArrangement(ins.Args[1].Reg)
	if !sourceOK || !destinationOK || sourceArrangement != destinationArrangement {
		return true, false, fmt.Errorf("arm64 %s expects matching vector arrangements: %q", op, ins.Raw)
	}
	elementBytes := sourceArrangement.elementBits / 8
	if elementBytes == 0 || elementBytes >= groupBytes {
		return true, false, fmt.Errorf("arm64 %s requires elements narrower than its %d-bit reversal groups: %q", op, groupBytes*8, ins.Raw)
	}
	source, err := c.loadARM64VectorInteger(ins.Args[0].Reg, sourceArrangement)
	if err != nil {
		return true, false, err
	}
	vectorType := fmt.Sprintf("<%d x i%d>", sourceArrangement.lanes, sourceArrangement.elementBits)
	groupElements := groupBytes / elementBytes
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector %s %s, %s poison, <%d x i32> <", result, vectorType, source, vectorType, sourceArrangement.lanes)
	for lane := 0; lane < sourceArrangement.lanes; lane++ {
		if lane != 0 {
			c.b.WriteString(", ")
		}
		groupStart := lane / groupElements * groupElements
		reversedLane := groupStart + groupElements - 1 - lane%groupElements
		fmt.Fprintf(c.b, "i32 %d", reversedLane)
	}
	c.b.WriteString(">\n")
	return true, false, c.storeARM64VectorInteger(ins.Args[1].Reg, destinationArrangement, "%"+result)
}
