package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) lowerARM64VectorIntegerMinMaxAcross(op Op, ins Instr) (ok bool, terminated bool, err error) {
	predicate, handled := map[Op]string{
		"VSMAXV": "sgt",
		"VSMINV": "slt",
		"VUMAXV": "ugt",
		"VUMINV": "ult",
	}[op]
	if !handled {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 ||
		ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("arm64 %s expects an arranged vector source, bare V destination, and no suffix: %q", op, ins.Raw)
	}
	arrangement, valid := parseARM64VectorArrangement(ins.Args[0].Reg)
	if !valid || !((arrangement.elementBits == 8 && (arrangement.lanes == 8 || arrangement.lanes == 16)) ||
		(arrangement.elementBits == 16 && (arrangement.lanes == 4 || arrangement.lanes == 8)) ||
		(arrangement.elementBits == 32 && arrangement.lanes == 4)) {
		return true, false, fmt.Errorf("arm64 %s accepts only B8, B16, H4, H8, or S4 source: %q", op, ins.Raw)
	}
	if strings.Contains(string(ins.Args[1].Reg), ".") {
		return true, false, fmt.Errorf("arm64 %s destination must be a bare V register: %q", op, ins.Raw)
	}
	if _, valid := arm64ParseVReg(ins.Args[1].Reg); !valid {
		return true, false, fmt.Errorf("arm64 %s destination must be a bare V register: %q", op, ins.Raw)
	}

	source, err := c.loadARM64VectorInteger(ins.Args[0].Reg, arrangement)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %s, i32 0\n", result, arrangement.lanes, arrangement.elementBits, source)
	current := "%" + result
	for lane := 1; lane < arrangement.lanes; lane++ {
		element := c.newTmp()
		condition := c.newTmp()
		selected := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %s, i32 %d\n", element, arrangement.lanes, arrangement.elementBits, source, lane)
		fmt.Fprintf(c.b, "  %%%s = icmp %s i%d %s, %%%s\n", condition, predicate, arrangement.elementBits, current, element)
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d %s, i%d %%%s\n", selected, condition, arrangement.elementBits, current, arrangement.elementBits, element)
		current = "%" + selected
	}
	physicalLanes := 128 / arrangement.elementBits
	vector := c.newTmp()
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> zeroinitializer, i%d %s, i32 0\n",
		vector, physicalLanes, arrangement.elementBits, arrangement.elementBits, current)
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %%%s to <16 x i8>\n", out, physicalLanes, arrangement.elementBits, vector)
	return true, false, c.storeVReg(ins.Args[1].Reg, "%"+out)
}
