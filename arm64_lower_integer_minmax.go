package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) lowerARM64VectorIntegerMinMax(op Op, ins Instr) (ok bool, terminated bool, err error) {
	type operationSpec struct {
		predicate string
		pairwise  bool
	}
	specs := map[Op]operationSpec{
		"VSMAX":  {predicate: "sgt"},
		"VSMIN":  {predicate: "slt"},
		"VUMAX":  {predicate: "ugt"},
		"VUMIN":  {predicate: "ult"},
		"VSMAXP": {predicate: "sgt", pairwise: true},
		"VSMINP": {predicate: "slt", pairwise: true},
		"VUMAXP": {predicate: "ugt", pairwise: true},
		"VUMINP": {predicate: "ult", pairwise: true},
	}
	spec, handled := specs[op]
	if !handled {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects three same-arrangement vector registers and no suffix: %q", op, ins.Raw)
	}
	var arrangement arm64VectorArrangement
	for i, arg := range ins.Args {
		if arg.Kind != OpReg {
			return true, false, fmt.Errorf("arm64 %s accepts only vector registers: %q", op, ins.Raw)
		}
		parsed, valid := parseARM64VectorArrangement(arg.Reg)
		if !valid || parsed.elementBits == 64 {
			return true, false, fmt.Errorf("arm64 %s accepts only B8, B16, H4, H8, S2, or S4 arrangements: %q", op, ins.Raw)
		}
		if i == 0 {
			arrangement = parsed
		} else if parsed != arrangement {
			return true, false, fmt.Errorf("arm64 %s arrangements must match: %q", op, ins.Raw)
		}
	}
	first, err := c.loadARM64VectorInteger(ins.Args[0].Reg, arrangement)
	if err != nil {
		return true, false, err
	}
	second, err := c.loadARM64VectorInteger(ins.Args[1].Reg, arrangement)
	if err != nil {
		return true, false, err
	}
	result := ""
	if !spec.pairwise {
		condition := c.newTmp()
		selected := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp %s <%d x i%d> %s, %s\n", condition, spec.predicate, arrangement.lanes, arrangement.elementBits, first, second)
		fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, <%d x i%d> %s, <%d x i%d> %s\n",
			selected, arrangement.lanes, condition, arrangement.lanes, arrangement.elementBits, first, arrangement.lanes, arrangement.elementBits, second)
		result = "%" + selected
	} else {
		result = "poison"
		half := arrangement.lanes / 2
		for lane := 0; lane < arrangement.lanes; lane++ {
			source := second
			if lane >= half {
				source = first
			}
			pair := (lane % half) * 2
			left := c.newTmp()
			right := c.newTmp()
			condition := c.newTmp()
			selected := c.newTmp()
			inserted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %s, i32 %d\n", left, arrangement.lanes, arrangement.elementBits, source, pair)
			fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %s, i32 %d\n", right, arrangement.lanes, arrangement.elementBits, source, pair+1)
			fmt.Fprintf(c.b, "  %%%s = icmp %s i%d %%%s, %%%s\n", condition, spec.predicate, arrangement.elementBits, left, right)
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d %%%s, i%d %%%s\n", selected, condition, arrangement.elementBits, left, arrangement.elementBits, right)
			fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> %s, i%d %%%s, i32 %d\n", inserted, arrangement.lanes, arrangement.elementBits, result, arrangement.elementBits, selected, lane)
			result = "%" + inserted
		}
	}
	return true, false, c.storeARM64VectorInteger(ins.Args[2].Reg, arrangement, result)
}
