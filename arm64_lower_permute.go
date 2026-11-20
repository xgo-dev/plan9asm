package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) lowerARM64VectorPermute(op Op, ins Instr) (ok bool, terminated bool, err error) {
	switch op {
	case "VZIP1", "VZIP2", "VUZP1", "VUZP2", "VTRN1", "VTRN2":
	default:
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects three same-arrangement vector registers: %q", op, ins.Raw)
	}
	allowed := func(a arm64VectorArrangement) bool {
		return (a.elementBits == 8 && (a.lanes == 8 || a.lanes == 16)) ||
			(a.elementBits == 16 && (a.lanes == 4 || a.lanes == 8)) ||
			(a.elementBits == 32 && (a.lanes == 2 || a.lanes == 4)) ||
			(a.elementBits == 64 && a.lanes == 2)
	}
	var arrangement arm64VectorArrangement
	for i, arg := range ins.Args {
		if arg.Kind != OpReg {
			return true, false, fmt.Errorf("arm64 %s accepts only vector registers: %q", op, ins.Raw)
		}
		parsed, valid := parseARM64VectorArrangement(arg.Reg)
		if !valid || !allowed(parsed) {
			return true, false, fmt.Errorf("arm64 %s has an invalid vector arrangement: %q", op, ins.Raw)
		}
		if i == 0 {
			arrangement = parsed
		} else if parsed != arrangement {
			return true, false, fmt.Errorf("arm64 %s arrangements must match: %q", op, ins.Raw)
		}
	}

	// Go's Plan 9 order is Vm, Vn, Vd, while the architectural operation is
	// written Vd, Vn, Vm. Keep Vn as LLVM's first shuffle input so the masks
	// below follow the ARM lane descriptions directly.
	m, err := c.loadARM64VectorInteger(ins.Args[0].Reg, arrangement)
	if err != nil {
		return true, false, err
	}
	n, err := c.loadARM64VectorInteger(ins.Args[1].Reg, arrangement)
	if err != nil {
		return true, false, err
	}
	mask := arm64VectorPermuteMask(string(op), arrangement.lanes)
	if len(mask) != arrangement.lanes {
		return true, false, fmt.Errorf("arm64 %s could not construct a vector shuffle mask: %q", op, ins.Raw)
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  ; arm64 vector permute %s\n", op)
	fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i%d> %s, <%d x i%d> %s, <%d x i32> <", result, arrangement.lanes, arrangement.elementBits, n, arrangement.lanes, arrangement.elementBits, m, arrangement.lanes)
	for i, lane := range mask {
		if i != 0 {
			c.b.WriteString(", ")
		}
		fmt.Fprintf(c.b, "i32 %d", lane)
	}
	c.b.WriteString(">\n")
	return true, false, c.storeARM64VectorInteger(ins.Args[2].Reg, arrangement, "%"+result)
}

func arm64VectorPermuteMask(op string, lanes int) []int {
	mask := make([]int, 0, lanes)
	switch op {
	case "VZIP1", "VZIP2":
		start := 0
		if op == "VZIP2" {
			start = lanes / 2
		}
		for lane := start; lane < start+lanes/2; lane++ {
			mask = append(mask, lane, lanes+lane)
		}
	case "VUZP1", "VUZP2":
		start := 0
		if op == "VUZP2" {
			start = 1
		}
		for lane := start; lane < lanes; lane += 2 {
			mask = append(mask, lane)
		}
		for lane := start; lane < lanes; lane += 2 {
			mask = append(mask, lanes+lane)
		}
	case "VTRN1", "VTRN2":
		start := 0
		if op == "VTRN2" {
			start = 1
		}
		for lane := start; lane < lanes; lane += 2 {
			mask = append(mask, lane, lanes+lane)
		}
	}
	return mask
}
