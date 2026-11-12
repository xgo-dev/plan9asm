package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) lowerARM64VectorExtract(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "VEXT" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != "VEXT" || len(ins.Args) != 4 ||
		ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" {
		return true, false, fmt.Errorf("arm64 VEXT expects $offset, Vm.B8/B16, Vn.B8/B16, Vd.B8/B16: %q", ins.Raw)
	}

	var arrangement arm64VectorArrangement
	for index, operand := range ins.Args[1:] {
		if operand.Kind != OpReg {
			return true, false, fmt.Errorf("arm64 VEXT accepts only arranged vector registers: %q", ins.Raw)
		}
		parsed, valid := parseARM64VectorArrangement(operand.Reg)
		if !valid || parsed.elementBits != 8 || parsed.lanes != 8 && parsed.lanes != 16 {
			return true, false, fmt.Errorf("arm64 VEXT arrangement must be B8 or B16: %q", ins.Raw)
		}
		if index == 0 {
			arrangement = parsed
		} else if parsed != arrangement {
			return true, false, fmt.Errorf("arm64 VEXT arrangements must match: %q", ins.Raw)
		}
	}
	offset := int(ins.Args[0].Imm)
	if offset < 0 || offset >= arrangement.lanes {
		return true, false, fmt.Errorf("arm64 VEXT offset must be in [0,%d): %q", arrangement.lanes, ins.Raw)
	}

	// Go's Plan 9 order is $offset, Vm, Vn, Vd. EXT concatenates Vn:Vm
	// and selects one vector starting at the byte offset.
	m, err := c.loadARM64VectorInteger(ins.Args[1].Reg, arrangement)
	if err != nil {
		return true, false, err
	}
	n, err := c.loadARM64VectorInteger(ins.Args[2].Reg, arrangement)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  ; arm64 vector extract\n")
	fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i8> %s, <%d x i8> %s, <%d x i32> <", result, arrangement.lanes, n, arrangement.lanes, m, arrangement.lanes)
	for lane := 0; lane < arrangement.lanes; lane++ {
		if lane != 0 {
			c.b.WriteString(", ")
		}
		fmt.Fprintf(c.b, "i32 %d", offset+lane)
	}
	c.b.WriteString(">\n")
	return true, false, c.storeARM64VectorInteger(ins.Args[3].Reg, arrangement, "%"+result)
}
