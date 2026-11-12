package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) lowerARM64VectorIntegerAbsNeg(op Op, ins Instr) (ok bool, terminated bool, err error) {
	saturating, handled := map[Op]bool{
		"VABS": false, "VNEG": false,
		"VSQABS": true, "VSQNEG": true,
	}[op]
	if !handled && op != "VABS" && op != "VNEG" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 ||
		ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("arm64 %s expects two same-arrangement vector registers and no suffix: %q", op, ins.Raw)
	}
	sourceArrangement, sourceOK := parseARM64VectorArrangement(ins.Args[0].Reg)
	destinationArrangement, destinationOK := parseARM64VectorArrangement(ins.Args[1].Reg)
	validArrangement := sourceArrangement.elementBits != 64 || sourceArrangement.lanes == 2
	if !sourceOK || !destinationOK || sourceArrangement != destinationArrangement || !validArrangement {
		return true, false, fmt.Errorf("arm64 %s requires matching B8, B16, H4, H8, S2, S4, or D2 arrangements: %q", op, ins.Raw)
	}

	arrangement := sourceArrangement
	vectorType := fmt.Sprintf("<%d x i%d>", arrangement.lanes, arrangement.elementBits)
	source, err := c.loadARM64VectorInteger(ins.Args[0].Reg, arrangement)
	if err != nil {
		return true, false, err
	}
	negated := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sub %s zeroinitializer, %s\n", negated, vectorType, source)
	result := "%" + negated
	if op == "VABS" || op == "VSQABS" {
		negative := c.newTmp()
		absolute := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp slt %s %s, zeroinitializer\n", negative, vectorType, source)
		fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %%%s, %s %s\n",
			absolute, arrangement.lanes, negative, vectorType, negated, vectorType, source)
		result = "%" + absolute
	}
	if saturating {
		// In two's complement, zero and the signed minimum are the only values
		// equal to their own negation. Excluding zero identifies saturation; a
		// logical shift of the minimum produces the signed maximum.
		equalNegation := c.newTmp()
		nonzero := c.newTmp()
		overflow := c.newTmp()
		saturated := c.newTmp()
		selected := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, %%%s\n", equalNegation, vectorType, source, negated)
		fmt.Fprintf(c.b, "  %%%s = icmp ne %s %s, zeroinitializer\n", nonzero, vectorType, source)
		fmt.Fprintf(c.b, "  %%%s = and <%d x i1> %%%s, %%%s\n", overflow, arrangement.lanes, equalNegation, nonzero)
		fmt.Fprintf(c.b, "  %%%s = lshr %s %%%s, %s\n", saturated, vectorType, negated, arm64VectorIntegerSplat(arrangement, 1))
		fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %%%s, %s %s\n",
			selected, arrangement.lanes, overflow, vectorType, saturated, vectorType, result)
		result = "%" + selected
	}
	return true, false, c.storeARM64VectorInteger(ins.Args[1].Reg, arrangement, result)
}

func arm64VectorIntegerSplat(arrangement arm64VectorArrangement, value int64) string {
	parts := make([]string, arrangement.lanes)
	for i := range parts {
		parts[i] = fmt.Sprintf("i%d %d", arrangement.elementBits, value)
	}
	return "<" + strings.Join(parts, ", ") + ">"
}
