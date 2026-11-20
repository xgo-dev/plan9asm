package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) lowerARM64WideningShift(op Op, ins Instr) (ok bool, terminated bool, err error) {
	switch op {
	case "VSHLL", "VSHLL2", "VUSHLL", "VUSHLL2", "VSSHLL", "VSSHLL2", "VUXTL", "VUXTL2", "VSXTL", "VSXTL2":
	default:
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) {
		return true, false, fmt.Errorf("arm64 %s does not accept an opcode suffix: %q", op, ins.Raw)
	}
	isExtendAlias := strings.Contains(string(op), "XTL")
	wantArgs := 3
	if isExtendAlias {
		wantArgs = 2
	}
	if len(ins.Args) != wantArgs {
		return true, false, fmt.Errorf("arm64 %s expects %d operands: %q", op, wantArgs, ins.Raw)
	}
	shift := int64(0)
	sourceIndex := 0
	if !isExtendAlias {
		if ins.Args[0].Kind != OpImm {
			return true, false, fmt.Errorf("arm64 %s expects an immediate shift: %q", op, ins.Raw)
		}
		shift = ins.Args[0].Imm
		sourceIndex = 1
	}
	if ins.Args[sourceIndex].Kind != OpReg || ins.Args[sourceIndex+1].Kind != OpReg {
		return true, false, fmt.Errorf("arm64 %s expects vector register source and destination: %q", op, ins.Raw)
	}
	sourceArrangement, valid := parseARM64VectorArrangement(ins.Args[sourceIndex].Reg)
	if !valid {
		return true, false, fmt.Errorf("arm64 %s has an invalid source arrangement: %q", op, ins.Raw)
	}
	destinationArrangement, valid := parseARM64VectorArrangement(ins.Args[sourceIndex+1].Reg)
	if !valid {
		return true, false, fmt.Errorf("arm64 %s has an invalid destination arrangement: %q", op, ins.Raw)
	}
	highHalf := strings.HasSuffix(string(op), "2")
	wantSourceLanes := destinationArrangement.lanes
	if highHalf {
		wantSourceLanes *= 2
	}
	if sourceArrangement.lanes != wantSourceLanes ||
		destinationArrangement.elementBits != sourceArrangement.elementBits*2 ||
		destinationArrangement.lanes*destinationArrangement.elementBits != 128 {
		return true, false, fmt.Errorf("arm64 %s source and destination arrangements do not form a widening pair: %q", op, ins.Raw)
	}
	maxShift := int64(sourceArrangement.elementBits - 1)
	// LLVM/Clang also emits the GNU SHLL alias. Unlike the Go V{S,U}SHLL
	// spellings, its fixed-width long form permits the full source width.
	if op == "VSHLL" || op == "VSHLL2" {
		maxShift++
	}
	if shift < 0 || shift > maxShift {
		return true, false, fmt.Errorf("arm64 %s shift must be in [0,%d]: %q", op, maxShift, ins.Raw)
	}

	source, err := c.loadARM64VectorInteger(ins.Args[sourceIndex].Reg, sourceArrangement)
	if err != nil {
		return true, false, err
	}
	if highHalf {
		selected := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i%d> %s, <%d x i%d> poison, <%d x i32> <", selected, sourceArrangement.lanes, sourceArrangement.elementBits, source, sourceArrangement.lanes, sourceArrangement.elementBits, destinationArrangement.lanes)
		for i := 0; i < destinationArrangement.lanes; i++ {
			if i != 0 {
				c.b.WriteString(", ")
			}
			fmt.Fprintf(c.b, "i32 %d", destinationArrangement.lanes+i)
		}
		c.b.WriteString(">\n")
		source = "%" + selected
	}

	extended := c.newTmp()
	extension := "zext"
	if strings.HasPrefix(string(op), "VSS") || strings.HasPrefix(string(op), "VSX") {
		extension = "sext"
	}
	fmt.Fprintf(c.b, "  %%%s = %s <%d x i%d> %s to <%d x i%d>\n", extended, extension, destinationArrangement.lanes, sourceArrangement.elementBits, source, destinationArrangement.lanes, destinationArrangement.elementBits)
	result := "%" + extended
	if !isExtendAlias {
		shifted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shl <%d x i%d> %s, <", shifted, destinationArrangement.lanes, destinationArrangement.elementBits, result)
		for i := 0; i < destinationArrangement.lanes; i++ {
			if i != 0 {
				c.b.WriteString(", ")
			}
			fmt.Fprintf(c.b, "i%d %d", destinationArrangement.elementBits, shift)
		}
		c.b.WriteString(">\n")
		result = "%" + shifted
	}
	return true, false, c.storeARM64VectorInteger(ins.Args[sourceIndex+1].Reg, destinationArrangement, result)
}
