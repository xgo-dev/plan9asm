package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) lowerARM64VectorShiftNarrow(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "VSHRN" && op != "VSHRN2" && op != "VRSHRN" && op != "VRSHRN2" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 ||
		ins.Args[0].Kind != OpImm || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
		return true, false, fmt.Errorf("arm64 %s expects immediate, wide vector source, narrow vector destination, and no suffix: %q", op, ins.Raw)
	}

	sourceArrangement, sourceOK := parseARM64VectorArrangement(ins.Args[1].Reg)
	destinationArrangement, destinationOK := parseARM64VectorArrangement(ins.Args[2].Reg)
	highHalf := op == "VSHRN2" || op == "VRSHRN2"
	rounding := op == "VRSHRN" || op == "VRSHRN2"
	wantDestinationLanes := sourceArrangement.lanes
	if highHalf {
		wantDestinationLanes *= 2
	}
	shift := ins.Args[0].Imm
	if !sourceOK || !destinationOK ||
		sourceArrangement.lanes*sourceArrangement.elementBits != 128 ||
		sourceArrangement.elementBits != destinationArrangement.elementBits*2 ||
		destinationArrangement.lanes != wantDestinationLanes ||
		shift < 1 || shift > int64(destinationArrangement.elementBits) {
		return true, false, fmt.Errorf("arm64 %s requires $1..$N with H8->B8/S4->H4/D2->S2 (or the doubled *2 destination): %q", op, ins.Raw)
	}

	source, err := c.loadARM64VectorInteger(ins.Args[1].Reg, sourceArrangement)
	if err != nil {
		return true, false, err
	}
	sourceType := fmt.Sprintf("<%d x i%d>", sourceArrangement.lanes, sourceArrangement.elementBits)
	shifted := c.newTmp()
	shiftValue := arm64VectorIntegerSplat(sourceArrangement, shift)
	if rounding {
		// RSHRN rounds the signed source before narrowing. The addition is
		// intentionally wrapping at the source width, matching the ARM
		// instruction's two's-complement operation for non-saturating forms.
		bias := arm64VectorIntegerSplat(sourceArrangement, int64(1)<<(shift-1))
		rounded := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add %s %s, %s\n", rounded, sourceType, source, bias)
		fmt.Fprintf(c.b, "  %%%s = ashr %s %%%s, %s\n", shifted, sourceType, rounded, shiftValue)
	} else {
		fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %s\n", shifted, sourceType, source, shiftValue)
	}
	destinationType := fmt.Sprintf("<%d x i%d>", sourceArrangement.lanes, destinationArrangement.elementBits)
	narrowed := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to %s\n", narrowed, sourceType, shifted, destinationType)
	if !highHalf {
		return true, false, c.storeARM64VectorInteger(ins.Args[2].Reg, destinationArrangement, "%"+narrowed)
	}

	// VSHRN2 preserves the existing low half and inserts the narrowed values
	// into the high half of the destination vector.
	result, err := c.loadARM64VectorInteger(ins.Args[2].Reg, destinationArrangement)
	if err != nil {
		return true, false, err
	}
	fullDestinationType := fmt.Sprintf("<%d x i%d>", destinationArrangement.lanes, destinationArrangement.elementBits)
	for lane := 0; lane < sourceArrangement.lanes; lane++ {
		element := c.newTmp()
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %%%s, i32 %d\n", element, destinationType, narrowed, lane)
		fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, i%d %%%s, i32 %d\n",
			inserted, fullDestinationType, result, destinationArrangement.elementBits, element, sourceArrangement.lanes+lane)
		result = "%" + inserted
	}
	return true, false, c.storeARM64VectorInteger(ins.Args[2].Reg, destinationArrangement, result)
}
