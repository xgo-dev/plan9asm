package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) lowerARM64VectorIntegerNarrow(op Op, ins Instr) (ok bool, terminated bool, err error) {
	kind, handled := map[Op]string{
		"VXTN": "truncate", "VXTN2": "truncate",
		"VSQXTN": "signed", "VSQXTN2": "signed",
		"VSQXTUN": "signed-to-unsigned", "VSQXTUN2": "signed-to-unsigned",
		"VUQXTN": "unsigned", "VUQXTN2": "unsigned",
	}[op]
	if !handled {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 ||
		ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("arm64 %s expects a wide vector source, narrow vector destination, and no suffix: %q", op, ins.Raw)
	}
	sourceArrangement, sourceOK := parseARM64VectorArrangement(ins.Args[0].Reg)
	destinationArrangement, destinationOK := parseARM64VectorArrangement(ins.Args[1].Reg)
	highHalf := strings.HasSuffix(string(op), "2")
	wantDestinationLanes := sourceArrangement.lanes
	if highHalf {
		wantDestinationLanes *= 2
	}
	if !sourceOK || !destinationOK ||
		sourceArrangement.lanes*sourceArrangement.elementBits != 128 ||
		sourceArrangement.elementBits != destinationArrangement.elementBits*2 ||
		destinationArrangement.lanes != wantDestinationLanes {
		return true, false, fmt.Errorf("arm64 %s requires H8->B8/S4->H4/D2->S2 (or the doubled *2 destination): %q", op, ins.Raw)
	}

	source, err := c.loadARM64VectorInteger(ins.Args[0].Reg, sourceArrangement)
	if err != nil {
		return true, false, err
	}
	sourceType := fmt.Sprintf("<%d x i%d>", sourceArrangement.lanes, sourceArrangement.elementBits)
	destinationType := fmt.Sprintf("<%d x i%d>", sourceArrangement.lanes, destinationArrangement.elementBits)
	clamped := source
	switch kind {
	case "signed":
		minimum := -(int64(1) << (destinationArrangement.elementBits - 1))
		maximum := (int64(1) << (destinationArrangement.elementBits - 1)) - 1
		clamped = c.clampARM64VectorInteger(sourceType, sourceArrangement, source, "slt", minimum, "sgt", maximum)
	case "signed-to-unsigned":
		maximum := (int64(1) << destinationArrangement.elementBits) - 1
		clamped = c.clampARM64VectorInteger(sourceType, sourceArrangement, source, "slt", 0, "sgt", maximum)
	case "unsigned":
		maximum := (int64(1) << destinationArrangement.elementBits) - 1
		above := c.newTmp()
		selected := c.newTmp()
		upper := arm64VectorIntegerSplat(sourceArrangement, maximum)
		fmt.Fprintf(c.b, "  %%%s = icmp ugt %s %s, %s\n", above, sourceType, source, upper)
		fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %s, %s %s\n",
			selected, sourceArrangement.lanes, above, sourceType, upper, sourceType, source)
		clamped = "%" + selected
	}
	narrowed := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc %s %s to %s\n", narrowed, sourceType, clamped, destinationType)
	if !highHalf {
		return true, false, c.storeARM64VectorInteger(ins.Args[1].Reg, destinationArrangement, "%"+narrowed)
	}

	// The *2 forms preserve the low half of the destination and insert the
	// newly narrowed lanes into its high half.
	result, err := c.loadARM64VectorInteger(ins.Args[1].Reg, destinationArrangement)
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
	return true, false, c.storeARM64VectorInteger(ins.Args[1].Reg, destinationArrangement, result)
}

func (c *arm64Ctx) clampARM64VectorInteger(vectorType string, arrangement arm64VectorArrangement, source, lowerPredicate string, lower int64, upperPredicate string, upper int64) string {
	lowerValue := arm64VectorIntegerSplat(arrangement, lower)
	below := c.newTmp()
	lowerClamped := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp %s %s %s, %s\n", below, lowerPredicate, vectorType, source, lowerValue)
	fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %s, %s %s\n",
		lowerClamped, arrangement.lanes, below, vectorType, lowerValue, vectorType, source)
	upperValue := arm64VectorIntegerSplat(arrangement, upper)
	above := c.newTmp()
	upperClamped := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp %s %s %%%s, %s\n", above, upperPredicate, vectorType, lowerClamped, upperValue)
	fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %s, %s %%%s\n",
		upperClamped, arrangement.lanes, above, vectorType, upperValue, vectorType, lowerClamped)
	return "%" + upperClamped
}
