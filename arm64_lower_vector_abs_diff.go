package plan9asm

import (
	"fmt"
	"strings"
)

// lowerARM64VectorAbsDiff lowers the complete Advanced SIMD absolute-
// difference family decoded from WORD forms. Go 1.27 has no named NEON optab
// row for these instructions; x/arch prints the V-prefixed aliases.
func (c *arm64Ctx) lowerARM64VectorAbsDiff(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if ok, terminated, err := c.lowerARM64VectorAbsDiffLong(op, ins); ok {
		return ok, terminated, err
	}
	type operationSpec struct {
		signed     bool
		accumulate bool
	}
	spec, handled := map[Op]operationSpec{
		"VSABD": {signed: true},
		"VUABD": {},
		"VSABA": {signed: true, accumulate: true},
		"VUABA": {accumulate: true},
	}[op]
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
		if !valid || parsed.elementBits > 32 || (parsed.elementBits == 8 && parsed.lanes != 8 && parsed.lanes != 16) ||
			(parsed.elementBits == 16 && parsed.lanes != 4 && parsed.lanes != 8) ||
			(parsed.elementBits == 32 && parsed.lanes != 2 && parsed.lanes != 4) {
			return true, false, fmt.Errorf("arm64 %s accepts only B8/B16/H4/H8/S2/S4 arrangements: %q", op, ins.Raw)
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
	vectorType := fmt.Sprintf("<%d x i%d>", arrangement.lanes, arrangement.elementBits)
	result := ""
	if spec.signed {
		wideBits := arrangement.elementBits * 2
		wideType := fmt.Sprintf("<%d x i%d>", arrangement.lanes, wideBits)
		wideFirst := c.newTmp()
		wideSecond := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sext %s %s to %s\n", wideFirst, vectorType, first, wideType)
		fmt.Fprintf(c.b, "  %%%s = sext %s %s to %s\n", wideSecond, vectorType, second, wideType)
		condition := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp sgt %s %%%s, %%%s\n", condition, wideType, wideFirst, wideSecond)
		firstDifference := c.newTmp()
		secondDifference := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub %s %%%s, %%%s\n", firstDifference, wideType, wideFirst, wideSecond)
		fmt.Fprintf(c.b, "  %%%s = sub %s %%%s, %%%s\n", secondDifference, wideType, wideSecond, wideFirst)
		wideResult := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %%%s, %s %%%s\n", wideResult, arrangement.lanes, condition, wideType, firstDifference, wideType, secondDifference)
		narrow := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to %s\n", narrow, wideType, wideResult, vectorType)
		result = "%" + narrow
	} else {
		condition := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp ugt %s %s, %s\n", condition, vectorType, first, second)
		firstDifference := c.newTmp()
		secondDifference := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub %s %s, %s\n", firstDifference, vectorType, first, second)
		fmt.Fprintf(c.b, "  %%%s = sub %s %s, %s\n", secondDifference, vectorType, second, first)
		selected := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %%%s, %s %%%s\n", selected, arrangement.lanes, condition, vectorType, firstDifference, vectorType, secondDifference)
		result = "%" + selected
	}
	if spec.accumulate {
		accumulator, err := c.loadARM64VectorInteger(ins.Args[2].Reg, arrangement)
		if err != nil {
			return true, false, err
		}
		accumulated := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add %s %s, %s\n", accumulated, vectorType, accumulator, result)
		result = "%" + accumulated
	}
	return true, false, c.storeARM64VectorInteger(ins.Args[2].Reg, arrangement, result)
}

func (c *arm64Ctx) lowerARM64VectorAbsDiffLong(op Op, ins Instr) (ok bool, terminated bool, err error) {
	type operationSpec struct {
		signed     bool
		accumulate bool
	}
	spec, handled := map[Op]operationSpec{
		"VSABDL":  {signed: true},
		"VSABDL2": {signed: true},
		"VUABDL":  {},
		"VUABDL2": {},
		"VSABAL":  {signed: true, accumulate: true},
		"VSABAL2": {signed: true, accumulate: true},
		"VUABAL":  {accumulate: true},
		"VUABAL2": {accumulate: true},
	}[op]
	if !handled {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects two source and one destination vector register, with no suffix: %q", op, ins.Raw)
	}
	if ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
		return true, false, fmt.Errorf("arm64 %s accepts only vector registers: %q", op, ins.Raw)
	}
	firstArrangement, firstOK := parseARM64VectorArrangement(ins.Args[0].Reg)
	secondArrangement, secondOK := parseARM64VectorArrangement(ins.Args[1].Reg)
	destinationArrangement, destinationOK := parseARM64VectorArrangement(ins.Args[2].Reg)
	if !firstOK || !secondOK || !destinationOK || firstArrangement != secondArrangement {
		return true, false, fmt.Errorf("arm64 %s requires matching source arrangements: %q", op, ins.Raw)
	}
	highHalf := strings.HasSuffix(string(op), "2")
	wantSourceLanes := destinationArrangement.lanes
	if highHalf {
		wantSourceLanes *= 2
	}
	if firstArrangement.lanes != wantSourceLanes || destinationArrangement.elementBits != 2*firstArrangement.elementBits ||
		destinationArrangement.lanes*destinationArrangement.elementBits != 128 || firstArrangement.elementBits > 32 {
		return true, false, fmt.Errorf("arm64 %s requires B/H/S sources widened to H/S/D: %q", op, ins.Raw)
	}
	first, err := c.loadARM64VectorInteger(ins.Args[0].Reg, firstArrangement)
	if err != nil {
		return true, false, err
	}
	second, err := c.loadARM64VectorInteger(ins.Args[1].Reg, secondArrangement)
	if err != nil {
		return true, false, err
	}
	if highHalf {
		first = c.selectARM64VectorHighHalf(firstArrangement, destinationArrangement.lanes, first)
		second = c.selectARM64VectorHighHalf(secondArrangement, destinationArrangement.lanes, second)
	}
	sourceType := fmt.Sprintf("<%d x i%d>", destinationArrangement.lanes, firstArrangement.elementBits)
	destinationType := fmt.Sprintf("<%d x i%d>", destinationArrangement.lanes, destinationArrangement.elementBits)
	wideFirst, wideSecond := c.newTmp(), c.newTmp()
	extension := "zext"
	if spec.signed {
		extension = "sext"
	}
	fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", wideFirst, extension, sourceType, first, destinationType)
	fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", wideSecond, extension, sourceType, second, destinationType)
	condition := c.newTmp()
	compare := "icmp ugt"
	if spec.signed {
		compare = "icmp sgt"
	}
	fmt.Fprintf(c.b, "  %%%s = %s %s %%%s, %%%s\n", condition, compare, destinationType, wideFirst, wideSecond)
	firstDifference, secondDifference, result := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sub %s %%%s, %%%s\n", firstDifference, destinationType, wideFirst, wideSecond)
	fmt.Fprintf(c.b, "  %%%s = sub %s %%%s, %%%s\n", secondDifference, destinationType, wideSecond, wideFirst)
	fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %%%s, %s %%%s\n", result, destinationArrangement.lanes, condition, destinationType, firstDifference, destinationType, secondDifference)
	value := "%" + result
	if spec.accumulate {
		accumulator, err := c.loadARM64VectorInteger(ins.Args[2].Reg, destinationArrangement)
		if err != nil {
			return true, false, err
		}
		accumulated := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add %s %s, %s\n", accumulated, destinationType, accumulator, value)
		value = "%" + accumulated
	}
	return true, false, c.storeARM64VectorInteger(ins.Args[2].Reg, destinationArrangement, value)
}
