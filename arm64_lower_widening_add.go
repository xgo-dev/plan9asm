package plan9asm

import (
	"fmt"
	"strings"
)

type arm64WideningAddSubtractSpec struct {
	signed   bool
	subtract bool
	wide     bool
	highHalf bool
}

var arm64WideningAddSubtractOps = map[Op]arm64WideningAddSubtractSpec{
	"VSADDL":  {signed: true},
	"VSADDL2": {signed: true, highHalf: true},
	"VSADDW":  {signed: true, wide: true},
	"VSADDW2": {signed: true, wide: true, highHalf: true},
	"VSSUBL":  {signed: true, subtract: true},
	"VSSUBL2": {signed: true, subtract: true, highHalf: true},
	"VSSUBW":  {signed: true, subtract: true, wide: true},
	"VSSUBW2": {signed: true, subtract: true, wide: true, highHalf: true},
	"VUADDL":  {},
	"VUADDL2": {highHalf: true},
	"VUADDW":  {wide: true},
	"VUADDW2": {wide: true, highHalf: true},
	"VUSUBL":  {subtract: true},
	"VUSUBL2": {subtract: true, highHalf: true},
	"VUSUBW":  {subtract: true, wide: true},
	"VUSUBW2": {subtract: true, wide: true, highHalf: true},
}

// lowerARM64WideningAddSubtract implements the complete AdvSIMD
// three-different add/subtract-long and add/subtract-wide family. Go 1.27 has
// named forms for VUADDW/VUADDW2; the remaining architectural forms enter
// through WORD decoding from external assembly.
func (c *arm64Ctx) lowerARM64WideningAddSubtract(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, handled := arm64WideningAddSubtractOps[op]
	if !handled {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects two sources, one wide destination, and no suffix: %q", op, ins.Raw)
	}
	for _, arg := range ins.Args {
		if arg.Kind != OpReg {
			return true, false, fmt.Errorf("arm64 %s accepts only vector registers: %q", op, ins.Raw)
		}
	}

	firstArrangement, firstOK := parseARM64VectorArrangement(ins.Args[0].Reg)
	secondArrangement, secondOK := parseARM64VectorArrangement(ins.Args[1].Reg)
	destinationArrangement, destinationOK := parseARM64VectorArrangement(ins.Args[2].Reg)
	wantNarrowLanes := destinationArrangement.lanes
	if spec.highHalf {
		wantNarrowLanes *= 2
	}
	valid := firstOK && secondOK && destinationOK &&
		destinationArrangement.lanes*destinationArrangement.elementBits == 128 &&
		destinationArrangement.elementBits >= 16 && destinationArrangement.elementBits <= 64 &&
		firstArrangement.elementBits*2 == destinationArrangement.elementBits &&
		firstArrangement.lanes == wantNarrowLanes
	if spec.wide {
		valid = valid && secondArrangement == destinationArrangement
	} else {
		valid = valid && secondArrangement == firstArrangement
	}
	if !valid {
		return true, false, fmt.Errorf("arm64 %s arrangements do not form an 8->16, 16->32, or 32->64 widening row: %q", op, ins.Raw)
	}

	first, err := c.loadARM64VectorInteger(ins.Args[0].Reg, firstArrangement)
	if err != nil {
		return true, false, err
	}
	if spec.highHalf {
		first = c.selectARM64VectorHighHalf(firstArrangement, destinationArrangement.lanes, first)
	}
	narrowType := fmt.Sprintf("<%d x i%d>", destinationArrangement.lanes, firstArrangement.elementBits)
	wideType := fmt.Sprintf("<%d x i%d>", destinationArrangement.lanes, destinationArrangement.elementBits)
	extension := "zext"
	if spec.signed {
		extension = "sext"
	}
	wideFirst := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", wideFirst, extension, narrowType, first, wideType)

	second, err := c.loadARM64VectorInteger(ins.Args[1].Reg, secondArrangement)
	if err != nil {
		return true, false, err
	}
	if !spec.wide {
		if spec.highHalf {
			second = c.selectARM64VectorHighHalf(secondArrangement, destinationArrangement.lanes, second)
		}
		wideSecond := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", wideSecond, extension, narrowType, second, wideType)
		second = "%" + wideSecond
	}

	operation := "add"
	left, right := "%"+wideFirst, second
	if spec.subtract {
		operation = "sub"
		// Go syntax reverses the architectural Vn/Vm sources. Both SUBL and
		// SUBW therefore compute the second source minus the widened first.
		left, right = second, "%"+wideFirst
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s %s %s, %s\n", result, operation, wideType, left, right)
	return true, false, c.storeARM64VectorInteger(ins.Args[2].Reg, destinationArrangement, "%"+result)
}
