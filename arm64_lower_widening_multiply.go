package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) lowerARM64VectorWideningMultiply(op Op, ins Instr) (ok bool, terminated bool, err error) {
	type operationSpec struct {
		signed     bool
		accumulate string
		highHalf   bool
	}
	spec, handled := map[Op]operationSpec{
		"VSMULL": {signed: true}, "VSMULL2": {signed: true, highHalf: true},
		"VSMLAL": {signed: true, accumulate: "add"}, "VSMLAL2": {signed: true, accumulate: "add", highHalf: true},
		"VSMLSL": {signed: true, accumulate: "sub"}, "VSMLSL2": {signed: true, accumulate: "sub", highHalf: true},
		"VUMULL": {}, "VUMULL2": {highHalf: true},
		"VUMLAL": {accumulate: "add"}, "VUMLAL2": {accumulate: "add", highHalf: true},
		"VUMLSL": {accumulate: "sub"}, "VUMLSL2": {accumulate: "sub", highHalf: true},
	}[op]
	if !handled {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects two narrow sources, one wide destination, and no suffix: %q", op, ins.Raw)
	}
	for _, arg := range ins.Args {
		if arg.Kind != OpReg {
			return true, false, fmt.Errorf("arm64 %s accepts only vector registers: %q", op, ins.Raw)
		}
	}
	firstArrangement, firstOK := parseARM64VectorArrangement(ins.Args[0].Reg)
	laneKind, lane, laneForm := arm64ParseVRegLane(ins.Args[0].Reg)
	secondArrangement, secondOK := parseARM64VectorArrangement(ins.Args[1].Reg)
	destinationArrangement, destinationOK := parseARM64VectorArrangement(ins.Args[2].Reg)
	wantSourceLanes := destinationArrangement.lanes
	if spec.highHalf {
		wantSourceLanes *= 2
	}
	if laneForm {
		sourceBits := 0
		switch laneKind {
		case 'H':
			sourceBits = 16
		case 'S':
			sourceBits = 32
		}
		laneRegister, laneRegisterOK := arm64ParseVReg(ins.Args[0].Reg)
		physicalLanes := 0
		if sourceBits != 0 {
			physicalLanes = 128 / sourceBits
		}
		firstArrangement = arm64VectorArrangement{elementBits: sourceBits, lanes: destinationArrangement.lanes}
		firstOK = sourceBits != 0 && lane >= 0 && lane < physicalLanes && laneRegisterOK &&
			(sourceBits != 16 || laneRegister <= 15)
	}
	if !firstOK || !secondOK || !destinationOK ||
		firstArrangement.elementBits != secondArrangement.elementBits ||
		firstArrangement.elementBits*2 != destinationArrangement.elementBits ||
		secondArrangement.lanes != wantSourceLanes ||
		(!laneForm && firstArrangement != secondArrangement) ||
		destinationArrangement.lanes*destinationArrangement.elementBits != 128 {
		return true, false, fmt.Errorf("arm64 %s arrangements do not form a B->H, H->S, or S->D widening multiply row: %q", op, ins.Raw)
	}
	var first string
	if laneForm {
		physical := arm64VectorArrangement{elementBits: firstArrangement.elementBits, lanes: 128 / firstArrangement.elementBits}
		loaded, err := c.loadARM64VectorInteger(ins.Args[0].Reg, physical)
		if err != nil {
			return true, false, err
		}
		element := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %s, i32 %d\n", element, physical.lanes, physical.elementBits, loaded, lane)
		first = "poison"
		for index := 0; index < destinationArrangement.lanes; index++ {
			inserted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> %s, i%d %%%s, i32 %d\n",
				inserted, destinationArrangement.lanes, firstArrangement.elementBits, first,
				firstArrangement.elementBits, element, index)
			first = "%" + inserted
		}
	} else {
		var err error
		first, err = c.loadARM64VectorInteger(ins.Args[0].Reg, firstArrangement)
		if err != nil {
			return true, false, err
		}
	}
	second, err := c.loadARM64VectorInteger(ins.Args[1].Reg, secondArrangement)
	if err != nil {
		return true, false, err
	}
	if spec.highHalf {
		if !laneForm {
			first = c.selectARM64VectorHighHalf(firstArrangement, destinationArrangement.lanes, first)
		}
		second = c.selectARM64VectorHighHalf(secondArrangement, destinationArrangement.lanes, second)
	}
	narrowType := fmt.Sprintf("<%d x i%d>", destinationArrangement.lanes, firstArrangement.elementBits)
	wideType := fmt.Sprintf("<%d x i%d>", destinationArrangement.lanes, destinationArrangement.elementBits)
	extension := "zext"
	if spec.signed {
		extension = "sext"
	}
	wideFirst := c.newTmp()
	wideSecond := c.newTmp()
	product := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", wideFirst, extension, narrowType, first, wideType)
	fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", wideSecond, extension, narrowType, second, wideType)
	fmt.Fprintf(c.b, "  %%%s = mul %s %%%s, %%%s\n", product, wideType, wideFirst, wideSecond)
	result := "%" + product
	if spec.accumulate != "" {
		accumulator, err := c.loadARM64VectorInteger(ins.Args[2].Reg, destinationArrangement)
		if err != nil {
			return true, false, err
		}
		combined := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s %s %s, %%%s\n", combined, spec.accumulate, wideType, accumulator, product)
		result = "%" + combined
	}
	return true, false, c.storeARM64VectorInteger(ins.Args[2].Reg, destinationArrangement, result)
}

func (c *arm64Ctx) selectARM64VectorHighHalf(arrangement arm64VectorArrangement, resultLanes int, value string) string {
	selected := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i%d> %s, <%d x i%d> poison, <%d x i32> <",
		selected, arrangement.lanes, arrangement.elementBits, value, arrangement.lanes, arrangement.elementBits, resultLanes)
	for lane := 0; lane < resultLanes; lane++ {
		if lane != 0 {
			c.b.WriteString(", ")
		}
		fmt.Fprintf(c.b, "i32 %d", resultLanes+lane)
	}
	c.b.WriteString(">\n")
	return "%" + selected
}
