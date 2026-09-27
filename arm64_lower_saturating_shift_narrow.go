package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SaturatingShiftNarrowSpec struct {
	signedSource        bool
	unsignedDestination bool
	rounding            bool
}

var arm64SaturatingShiftNarrowSpecs = map[Op]arm64SaturatingShiftNarrowSpec{
	"VSQSHRN":    {signedSource: true},
	"VSQSHRN2":   {signedSource: true},
	"VSQRSHRN":   {signedSource: true, rounding: true},
	"VSQRSHRN2":  {signedSource: true, rounding: true},
	"VSQSHRUN":   {signedSource: true, unsignedDestination: true},
	"VSQSHRUN2":  {signedSource: true, unsignedDestination: true},
	"VSQRSHRUN":  {signedSource: true, unsignedDestination: true, rounding: true},
	"VSQRSHRUN2": {signedSource: true, unsignedDestination: true, rounding: true},
	"VUQSHRN":    {},
	"VUQSHRN2":   {},
	"VUQRSHRN":   {rounding: true},
	"VUQRSHRN2":  {rounding: true},
}

type arm64RawSaturatingShiftNarrow struct {
	op                     Op
	spec                   arm64SaturatingShiftNarrowSpec
	scalar                 bool
	highHalf               bool
	sourceArrangement      arm64VectorArrangement
	destinationArrangement arm64VectorArrangement
	shift                  int
	source                 int
	destination            int
}

func decodeARM64RawSaturatingShiftNarrow(word uint32) (arm64RawSaturatingShiftNarrow, bool) {
	type encoding struct {
		op       Op
		scalar   bool
		highHalf bool
	}
	encodings := map[uint32]encoding{
		0x0f009400: {op: "VSQSHRN"},
		0x4f009400: {op: "VSQSHRN2", highHalf: true},
		0x5f009400: {op: "VSQSHRN", scalar: true},
		0x0f009c00: {op: "VSQRSHRN"},
		0x4f009c00: {op: "VSQRSHRN2", highHalf: true},
		0x5f009c00: {op: "VSQRSHRN", scalar: true},
		0x2f008400: {op: "VSQSHRUN"},
		0x6f008400: {op: "VSQSHRUN2", highHalf: true},
		0x7f008400: {op: "VSQSHRUN", scalar: true},
		0x2f008c00: {op: "VSQRSHRUN"},
		0x6f008c00: {op: "VSQRSHRUN2", highHalf: true},
		0x7f008c00: {op: "VSQRSHRUN", scalar: true},
		0x2f009400: {op: "VUQSHRN"},
		0x6f009400: {op: "VUQSHRN2", highHalf: true},
		0x7f009400: {op: "VUQSHRN", scalar: true},
		0x2f009c00: {op: "VUQRSHRN"},
		0x6f009c00: {op: "VUQRSHRN2", highHalf: true},
		0x7f009c00: {op: "VUQRSHRN", scalar: true},
	}
	decoded, ok := encodings[word&0xff80fc00]
	if !ok {
		return arm64RawSaturatingShiftNarrow{}, false
	}
	encodedImmediate := int(word>>16) & 0x7f
	destinationBits := 0
	switch {
	case encodedImmediate >= 32 && encodedImmediate < 64:
		destinationBits = 32
	case encodedImmediate >= 16:
		destinationBits = 16
	case encodedImmediate >= 8:
		destinationBits = 8
	default:
		return arm64RawSaturatingShiftNarrow{}, false
	}
	shift := 2*destinationBits - encodedImmediate
	if shift < 1 || shift > destinationBits {
		return arm64RawSaturatingShiftNarrow{}, false
	}
	sourceLanes := 128 / (destinationBits * 2)
	destinationLanes := sourceLanes
	if decoded.scalar {
		sourceLanes = 1
		destinationLanes = 1
	} else if decoded.highHalf {
		destinationLanes *= 2
	}
	return arm64RawSaturatingShiftNarrow{
		op:                     decoded.op,
		spec:                   arm64SaturatingShiftNarrowSpecs[decoded.op],
		scalar:                 decoded.scalar,
		highHalf:               decoded.highHalf,
		sourceArrangement:      arm64VectorArrangement{elementBits: destinationBits * 2, lanes: sourceLanes},
		destinationArrangement: arm64VectorArrangement{elementBits: destinationBits, lanes: destinationLanes},
		shift:                  shift,
		source:                 int(word>>5) & 31,
		destination:            int(word) & 31,
	}, true
}

func (c *arm64Ctx) lowerRawSaturatingShiftNarrow(form arm64RawSaturatingShiftNarrow) error {
	return c.lowerARM64SaturatingShiftNarrowForm(form)
}

func (c *arm64Ctx) lowerARM64VectorSaturatingShiftNarrow(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, handled := arm64SaturatingShiftNarrowSpecs[op]
	if !handled {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 ||
		ins.Args[0].Kind != OpImm || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
		return true, false, fmt.Errorf("arm64 %s expects immediate, wide vector source, narrow vector destination, and no suffix: %q", op, ins.Raw)
	}
	sourceArrangement, sourceOK := parseARM64VectorArrangement(ins.Args[1].Reg)
	destinationArrangement, destinationOK := parseARM64VectorArrangement(ins.Args[2].Reg)
	highHalf := strings.HasSuffix(string(op), "2")
	wantDestinationLanes := sourceArrangement.lanes
	if highHalf {
		wantDestinationLanes *= 2
	}
	shift := ins.Args[0].Imm
	if !sourceOK || !destinationOK || sourceArrangement.lanes*sourceArrangement.elementBits != 128 ||
		sourceArrangement.elementBits != destinationArrangement.elementBits*2 ||
		destinationArrangement.lanes != wantDestinationLanes || shift < 1 || shift > int64(destinationArrangement.elementBits) {
		return true, false, fmt.Errorf("arm64 %s requires $1..$N with H8->B8/S4->H4/D2->S2 (or the doubled *2 destination): %q", op, ins.Raw)
	}
	source, _ := arm64ParseVReg(ins.Args[1].Reg)
	destination, _ := arm64ParseVReg(ins.Args[2].Reg)
	form := arm64RawSaturatingShiftNarrow{
		op: op, spec: spec, highHalf: highHalf,
		sourceArrangement: sourceArrangement, destinationArrangement: destinationArrangement,
		shift: int(shift), source: source, destination: destination,
	}
	return true, false, c.lowerARM64SaturatingShiftNarrowForm(form)
}

func (c *arm64Ctx) lowerARM64SaturatingShiftNarrowForm(form arm64RawSaturatingShiftNarrow) error {
	source, err := c.loadRawARM64VectorOperand(form.source, form.sourceArrangement, 0, form.scalar)
	if err != nil {
		return err
	}
	sourceType := fmt.Sprintf("<%d x i%d>", form.sourceArrangement.lanes, form.sourceArrangement.elementBits)
	shiftValue := arm64VectorIntegerSplat(form.sourceArrangement, int64(form.shift))
	shifted := c.newTmp()
	operation := "lshr"
	if form.spec.signedSource {
		operation = "ashr"
	}
	fmt.Fprintf(c.b, "  %%%s = %s %s %s, %s\n", shifted, operation, sourceType, source, shiftValue)
	shiftedValue := "%" + shifted
	if form.spec.rounding {
		roundingShift := c.newTmp()
		roundingBit := c.newTmp()
		rounded := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %s\n", roundingShift, sourceType, source,
			arm64VectorIntegerSplat(form.sourceArrangement, int64(form.shift-1)))
		fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %s\n", roundingBit, sourceType, roundingShift,
			arm64VectorIntegerSplat(form.sourceArrangement, 1))
		fmt.Fprintf(c.b, "  %%%s = add %s %s, %%%s\n", rounded, sourceType, shiftedValue, roundingBit)
		shiftedValue = "%" + rounded
	}

	clamped := shiftedValue
	destinationBits := form.destinationArrangement.elementBits
	switch {
	case form.spec.signedSource && form.spec.unsignedDestination:
		maximum := (int64(1) << destinationBits) - 1
		clamped = c.clampARM64VectorInteger(sourceType, form.sourceArrangement, shiftedValue, "slt", 0, "sgt", maximum)
	case form.spec.signedSource:
		minimum := -(int64(1) << (destinationBits - 1))
		maximum := (int64(1) << (destinationBits - 1)) - 1
		clamped = c.clampARM64VectorInteger(sourceType, form.sourceArrangement, shiftedValue, "slt", minimum, "sgt", maximum)
	default:
		maximum := (int64(1) << destinationBits) - 1
		above := c.newTmp()
		selected := c.newTmp()
		upper := arm64VectorIntegerSplat(form.sourceArrangement, maximum)
		fmt.Fprintf(c.b, "  %%%s = icmp ugt %s %s, %s\n", above, sourceType, shiftedValue, upper)
		fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %s, %s %s\n",
			selected, form.sourceArrangement.lanes, above, sourceType, upper, sourceType, shiftedValue)
		clamped = "%" + selected
	}

	narrowType := fmt.Sprintf("<%d x i%d>", form.sourceArrangement.lanes, destinationBits)
	narrowed := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc %s %s to %s\n", narrowed, sourceType, clamped, narrowType)
	result := "%" + narrowed
	if form.highHalf {
		destination, err := c.loadRawARM64VectorOperand(form.destination, form.destinationArrangement, 0, false)
		if err != nil {
			return err
		}
		fullDestinationType := fmt.Sprintf("<%d x i%d>", form.destinationArrangement.lanes, destinationBits)
		for lane := 0; lane < form.sourceArrangement.lanes; lane++ {
			element := c.newTmp()
			inserted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", element, narrowType, result, lane)
			fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, i%d %%%s, i32 %d\n",
				inserted, fullDestinationType, destination, destinationBits, element, form.sourceArrangement.lanes+lane)
			destination = "%" + inserted
		}
		result = destination
	}
	return c.storeRawARM64VectorResult(form.destination, form.destinationArrangement, result, form.scalar)
}
