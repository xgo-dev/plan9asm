package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVELSRMode uint8

const (
	arm64SVELSRWidePredicated arm64SVELSRMode = iota
	arm64SVELSRWideUnpredicated
	arm64SVELSRVectorPredicated
	arm64SVELSRImmediatePredicated
	arm64SVELSRImmediateUnpredicated
)

type arm64RawSVELSR struct {
	op          Op
	mode        arm64SVELSRMode
	elementBits int
	shifts      int
	source      int
	predicate   int
	shift       int
	destination int
}

type arm64SVEShiftSpec struct {
	intrinsic string
	right     bool
}

var arm64SVEShiftSpecs = map[Op]arm64SVEShiftSpec{
	"ZASR": {intrinsic: "asr", right: true},
	"ZLSL": {intrinsic: "lsl"},
	"ZLSR": {intrinsic: "lsr", right: true},
}

func decodeARM64SVEShiftImmediate(word uint32, lowBit int) (elementBits, shift int, ok bool) {
	encoded := 0
	if lowBit == 5 {
		encoded = int(word>>5)&7 | (int(word>>8)&3)<<3 | (int(word>>22)&3)<<5
	} else {
		encoded = int(word>>16)&7 | (int(word>>19)&3)<<3 | (int(word>>22)&3)<<5
	}
	switch {
	case encoded >= 64:
		elementBits = 64
	case encoded >= 32:
		elementBits = 32
	case encoded >= 16:
		elementBits = 16
	case encoded >= 8:
		elementBits = 8
	default:
		return 0, 0, false
	}
	shift = 2*elementBits - encoded
	return elementBits, shift, shift >= 1 && shift <= elementBits
}

// All five Go 1.27 forms of ASR, LSL, and LSR share register fields. Keep
// the operation and form axes separate so raw WORDs use the named lowerer.
var arm64SVEShiftWidePredicatedBases = map[uint32]Op{
	0x04188000: "ZASR",
	0x041b8000: "ZLSL",
	0x04198000: "ZLSR",
}

var arm64SVEShiftWideUnpredicatedBases = map[uint32]Op{
	0x04208000: "ZASR",
	0x04208c00: "ZLSL",
	0x04208400: "ZLSR",
}

var arm64SVEShiftVectorPredicatedBases = map[uint32]Op{
	0x04108000: "ZASR",
	0x04138000: "ZLSL",
	0x04118000: "ZLSR",
}

var arm64SVEShiftImmediatePredicatedBases = map[uint32]Op{
	0x04008000: "ZASR",
	0x04038000: "ZLSL",
	0x04018000: "ZLSR",
}

var arm64SVEShiftImmediateUnpredicatedBases = map[uint32]Op{
	0x04209000: "ZASR",
	0x04209c00: "ZLSL",
	0x04209400: "ZLSR",
}

func decodeARM64RawSVEShift(word uint32) (arm64RawSVELSR, bool) {
	form := arm64RawSVELSR{}
	if op, ok := arm64SVEShiftWidePredicatedBases[word&0xff3fe000]; ok {
		form.op = op
		form.mode = arm64SVELSRWidePredicated
		form.elementBits = 8 << (int(word>>22) & 3)
		if form.elementBits == 64 {
			return arm64RawSVELSR{}, false
		}
		form.shifts = int(word>>5) & 31
		form.predicate = int(word>>10) & 7
		form.destination = int(word) & 31
		form.source = form.destination
	} else if op, ok := arm64SVEShiftWideUnpredicatedBases[word&0xff20fc00]; ok {
		form.op = op
		form.mode = arm64SVELSRWideUnpredicated
		form.elementBits = 8 << (int(word>>22) & 3)
		if form.elementBits == 64 {
			return arm64RawSVELSR{}, false
		}
		form.shifts = int(word>>16) & 31
		form.source = int(word>>5) & 31
		form.destination = int(word) & 31
	} else if op, ok := arm64SVEShiftVectorPredicatedBases[word&0xff3fe000]; ok {
		form.op = op
		form.mode = arm64SVELSRVectorPredicated
		form.elementBits = 8 << (int(word>>22) & 3)
		form.shifts = int(word>>5) & 31
		form.predicate = int(word>>10) & 7
		form.destination = int(word) & 31
		form.source = form.destination
	} else if op, ok := arm64SVEShiftImmediatePredicatedBases[word&0xff3fe000]; ok {
		form.op = op
		form.mode = arm64SVELSRImmediatePredicated
		var ok bool
		form.elementBits, form.shift, ok = decodeARM64SVEShiftImmediate(word, 5)
		if !ok {
			return arm64RawSVELSR{}, false
		}
		if op == "ZLSL" {
			form.shift = form.elementBits - form.shift
		}
		form.predicate = int(word>>10) & 7
		form.destination = int(word) & 31
		form.source = form.destination
	} else if op, ok := arm64SVEShiftImmediateUnpredicatedBases[word&0xff20fc00]; ok {
		form.op = op
		form.mode = arm64SVELSRImmediateUnpredicated
		var ok bool
		form.elementBits, form.shift, ok = decodeARM64SVEShiftImmediate(word, 16)
		if !ok {
			return arm64RawSVELSR{}, false
		}
		if op == "ZLSL" {
			form.shift = form.elementBits - form.shift
		}
		form.source = int(word>>5) & 31
		form.destination = int(word) & 31
	} else {
		return arm64RawSVELSR{}, false
	}
	return form, true
}

func decodeARM64RawSVELSR(word uint32) (arm64RawSVELSR, bool) {
	form, ok := decodeARM64RawSVEShift(word)
	return form, ok && form.op == "ZLSR"
}

func (c *arm64Ctx) lowerARM64SVELSR(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVEShiftSpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) {
		return true, false, fmt.Errorf("arm64 %s does not accept an instruction suffix: %q", op, ins.Raw)
	}

	form := arm64RawSVELSR{op: op}
	if len(ins.Args) == 3 && ins.Args[0].Kind == OpImm {
		source, sourceBits, sourceOK := arm64ParseSVEZElementReg(ins.Args[1])
		destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
		shift := ins.Args[0].Imm
		minimum := int64(0)
		if spec.right {
			minimum = 1
		}
		if ins.Args[0].ImmRaw != "" || !sourceOK || !destinationOK || sourceBits != destinationBits || shift < minimum || shift >= int64(sourceBits) {
			return true, false, fmt.Errorf("arm64 %s immediate is outside Go 1.27's element-width range: %q", op, ins.Raw)
		}
		form = arm64RawSVELSR{op: op, mode: arm64SVELSRImmediateUnpredicated, elementBits: sourceBits, source: source, shift: int(shift), destination: destination}
	} else if len(ins.Args) == 4 && ins.Args[0].Kind == OpImm {
		source, sourceBits, sourceOK := arm64ParseSVEZElementReg(ins.Args[1])
		predicate, predicateOK := arm64ParseSVEPredicateMerge(ins.Args[2])
		destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[3])
		shift := ins.Args[0].Imm
		minimum := int64(0)
		if spec.right {
			minimum = 1
		}
		if ins.Args[0].ImmRaw != "" || !sourceOK || !predicateOK || !destinationOK || source != destination || sourceBits != destinationBits || shift < minimum || shift >= int64(sourceBits) {
			return true, false, fmt.Errorf("arm64 %s predicated immediate is outside Go 1.27's destructive element-width form: %q", op, ins.Raw)
		}
		form = arm64RawSVELSR{op: op, mode: arm64SVELSRImmediatePredicated, elementBits: sourceBits, source: source, predicate: predicate, shift: int(shift), destination: destination}
	} else if len(ins.Args) == 3 {
		shifts, shiftBits, shiftsOK := arm64ParseSVEZElementReg(ins.Args[0])
		source, sourceBits, sourceOK := arm64ParseSVEZElementReg(ins.Args[1])
		destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
		if !shiftsOK || !sourceOK || !destinationOK || shiftBits != 64 || sourceBits == 64 || sourceBits != destinationBits {
			return true, false, fmt.Errorf("arm64 %s unpredicated wide form expects Zm.D, Zn.B|H|S, Zd.B|H|S: %q", op, ins.Raw)
		}
		form = arm64RawSVELSR{op: op, mode: arm64SVELSRWideUnpredicated, elementBits: sourceBits, shifts: shifts, source: source, destination: destination}
	} else if len(ins.Args) == 4 {
		shifts, shiftBits, shiftsOK := arm64ParseSVEZElementReg(ins.Args[0])
		source, sourceBits, sourceOK := arm64ParseSVEZElementReg(ins.Args[1])
		predicate, predicateOK := arm64ParseSVEPredicateMerge(ins.Args[2])
		destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[3])
		if !shiftsOK || !sourceOK || !predicateOK || !destinationOK || source != destination || sourceBits != destinationBits {
			return true, false, fmt.Errorf("arm64 %s predicated form requires identical destructive source and destination: %q", op, ins.Raw)
		}
		mode := arm64SVELSRVectorPredicated
		if shiftBits == 64 && sourceBits != 64 {
			mode = arm64SVELSRWidePredicated
		} else if shiftBits != sourceBits {
			return true, false, fmt.Errorf("arm64 %s shift register width is incompatible with data elements: %q", op, ins.Raw)
		}
		form = arm64RawSVELSR{op: op, mode: mode, elementBits: sourceBits, shifts: shifts, source: source, predicate: predicate, destination: destination}
	} else {
		return true, false, fmt.Errorf("arm64 %s expects one of its five Go 1.27 SVE forms: %q", op, ins.Raw)
	}
	return true, false, c.lowerRawSVELSR(form)
}

func (c *arm64Ctx) lowerRawSVELSR(form arm64RawSVELSR) error {
	spec, ok := arm64SVEShiftSpecs[form.op]
	if !ok {
		return fmt.Errorf("unsupported ARM64 SVE shift operation %s", form.op)
	}
	source, vectorType, err := c.loadZRegElements(form.source, form.elementBits)
	if err != nil {
		return err
	}
	var predicate, predicateType string
	if form.mode == arm64SVELSRWidePredicated || form.mode == arm64SVELSRVectorPredicated || form.mode == arm64SVELSRImmediatePredicated {
		predicate, predicateType, err = c.loadPRegElements(form.predicate, form.elementBits)
	} else {
		predicate, predicateType, err = c.allTruePRegElements(form.elementBits)
	}
	if err != nil {
		return err
	}

	intrinsic := "llvm.aarch64.sve." + spec.intrinsic
	shiftType := vectorType
	shiftValue := fmt.Sprintf("splat (i%d %d)", form.elementBits, form.shift)
	if form.mode == arm64SVELSRWidePredicated || form.mode == arm64SVELSRWideUnpredicated {
		intrinsic += ".wide"
		shiftType = "<vscale x 2 x i64>"
		shiftValue, _, err = c.loadZRegElements(form.shifts, 64)
	} else if form.mode == arm64SVELSRVectorPredicated {
		shiftValue, _, err = c.loadZRegElements(form.shifts, form.elementBits)
	}
	if err != nil {
		return err
	}
	_, lanes, err := arm64SVEVectorType(form.elementBits)
	if err != nil {
		return err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @%s.nxv%di%d(%s %s, %s %s, %s %s)\n",
		result, vectorType, intrinsic, lanes, form.elementBits, predicateType, predicate, vectorType, source, shiftType, shiftValue)
	return c.storeZRegElements(form.destination, form.elementBits, "%"+result)
}
