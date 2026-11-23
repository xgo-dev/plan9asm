package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVEAbsoluteDifferenceKind uint8

const (
	arm64SVEAbsoluteAccumulate arm64SVEAbsoluteDifferenceKind = iota
	arm64SVEAbsoluteDifference
	arm64SVEAbsoluteLongAccumulate
	arm64SVEAbsoluteLongDifference
	arm64SVEAbsolutePairAccumulate
)

type arm64SVEAbsoluteDifferenceSpec struct {
	mnemonic string
	kind     arm64SVEAbsoluteDifferenceKind
	feature  string
	rawBase  uint32
	native   bool
}

var arm64SVEAbsoluteDifferenceSpecs = map[Op]arm64SVEAbsoluteDifferenceSpec{
	"ZSABA":   {mnemonic: "saba", kind: arm64SVEAbsoluteAccumulate, feature: "+sve2", rawBase: 0x4500f800},
	"ZUABA":   {mnemonic: "uaba", kind: arm64SVEAbsoluteAccumulate, feature: "+sve2", rawBase: 0x4500fc00},
	"ZSABD":   {mnemonic: "sabd", kind: arm64SVEAbsoluteDifference, rawBase: 0x040c0000},
	"ZUABD":   {mnemonic: "uabd", kind: arm64SVEAbsoluteDifference, rawBase: 0x040d0000},
	"ZSABALB": {mnemonic: "sabalb", kind: arm64SVEAbsoluteLongAccumulate, feature: "+sve2", rawBase: 0x4500c000},
	"ZSABALT": {mnemonic: "sabalt", kind: arm64SVEAbsoluteLongAccumulate, feature: "+sve2", rawBase: 0x4500c400},
	"ZUABALB": {mnemonic: "uabalb", kind: arm64SVEAbsoluteLongAccumulate, feature: "+sve2", rawBase: 0x4500c800},
	"ZUABALT": {mnemonic: "uabalt", kind: arm64SVEAbsoluteLongAccumulate, feature: "+sve2", rawBase: 0x4500cc00},
	"ZSABAL":  {mnemonic: "sabal", kind: arm64SVEAbsoluteLongAccumulate, feature: "+sve2p3", rawBase: 0x4400d400, native: true},
	"ZUABAL":  {mnemonic: "uabal", kind: arm64SVEAbsoluteLongAccumulate, feature: "+sve2p3", rawBase: 0x4400dc00, native: true},
	"ZSABDLB": {mnemonic: "sabdlb", kind: arm64SVEAbsoluteLongDifference, feature: "+sve2", rawBase: 0x45003000},
	"ZSABDLT": {mnemonic: "sabdlt", kind: arm64SVEAbsoluteLongDifference, feature: "+sve2", rawBase: 0x45003400},
	"ZUABDLB": {mnemonic: "uabdlb", kind: arm64SVEAbsoluteLongDifference, feature: "+sve2", rawBase: 0x45003800},
	"ZUABDLT": {mnemonic: "uabdlt", kind: arm64SVEAbsoluteLongDifference, feature: "+sve2", rawBase: 0x45003c00},
	"ZSADALP": {mnemonic: "sadalp", kind: arm64SVEAbsolutePairAccumulate, feature: "+sve2", rawBase: 0x4404a000},
	"ZUADALP": {mnemonic: "uadalp", kind: arm64SVEAbsolutePairAccumulate, feature: "+sve2", rawBase: 0x4405a000},
}

type arm64SVEAbsoluteDifferenceForm struct {
	spec        arm64SVEAbsoluteDifferenceSpec
	elementBits int
	sourceBits  int
	first       int
	second      int // -1 for the single-source pairwise group.
	predicate   int // -1 for an unpredicated group.
	destination int
}

var arm64SVEAbsoluteVectorRows, arm64SVEAbsolutePredicatedRows = arm64SVEAbsoluteRawTables()

func arm64SVEAbsoluteRawTables() (vectors, predicated map[uint32]arm64SVEAbsoluteDifferenceSpec) {
	vectors = make(map[uint32]arm64SVEAbsoluteDifferenceSpec)
	predicated = make(map[uint32]arm64SVEAbsoluteDifferenceSpec)
	for _, spec := range arm64SVEAbsoluteDifferenceSpecs {
		switch spec.kind {
		case arm64SVEAbsoluteDifference, arm64SVEAbsolutePairAccumulate:
			predicated[spec.rawBase] = spec
		default:
			vectors[spec.rawBase] = spec
		}
	}
	return vectors, predicated
}

func decodeARM64RawSVEAbsoluteDifference(word uint32) (arm64SVEAbsoluteDifferenceForm, bool) {
	// The three-vector group encodes Zm in bits 20:16. The predicated
	// group fixes those bits and encodes Pg in bits 12:10.
	spec, ok := arm64SVEAbsoluteVectorRows[word&0xff20fc00]
	if !ok {
		spec, ok = arm64SVEAbsolutePredicatedRows[word&0xff3fe000]
		if !ok {
			return arm64SVEAbsoluteDifferenceForm{}, false
		}
	}
	bits := 8 << ((word >> 22) & 3)
	form := arm64SVEAbsoluteDifferenceForm{
		spec: spec, elementBits: bits, sourceBits: bits,
		first: int(word>>5) & 31, second: int(word>>16) & 31,
		predicate: -1, destination: int(word) & 31,
	}
	switch spec.kind {
	case arm64SVEAbsoluteDifference:
		form.first, form.second = form.destination, form.first
		form.predicate = int(word>>10) & 7
	case arm64SVEAbsolutePairAccumulate:
		form.second = -1
		form.predicate = int(word>>10) & 7
	}
	switch spec.kind {
	case arm64SVEAbsoluteLongAccumulate, arm64SVEAbsoluteLongDifference, arm64SVEAbsolutePairAccumulate:
		if bits == 8 {
			return arm64SVEAbsoluteDifferenceForm{}, false
		}
		form.sourceBits /= 2
	}
	return form, true
}

func (c *arm64Ctx) lowerARM64SVEAbsoluteDifference(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVEAbsoluteDifferenceSpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) {
		return true, false, fmt.Errorf("arm64 %s does not accept an instruction suffix: %q", op, ins.Raw)
	}
	form, err := arm64ParseSVEAbsoluteDifferenceForm(op, spec, ins)
	if err != nil {
		return true, false, err
	}
	return true, false, c.lowerARM64SVEAbsoluteDifferenceForm(form)
}

func arm64ParseSVEAbsoluteDifferenceForm(op Op, spec arm64SVEAbsoluteDifferenceSpec, ins Instr) (arm64SVEAbsoluteDifferenceForm, error) {
	form := arm64SVEAbsoluteDifferenceForm{spec: spec, second: -1, predicate: -1}
	switch spec.kind {
	case arm64SVEAbsoluteDifference:
		if len(ins.Args) != 4 {
			return form, fmt.Errorf("arm64 %s expects Zm.T, Zdn.T, Pg/M, Zdn.T: %q", op, ins.Raw)
		}
		second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
		first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
		predicate, predicateOK := arm64ParseSVEPredicateMerge(ins.Args[2])
		destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[3])
		if !secondOK || !firstOK || !predicateOK || !destinationOK || secondBits != firstBits || firstBits != destinationBits || first != destination {
			return form, fmt.Errorf("arm64 %s requires matching-width destructive data and P0..P7/M: %q", op, ins.Raw)
		}
		form.elementBits, form.sourceBits = firstBits, firstBits
		form.first, form.second, form.predicate, form.destination = first, second, predicate, destination
	case arm64SVEAbsolutePairAccumulate:
		if len(ins.Args) != 3 {
			return form, fmt.Errorf("arm64 %s expects Zn.Tb, Pg/M, Zda.T: %q", op, ins.Raw)
		}
		first, sourceBits, firstOK := arm64ParseSVEZElementReg(ins.Args[0])
		predicate, predicateOK := arm64ParseSVEPredicateMerge(ins.Args[1])
		destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
		if !firstOK || !predicateOK || !destinationOK || sourceBits == 64 || destinationBits != 2*sourceBits {
			return form, fmt.Errorf("arm64 %s requires a B/H/S source, P0..P7/M, and H/S/D accumulator: %q", op, ins.Raw)
		}
		form.elementBits, form.sourceBits = destinationBits, sourceBits
		form.first, form.predicate, form.destination = first, predicate, destination
	default:
		if len(ins.Args) != 3 {
			return form, fmt.Errorf("arm64 %s expects three scalable vector operands: %q", op, ins.Raw)
		}
		second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
		first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
		destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
		if !secondOK || !firstOK || !destinationOK || secondBits != firstBits {
			return form, fmt.Errorf("arm64 %s requires matching source widths: %q", op, ins.Raw)
		}
		if spec.kind == arm64SVEAbsoluteAccumulate {
			if firstBits != destinationBits {
				return form, fmt.Errorf("arm64 %s requires matching B/H/S/D sources and accumulator: %q", op, ins.Raw)
			}
		} else if firstBits == 64 || destinationBits != 2*firstBits {
			return form, fmt.Errorf("arm64 %s requires B/H/S sources widened to H/S/D: %q", op, ins.Raw)
		}
		form.elementBits, form.sourceBits = destinationBits, firstBits
		form.first, form.second, form.destination = first, second, destination
	}
	return form, nil
}

func (c *arm64Ctx) lowerARM64SVEAbsoluteDifferenceForm(form arm64SVEAbsoluteDifferenceForm) error {
	spec := form.spec
	destinationType, destinationLanes, err := arm64SVEVectorType(form.elementBits)
	if err != nil {
		return err
	}
	first, sourceType, err := c.loadZRegElements(form.first, form.sourceBits)
	if err != nil {
		return err
	}
	var arguments [3]string
	args := arguments[:0]
	if form.predicate >= 0 {
		predicate, predicateType, err := c.loadPRegElements(form.predicate, form.elementBits)
		if err != nil {
			return err
		}
		args = append(args, predicateType+" "+predicate)
	}
	switch spec.kind {
	case arm64SVEAbsoluteAccumulate, arm64SVEAbsoluteLongAccumulate, arm64SVEAbsolutePairAccumulate:
		accumulator, _, err := c.loadZRegElements(form.destination, form.elementBits)
		if err != nil {
			return err
		}
		args = append(args, destinationType+" "+accumulator)
	}
	args = append(args, sourceType+" "+first)
	if form.second >= 0 {
		second, _, err := c.loadZRegElements(form.second, form.sourceBits)
		if err != nil {
			return err
		}
		args = append(args, sourceType+" "+second)
	}

	result := c.newTmp()
	if spec.native {
		// LLVM 22 has no SABAL/UABAL intrinsic. The tied accumulator
		// retains the full scalable-vector value and the hardware lane selection.
		wide := strings.ToLower(arm64SVEElementLetter(form.elementBits))
		narrow := strings.ToLower(arm64SVEElementLetter(form.sourceBits))
		assembly := fmt.Sprintf("%s $0.%s, $2.%s, $3.%s", spec.mnemonic, wide, narrow, narrow)
		fmt.Fprintf(c.b, "  %%%s = call %s asm %q, %q(%s)\n",
			result, destinationType, assembly, "=w,0,w,w", strings.Join(args, ", "))
	} else {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s)\n",
			result, destinationType, spec.mnemonic, destinationLanes, form.elementBits, strings.Join(args, ", "))
	}
	return c.storeZRegElements(form.destination, form.elementBits, "%"+result)
}
