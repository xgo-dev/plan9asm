package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVEAddSubSpec struct {
	intrinsic    string
	reverse      bool
	unpredicated uint32
	predicated   uint32
	immediate    uint32
}

var arm64SVEAddSubSpecs = map[Op]arm64SVEAddSubSpec{
	"ZSUB":    {unpredicated: 0x04200400, predicated: 0x04010000, immediate: 0x2521c000},
	"ZSUBR":   {reverse: true, predicated: 0x04030000, immediate: 0x2523c000},
	"ZSQADD":  {intrinsic: "aarch64.sve.sqadd.x", unpredicated: 0x04201000, predicated: 0x44188000, immediate: 0x2524c000},
	"ZSQSUB":  {intrinsic: "aarch64.sve.sqsub.x", unpredicated: 0x04201800, predicated: 0x441a8000, immediate: 0x2526c000},
	"ZSQSUBR": {intrinsic: "aarch64.sve.sqsub.x", reverse: true, predicated: 0x441e8000},
	"ZUQADD":  {intrinsic: "aarch64.sve.uqadd.x", unpredicated: 0x04201400, predicated: 0x44198000, immediate: 0x2525c000},
	"ZUQSUB":  {intrinsic: "aarch64.sve.uqsub.x", unpredicated: 0x04201c00, predicated: 0x441b8000, immediate: 0x2527c000},
	"ZUQSUBR": {intrinsic: "aarch64.sve.uqsub.x", reverse: true, predicated: 0x441f8000},
}

// Go's complete SUB and saturating ADD/SUB families share ADD's three field
// layouts. Zero encoding values denote absent forms, both here and in the
// named validator. Normalization retains ADD's reserved-immediate checks.
func decodeARM64RawSVEAddSub(word uint32) (Op, arm64RawSVEAdd, bool) {
	for op, spec := range arm64SVEAddSubSpecs {
		for _, row := range [...]struct{ bits, mask, add uint32 }{
			{spec.unpredicated, 0xff20fc00, 0x04200000},
			{spec.predicated, 0xff3fe000, 0x04000000},
			{spec.immediate, 0xff3fc000, 0x2520c000},
		} {
			if row.bits != 0 && word&row.mask == row.bits {
				form, ok := decodeARM64RawSVEAdd(word ^ row.bits ^ row.add)
				return op, form, ok
			}
		}
	}
	return "", arm64RawSVEAdd{}, false
}

func (c *arm64Ctx) lowerARM64SVEAddSub(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVEAddSubSpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) {
		return true, false, fmt.Errorf("arm64 %s does not accept an instruction suffix: %q", op, ins.Raw)
	}

	form := arm64RawSVEAdd{}
	switch {
	case len(ins.Args) == 3 && ins.Args[0].Kind == OpImm:
		first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
		destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
		if spec.immediate == 0 || ins.Args[0].ImmRaw != "" || !firstOK || !destinationOK || first != destination || firstBits != destinationBits || !arm64SVEAddImmediateRepresentable(firstBits, ins.Args[0].Imm) {
			return true, false, fmt.Errorf("arm64 %s does not accept this immediate form: %q", op, ins.Raw)
		}
		form = arm64RawSVEAdd{mode: arm64SVEAddImmediate, elementBits: firstBits, first: first, destination: destination, immediate: int(ins.Args[0].Imm)}
	case len(ins.Args) == 3:
		second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
		first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
		destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
		if spec.unpredicated == 0 || !secondOK || !firstOK || !destinationOK || secondBits != firstBits || firstBits != destinationBits {
			return true, false, fmt.Errorf("arm64 %s does not accept this unpredicated vector form: %q", op, ins.Raw)
		}
		form = arm64RawSVEAdd{mode: arm64SVEAddUnpredicated, elementBits: firstBits, first: first, second: second, destination: destination}
	case len(ins.Args) == 4:
		second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
		first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
		predicate, predicateOK := arm64ParseSVEPredicateMerge(ins.Args[2])
		destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[3])
		if spec.predicated == 0 || !secondOK || !firstOK || !predicateOK || !destinationOK || secondBits != firstBits || firstBits != destinationBits || first != destination {
			return true, false, fmt.Errorf("arm64 %s does not accept this predicated destructive form: %q", op, ins.Raw)
		}
		form = arm64RawSVEAdd{mode: arm64SVEAddPredicated, elementBits: firstBits, first: first, second: second, predicate: predicate, destination: destination}
	default:
		return true, false, fmt.Errorf("arm64 %s expects one of its Go 1.27 SVE forms: %q", op, ins.Raw)
	}
	return true, false, c.lowerRawSVEAddSub(spec, form)
}

func (c *arm64Ctx) lowerRawSVEAddSub(spec arm64SVEAddSubSpec, form arm64RawSVEAdd) error {
	first, vectorType, err := c.loadZRegElements(form.first, form.elementBits)
	if err != nil {
		return err
	}
	// Unlike the vector form, SQADD/SQSUB's immediate is unsigned. A byte or
	// halfword immediate with its sign bit set cannot use the signed binary
	// intrinsic: widen first, then clamp before truncation. This path is never
	// needed for S/D, whose encodable immediates fit their signed range.
	if form.mode == arm64SVEAddImmediate && uint64(form.immediate) >= uint64(1)<<(form.elementBits-1) &&
		(spec.intrinsic == "aarch64.sve.sqadd.x" || spec.intrinsic == "aarch64.sve.sqsub.x") {
		return c.lowerSVESignedSaturationImmediate(spec, form, first, vectorType)
	}
	second := fmt.Sprintf("splat (i%d %d)", form.elementBits, form.immediate)
	if form.mode != arm64SVEAddImmediate {
		second, _, err = c.loadZRegElements(form.second, form.elementBits)
		if err != nil {
			return err
		}
	}
	left, right := first, second
	if spec.reverse {
		left, right = right, left
	}
	calculated := c.newTmp()
	if spec.intrinsic == "" {
		fmt.Fprintf(c.b, "  %%%s = sub %s %s, %s\n", calculated, vectorType, left, right)
	} else {
		lanes := 128 / form.elementBits
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.%s.nxv%di%d(%s %s, %s %s)\n", calculated, vectorType, spec.intrinsic, lanes, form.elementBits, vectorType, left, vectorType, right)
	}
	result := "%" + calculated
	if form.mode == arm64SVEAddPredicated {
		predicate, predicateType, err := c.loadPRegElements(form.predicate, form.elementBits)
		if err != nil {
			return err
		}
		selected := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select %s %s, %s %s, %s %s\n", selected, predicateType, predicate, vectorType, result, vectorType, first)
		result = "%" + selected
	}
	return c.storeZRegElements(form.destination, form.elementBits, result)
}

func (c *arm64Ctx) lowerSVESignedSaturationImmediate(spec arm64SVEAddSubSpec, form arm64RawSVEAdd, first, vectorType string) error {
	lanes, wideBits := 128/form.elementBits, form.elementBits*2
	wideType := fmt.Sprintf("<vscale x %d x i%d>", lanes, wideBits)
	predicateType := fmt.Sprintf("<vscale x %d x i1>", lanes)
	op, comparison := "add", "sgt"
	bound := int64(1)<<(form.elementBits-1) - 1
	if spec.intrinsic == "aarch64.sve.sqsub.x" {
		op, comparison = "sub", "slt"
		bound = -(int64(1) << (form.elementBits - 1))
	}
	widened, calculated, outside, clamped, result := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sext %s %s to %s\n", widened, vectorType, first, wideType)
	fmt.Fprintf(c.b, "  %%%s = %s %s %%%s, splat (i%d %d)\n", calculated, op, wideType, widened, wideBits, form.immediate)
	fmt.Fprintf(c.b, "  %%%s = icmp %s %s %%%s, splat (i%d %d)\n", outside, comparison, wideType, calculated, wideBits, bound)
	fmt.Fprintf(c.b, "  %%%s = select %s %%%s, %s splat (i%d %d), %s %%%s\n", clamped, predicateType, outside, wideType, wideBits, bound, wideType, calculated)
	fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to %s\n", result, wideType, clamped, vectorType)
	return c.storeZRegElements(form.destination, form.elementBits, "%"+result)
}
