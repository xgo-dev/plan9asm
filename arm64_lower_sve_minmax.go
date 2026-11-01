package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVEMinMaxKind uint8

const (
	arm64SVEMinMaxDirect arm64SVEMinMaxKind = iota
	arm64SVEMinMaxPairwise
	arm64SVEMinMaxReduce
	arm64SVEMinMaxQuadReduce
)

type arm64SVEMinMaxSpec struct {
	intrinsic   string
	kind        arm64SVEMinMaxKind
	elementBits int
	unsignedImm bool
}

var arm64SVEMinMaxSpecs = map[Op]arm64SVEMinMaxSpec{
	"ZSMAX":   {intrinsic: "smax", kind: arm64SVEMinMaxDirect},
	"ZSMAXP":  {intrinsic: "smaxp", kind: arm64SVEMinMaxPairwise},
	"ZSMAXQV": {intrinsic: "smaxqv", kind: arm64SVEMinMaxQuadReduce},
	"ZSMAXVB": {intrinsic: "smaxv", kind: arm64SVEMinMaxReduce, elementBits: 8},
	"ZSMAXVH": {intrinsic: "smaxv", kind: arm64SVEMinMaxReduce, elementBits: 16},
	"ZSMAXVS": {intrinsic: "smaxv", kind: arm64SVEMinMaxReduce, elementBits: 32},
	"ZSMAXVD": {intrinsic: "smaxv", kind: arm64SVEMinMaxReduce, elementBits: 64},
	"ZSMIN":   {intrinsic: "smin", kind: arm64SVEMinMaxDirect},
	"ZSMINP":  {intrinsic: "sminp", kind: arm64SVEMinMaxPairwise},
	"ZSMINQV": {intrinsic: "sminqv", kind: arm64SVEMinMaxQuadReduce},
	"ZSMINVB": {intrinsic: "sminv", kind: arm64SVEMinMaxReduce, elementBits: 8},
	"ZSMINVH": {intrinsic: "sminv", kind: arm64SVEMinMaxReduce, elementBits: 16},
	"ZSMINVS": {intrinsic: "sminv", kind: arm64SVEMinMaxReduce, elementBits: 32},
	"ZSMINVD": {intrinsic: "sminv", kind: arm64SVEMinMaxReduce, elementBits: 64},
	"ZUMAX":   {intrinsic: "umax", kind: arm64SVEMinMaxDirect, unsignedImm: true},
	"ZUMAXP":  {intrinsic: "umaxp", kind: arm64SVEMinMaxPairwise},
	"ZUMAXQV": {intrinsic: "umaxqv", kind: arm64SVEMinMaxQuadReduce},
	"ZUMAXVB": {intrinsic: "umaxv", kind: arm64SVEMinMaxReduce, elementBits: 8},
	"ZUMAXVH": {intrinsic: "umaxv", kind: arm64SVEMinMaxReduce, elementBits: 16},
	"ZUMAXVS": {intrinsic: "umaxv", kind: arm64SVEMinMaxReduce, elementBits: 32},
	"ZUMAXVD": {intrinsic: "umaxv", kind: arm64SVEMinMaxReduce, elementBits: 64},
	"ZUMIN":   {intrinsic: "umin", kind: arm64SVEMinMaxDirect, unsignedImm: true},
	"ZUMINP":  {intrinsic: "uminp", kind: arm64SVEMinMaxPairwise},
	"ZUMINQV": {intrinsic: "uminqv", kind: arm64SVEMinMaxQuadReduce},
	"ZUMINVB": {intrinsic: "uminv", kind: arm64SVEMinMaxReduce, elementBits: 8},
	"ZUMINVH": {intrinsic: "uminv", kind: arm64SVEMinMaxReduce, elementBits: 16},
	"ZUMINVS": {intrinsic: "uminv", kind: arm64SVEMinMaxReduce, elementBits: 32},
	"ZUMINVD": {intrinsic: "uminv", kind: arm64SVEMinMaxReduce, elementBits: 64},
}

type arm64SVEMinMaxForm struct {
	elementBits  int
	first        int
	second       int
	predicate    int
	destination  int
	immediate    int64
	hasImmediate bool
}

func (c *arm64Ctx) lowerARM64SVEMinMax(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVEMinMaxSpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) {
		return true, false, fmt.Errorf("arm64 %s does not accept an instruction suffix: %q", op, ins.Raw)
	}

	switch spec.kind {
	case arm64SVEMinMaxDirect, arm64SVEMinMaxPairwise:
		form, err := arm64ParseSVEMinMaxDirectForm(op, spec, ins)
		if err != nil {
			return true, false, err
		}
		return true, false, c.lowerARM64SVEMinMaxDirectForm(spec, form)
	case arm64SVEMinMaxReduce, arm64SVEMinMaxQuadReduce:
		form, err := arm64ParseSVEMinMaxReductionForm(op, spec, ins)
		if err != nil {
			return true, false, err
		}
		return true, false, c.lowerARM64SVEMinMaxReductionForm(spec, form, ins.Args[2].Reg)
	default:
		return true, false, fmt.Errorf("arm64 %s has an unknown SVE min/max form", op)
	}
}

func arm64ParseSVEMinMaxDirectForm(op Op, spec arm64SVEMinMaxSpec, ins Instr) (arm64SVEMinMaxForm, error) {
	form := arm64SVEMinMaxForm{}
	if len(ins.Args) == 3 && ins.Args[0].Kind == OpImm {
		first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
		destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
		immediate := ins.Args[0].Imm
		validImmediate := spec.kind == arm64SVEMinMaxDirect && ins.Args[0].ImmRaw == "" && !ins.Args[0].ImmIsFloat
		if spec.unsignedImm {
			validImmediate = validImmediate && immediate >= 0 && immediate <= 255
		} else {
			validImmediate = validImmediate && immediate >= -128 && immediate <= 127
		}
		if !validImmediate || !firstOK || !destinationOK || first != destination || firstBits != destinationBits {
			return form, fmt.Errorf("arm64 %s does not accept this destructive immediate form: %q", op, ins.Raw)
		}
		form = arm64SVEMinMaxForm{elementBits: firstBits, first: first, destination: destination, immediate: immediate, hasImmediate: true}
		return form, nil
	}
	if len(ins.Args) != 4 {
		return form, fmt.Errorf("arm64 %s expects its Go 1.27 predicated%s form: %q", op, map[bool]string{true: " pairwise", false: ""}[spec.kind == arm64SVEMinMaxPairwise], ins.Raw)
	}
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
	first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
	predicate, predicateOK := arm64ParseSVEPredicateMerge(ins.Args[2])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[3])
	if !secondOK || !firstOK || !predicateOK || !destinationOK || secondBits != firstBits || firstBits != destinationBits || first != destination {
		return form, fmt.Errorf("arm64 %s requires matching-width destructive registers and P0..P7/M: %q", op, ins.Raw)
	}
	form = arm64SVEMinMaxForm{elementBits: firstBits, first: first, second: second, predicate: predicate, destination: destination}
	return form, nil
}

func arm64ParseSVEMinMaxReductionForm(op Op, spec arm64SVEMinMaxSpec, ins Instr) (arm64SVEMinMaxForm, error) {
	form := arm64SVEMinMaxForm{}
	if len(ins.Args) != 3 {
		return form, fmt.Errorf("arm64 %s expects Zn.T, Pg, Vd%s: %q", op, map[bool]string{true: ".T", false: ""}[spec.kind == arm64SVEMinMaxQuadReduce], ins.Raw)
	}
	first, elementBits, firstOK := arm64ParseSVEZElementReg(ins.Args[0])
	predicate, predicateOK := arm64ParseSVEPredicate(ins.Args[1])
	destination, destinationOK := arm64ParseVReg(ins.Args[2].Reg)
	if !firstOK || !predicateOK || predicate > 7 || !destinationOK || ins.Args[2].Kind != OpReg {
		return form, fmt.Errorf("arm64 %s requires a scalable source, bare predicate, and SIMD destination: %q", op, ins.Raw)
	}
	if spec.kind == arm64SVEMinMaxReduce {
		if strings.Contains(string(ins.Args[2].Reg), ".") {
			return form, fmt.Errorf("arm64 %s destination must be a bare V register: %q", op, ins.Raw)
		}
		// The Go table gives every VB/VH/VS/VD spelling a generic Zn.T
		// operand. Its encoder ORs the operand size bits into the mnemonic's
		// fixed size bits, so the effective hardware width is their bitwise
		// union rather than requiring the two suffixes to match.
		opcodeSize := map[int]int{8: 0, 16: 1, 32: 2, 64: 3}[spec.elementBits]
		sourceSize := map[int]int{8: 0, 16: 1, 32: 2, 64: 3}[elementBits]
		elementBits = 8 << (opcodeSize | sourceSize)
	} else {
		arrangement, arrangementOK := parseARM64VectorArrangement(ins.Args[2].Reg)
		if !arrangementOK || arrangement.elementBits != elementBits || arrangement.lanes*arrangement.elementBits != 128 {
			return form, fmt.Errorf("arm64 %s destination must be a full-width SIMD vector matching its source elements: %q", op, ins.Raw)
		}
	}
	form = arm64SVEMinMaxForm{elementBits: elementBits, first: first, predicate: predicate, destination: destination}
	return form, nil
}

func (c *arm64Ctx) lowerARM64SVEMinMaxDirectForm(spec arm64SVEMinMaxSpec, form arm64SVEMinMaxForm) error {
	first, vectorType, err := c.loadZRegElements(form.first, form.elementBits)
	if err != nil {
		return err
	}
	var predicate, predicateType string
	if form.hasImmediate {
		predicate, predicateType, err = c.allTruePRegElements(form.elementBits)
	} else {
		predicate, predicateType, err = c.loadPRegElements(form.predicate, form.elementBits)
	}
	if err != nil {
		return err
	}
	second := fmt.Sprintf("splat (i%d %d)", form.elementBits, form.immediate)
	if !form.hasImmediate {
		second, _, err = c.loadZRegElements(form.second, form.elementBits)
		if err != nil {
			return err
		}
	}
	lanes := 128 / form.elementBits
	calculated := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s, %s %s)\n", calculated, vectorType, spec.intrinsic, lanes, form.elementBits, predicateType, predicate, vectorType, first, vectorType, second)
	result := "%" + calculated
	if !form.hasImmediate {
		selected := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select %s %s, %s %s, %s %s\n", selected, predicateType, predicate, vectorType, result, vectorType, first)
		result = "%" + selected
	}
	return c.storeZRegElements(form.destination, form.elementBits, result)
}

func (c *arm64Ctx) lowerARM64SVEMinMaxReductionForm(spec arm64SVEMinMaxSpec, form arm64SVEMinMaxForm, destination Reg) error {
	source, vectorType, err := c.loadZRegElements(form.first, form.elementBits)
	if err != nil {
		return err
	}
	predicate, predicateType, err := c.loadPRegElements(form.predicate, form.elementBits)
	if err != nil {
		return err
	}
	lanes := 128 / form.elementBits
	result := c.newTmp()
	if spec.kind == arm64SVEMinMaxReduce {
		fmt.Fprintf(c.b, "  %%%s = call i%d @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s)\n", result, form.elementBits, spec.intrinsic, lanes, form.elementBits, predicateType, predicate, vectorType, source)
		fixed := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> zeroinitializer, i%d %%%s, i32 0\n", fixed, lanes, form.elementBits, form.elementBits, result)
		result = fixed
	} else {
		fmt.Fprintf(c.b, "  %%%s = call <%d x i%d> @llvm.aarch64.sve.%s.v%di%d.nxv%di%d(%s %s, %s %s)\n", result, lanes, form.elementBits, spec.intrinsic, lanes, form.elementBits, lanes, form.elementBits, predicateType, predicate, vectorType, source)
	}
	bytes := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %%%s to <16 x i8>\n", bytes, lanes, form.elementBits, result)
	return c.storeVReg(destination, "%"+bytes)
}
