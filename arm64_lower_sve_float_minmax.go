package plan9asm

import (
	"fmt"
	"math"
	"strings"
)

type arm64SVEFloatMinMaxKind uint8

const (
	arm64SVEFloatMinMaxDirect arm64SVEFloatMinMaxKind = iota
	arm64SVEFloatMinMaxPairwise
	arm64SVEFloatMinMaxReduce
	arm64SVEFloatMinMaxQuadReduce
)

type arm64SVEFloatMinMaxSpec struct {
	intrinsic   string
	kind        arm64SVEFloatMinMaxKind
	elementBits int
}

var arm64SVEFloatMinMaxSpecs = map[Op]arm64SVEFloatMinMaxSpec{
	"ZFMAX":     {intrinsic: "fmax", kind: arm64SVEFloatMinMaxDirect},
	"ZFMAXP":    {intrinsic: "fmaxp", kind: arm64SVEFloatMinMaxPairwise},
	"ZFMAXQV":   {intrinsic: "fmaxqv", kind: arm64SVEFloatMinMaxQuadReduce},
	"ZFMAXVH":   {intrinsic: "fmaxv", kind: arm64SVEFloatMinMaxReduce, elementBits: 16},
	"ZFMAXVS":   {intrinsic: "fmaxv", kind: arm64SVEFloatMinMaxReduce, elementBits: 32},
	"ZFMAXVD":   {intrinsic: "fmaxv", kind: arm64SVEFloatMinMaxReduce, elementBits: 64},
	"ZFMIN":     {intrinsic: "fmin", kind: arm64SVEFloatMinMaxDirect},
	"ZFMINP":    {intrinsic: "fminp", kind: arm64SVEFloatMinMaxPairwise},
	"ZFMINQV":   {intrinsic: "fminqv", kind: arm64SVEFloatMinMaxQuadReduce},
	"ZFMINVH":   {intrinsic: "fminv", kind: arm64SVEFloatMinMaxReduce, elementBits: 16},
	"ZFMINVS":   {intrinsic: "fminv", kind: arm64SVEFloatMinMaxReduce, elementBits: 32},
	"ZFMINVD":   {intrinsic: "fminv", kind: arm64SVEFloatMinMaxReduce, elementBits: 64},
	"ZFMAXNM":   {intrinsic: "fmaxnm", kind: arm64SVEFloatMinMaxDirect},
	"ZFMAXNMP":  {intrinsic: "fmaxnmp", kind: arm64SVEFloatMinMaxPairwise},
	"ZFMAXNMQV": {intrinsic: "fmaxnmqv", kind: arm64SVEFloatMinMaxQuadReduce},
	"ZFMAXNMVH": {intrinsic: "fmaxnmv", kind: arm64SVEFloatMinMaxReduce, elementBits: 16},
	"ZFMAXNMVS": {intrinsic: "fmaxnmv", kind: arm64SVEFloatMinMaxReduce, elementBits: 32},
	"ZFMAXNMVD": {intrinsic: "fmaxnmv", kind: arm64SVEFloatMinMaxReduce, elementBits: 64},
	"ZFMINNM":   {intrinsic: "fminnm", kind: arm64SVEFloatMinMaxDirect},
	"ZFMINNMP":  {intrinsic: "fminnmp", kind: arm64SVEFloatMinMaxPairwise},
	"ZFMINNMQV": {intrinsic: "fminnmqv", kind: arm64SVEFloatMinMaxQuadReduce},
	"ZFMINNMVH": {intrinsic: "fminnmv", kind: arm64SVEFloatMinMaxReduce, elementBits: 16},
	"ZFMINNMVS": {intrinsic: "fminnmv", kind: arm64SVEFloatMinMaxReduce, elementBits: 32},
	"ZFMINNMVD": {intrinsic: "fminnmv", kind: arm64SVEFloatMinMaxReduce, elementBits: 64},
}

type arm64SVEFloatMinMaxForm struct {
	elementBits  int
	first        int
	second       int
	predicate    int
	destination  int
	immediate    float64
	hasImmediate bool
}

// Four orthogonal opcode choices (min/max and numeric/propagating NaNs)
// share the same direct, immediate, pairwise and quad-reduction fields.
// Ordinary reductions already use decodeARM64RawSVEFloatMinMaxReduction.
func decodeARM64RawSVEFloatMinMax(word uint32) (Instr, bool) {
	size := word >> 22 & 3
	if size == 0 {
		return Instr{}, false
	}
	op := [...]Op{"ZFMAXNM", "ZFMINNM", "ZFMAX", "ZFMIN"}[word>>16&3]
	width := "BHSD"[size]
	source := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", word>>5&31, width))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", word&31, width))}
	predicate := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d.M", word>>10&7))}
	args := []Operand{source, destination, predicate, destination}
	switch word & 0xff3ce000 {
	case 0x65048000:
	case 0x651c8000:
		if word&0x3c0 != 0 {
			return Instr{}, false
		}
		args[0] = Operand{Kind: OpImm, ImmIsFloat: true, Imm: int64(math.Float64bits(float64(word >> 5 & 1)))}
	case 0x64148000:
		op += "P"
	case 0x6414a000:
		op += "QV"
		args = []Operand{
			source,
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d", word>>10&7))},
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("V%d.%c%d", word&31, width, 16>>size))},
		}
	default:
		return Instr{}, false
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("WORD $%#08x", word)}, true
}

func (c *arm64Ctx) lowerARM64SVEFloatMinMax(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVEFloatMinMaxSpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) {
		return true, false, fmt.Errorf("arm64 %s does not accept an instruction suffix: %q", op, ins.Raw)
	}

	switch spec.kind {
	case arm64SVEFloatMinMaxDirect, arm64SVEFloatMinMaxPairwise:
		form, err := arm64ParseSVEFloatMinMaxDirectForm(op, spec, ins)
		if err != nil {
			return true, false, err
		}
		return true, false, c.lowerARM64SVEFloatMinMaxDirectForm(spec, form)
	case arm64SVEFloatMinMaxReduce, arm64SVEFloatMinMaxQuadReduce:
		form, err := arm64ParseSVEFloatMinMaxReductionForm(op, spec, ins)
		if err != nil {
			return true, false, err
		}
		return true, false, c.lowerARM64SVEFloatMinMaxReductionForm(spec, form, ins.Args[2].Reg)
	default:
		return true, false, fmt.Errorf("arm64 %s has an unknown SVE floating min/max form", op)
	}
}

func arm64ParseSVEFloatMinMaxDirectForm(op Op, spec arm64SVEFloatMinMaxSpec, ins Instr) (arm64SVEFloatMinMaxForm, error) {
	form := arm64SVEFloatMinMaxForm{}
	if len(ins.Args) != 4 {
		return form, fmt.Errorf("arm64 %s expects its four-operand predicated Go 1.27 form: %q", op, ins.Raw)
	}
	first, firstBits, firstOK := arm64SVEFloatElementReg(ins.Args[1])
	predicate, predicateOK := arm64ParseSVEPredicateMerge(ins.Args[2])
	destination, destinationBits, destinationOK := arm64SVEFloatElementReg(ins.Args[3])
	if !firstOK || !predicateOK || !destinationOK || first != destination || firstBits != destinationBits {
		return form, fmt.Errorf("arm64 %s requires matching-width destructive registers and P0..P7/M: %q", op, ins.Raw)
	}
	form = arm64SVEFloatMinMaxForm{elementBits: firstBits, first: first, predicate: predicate, destination: destination}
	if ins.Args[0].Kind == OpImm {
		if spec.kind != arm64SVEFloatMinMaxDirect || ins.Args[0].ImmRaw != "" || !ins.Args[0].ImmIsFloat {
			return form, fmt.Errorf("arm64 %s does not accept this floating immediate: %q", op, ins.Raw)
		}
		form.immediate = math.Float64frombits(uint64(ins.Args[0].Imm))
		if form.immediate != 0 && form.immediate != 1 {
			return form, fmt.Errorf("arm64 %s immediate must be $(0.0) or $(1.0): %q", op, ins.Raw)
		}
		form.hasImmediate = true
		return form, nil
	}
	second, secondBits, secondOK := arm64SVEFloatElementReg(ins.Args[0])
	if !secondOK || secondBits != firstBits {
		return form, fmt.Errorf("arm64 %s vector operands must have identical H, S, or D widths: %q", op, ins.Raw)
	}
	form.second = second
	return form, nil
}

func arm64ParseSVEFloatMinMaxReductionForm(op Op, spec arm64SVEFloatMinMaxSpec, ins Instr) (arm64SVEFloatMinMaxForm, error) {
	form := arm64SVEFloatMinMaxForm{}
	if len(ins.Args) != 3 || ins.Args[2].Kind != OpReg {
		return form, fmt.Errorf("arm64 %s expects Zn.T, Pg, Vd%s: %q", op, map[bool]string{true: ".T", false: ""}[spec.kind == arm64SVEFloatMinMaxQuadReduce], ins.Raw)
	}
	first, elementBits, firstOK := arm64SVEFloatElementReg(ins.Args[0])
	predicate, predicateOK := arm64ParseSVEPredicate(ins.Args[1])
	destination, destinationOK := arm64ParseVReg(ins.Args[2].Reg)
	if !firstOK || !predicateOK || predicate > 7 || !destinationOK {
		return form, fmt.Errorf("arm64 %s requires an H/S/D scalable source, bare P0..P7, and SIMD destination: %q", op, ins.Raw)
	}
	if spec.kind == arm64SVEFloatMinMaxReduce {
		if strings.Contains(string(ins.Args[2].Reg), ".") {
			return form, fmt.Errorf("arm64 %s destination must be a bare V register: %q", op, ins.Raw)
		}
		opcodeSize := map[int]int{16: 1, 32: 2, 64: 3}[spec.elementBits]
		sourceSize := map[int]int{16: 1, 32: 2, 64: 3}[elementBits]
		elementBits = 8 << (opcodeSize | sourceSize)
	} else {
		arrangement, arrangementOK := parseARM64VectorArrangement(ins.Args[2].Reg)
		if !arrangementOK || arrangement.elementBits != elementBits || arrangement.lanes*arrangement.elementBits != 128 {
			return form, fmt.Errorf("arm64 %s destination must be a full-width SIMD vector matching its source elements: %q", op, ins.Raw)
		}
	}
	form = arm64SVEFloatMinMaxForm{elementBits: elementBits, first: first, predicate: predicate, destination: destination}
	return form, nil
}

func arm64SVEFloatType(elementBits int) (scalar, vector string, lanes int, err error) {
	lanes = 128 / elementBits
	scalar, ok := map[int]string{16: "half", 32: "float", 64: "double"}[elementBits]
	if !ok {
		return "", "", 0, fmt.Errorf("unsupported ARM64 SVE floating element width %d", elementBits)
	}
	return scalar, fmt.Sprintf("<vscale x %d x %s>", lanes, scalar), lanes, nil
}

func (c *arm64Ctx) arm64SVEFloatSplat(value float64, elementBits int) (string, error) {
	integerType, _, err := arm64SVEVectorType(elementBits)
	if err != nil {
		return "", err
	}
	_, vectorType, _, err := arm64SVEFloatType(elementBits)
	if err != nil {
		return "", err
	}
	var bits uint64
	switch elementBits {
	case 16:
		bits = uint64(arm64Float16Bits(value))
	case 32:
		bits = uint64(math.Float32bits(float32(value)))
	case 64:
		bits = math.Float64bits(value)
	}
	converted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s splat (i%d %d) to %s\n", converted, integerType, elementBits, bits, vectorType)
	return "%" + converted, nil
}

func (c *arm64Ctx) lowerARM64SVEFloatMinMaxDirectForm(spec arm64SVEFloatMinMaxSpec, form arm64SVEFloatMinMaxForm) error {
	first, vectorType, err := c.loadRawSVEFloatVector(form.first, form.elementBits)
	if err != nil {
		return err
	}
	second := ""
	if form.hasImmediate {
		second, err = c.arm64SVEFloatSplat(form.immediate, form.elementBits)
	} else {
		second, _, err = c.loadRawSVEFloatVector(form.second, form.elementBits)
	}
	if err != nil {
		return err
	}
	predicate, predicateType, err := c.loadPRegElements(form.predicate, form.elementBits)
	if err != nil {
		return err
	}
	_, _, lanes, err := arm64SVEFloatType(form.elementBits)
	if err != nil {
		return err
	}
	calculated := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%d%s(%s %s, %s %s, %s %s)\n", calculated, vectorType, spec.intrinsic, lanes, map[int]string{16: "f16", 32: "f32", 64: "f64"}[form.elementBits], predicateType, predicate, vectorType, first, vectorType, second)
	selected := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select %s %s, %s %%%s, %s %s\n", selected, predicateType, predicate, vectorType, calculated, vectorType, first)
	return c.storeRawSVEFloatVector(form.destination, form.elementBits, "%"+selected, vectorType)
}

func (c *arm64Ctx) lowerARM64SVEFloatMinMaxReductionForm(spec arm64SVEFloatMinMaxSpec, form arm64SVEFloatMinMaxForm, destination Reg) error {
	source, vectorType, err := c.loadRawSVEFloatVector(form.first, form.elementBits)
	if err != nil {
		return err
	}
	predicate, predicateType, err := c.loadPRegElements(form.predicate, form.elementBits)
	if err != nil {
		return err
	}
	scalarType, _, lanes, err := arm64SVEFloatType(form.elementBits)
	if err != nil {
		return err
	}
	mangle := fmt.Sprintf("nxv%d%s", lanes, map[int]string{16: "f16", 32: "f32", 64: "f64"}[form.elementBits])
	result := c.newTmp()
	if spec.kind == arm64SVEFloatMinMaxReduce {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.%s(%s %s, %s %s)\n", result, scalarType, spec.intrinsic, mangle, predicateType, predicate, vectorType, source)
		fixed := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x %s> zeroinitializer, %s %%%s, i32 0\n", fixed, lanes, scalarType, scalarType, result)
		result = fixed
	} else {
		fmt.Fprintf(c.b, "  %%%s = call <%d x %s> @llvm.aarch64.sve.%s.v%d%s.%s(%s %s, %s %s)\n", result, lanes, scalarType, spec.intrinsic, lanes, map[int]string{16: "f16", 32: "f32", 64: "f64"}[form.elementBits], mangle, predicateType, predicate, vectorType, source)
	}
	bytes := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x %s> %%%s to <16 x i8>\n", bytes, lanes, scalarType, result)
	return c.storeVReg(destination, "%"+bytes)
}
