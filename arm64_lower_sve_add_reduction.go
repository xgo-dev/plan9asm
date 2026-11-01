package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVEAddReductionKind uint8

const (
	arm64SVEFloatAddAccumulate arm64SVEAddReductionKind = iota
	arm64SVEFloatAddReduce
	arm64SVEFloatAddQuadReduce
	arm64SVESignedAddReduce
	arm64SVEUnsignedAddReduce
)

type arm64SVEAddReductionSpec struct {
	kind        arm64SVEAddReductionKind
	elementBits int
}

var arm64SVEAddReductionSpecs = map[Op]arm64SVEAddReductionSpec{
	"ZFADDAD": {kind: arm64SVEFloatAddAccumulate, elementBits: 64},
	"ZFADDAH": {kind: arm64SVEFloatAddAccumulate, elementBits: 16},
	"ZFADDAS": {kind: arm64SVEFloatAddAccumulate, elementBits: 32},
	"ZFADDQV": {kind: arm64SVEFloatAddQuadReduce},
	"ZFADDVD": {kind: arm64SVEFloatAddReduce, elementBits: 64},
	"ZFADDVH": {kind: arm64SVEFloatAddReduce, elementBits: 16},
	"ZFADDVS": {kind: arm64SVEFloatAddReduce, elementBits: 32},
	"ZSADDVD": {kind: arm64SVESignedAddReduce},
	"ZUADDVD": {kind: arm64SVEUnsignedAddReduce},
}

type arm64SVEAddReductionForm struct {
	elementBits int
	source      int
	predicate   int
	destination int
}

func (c *arm64Ctx) lowerARM64SVEAddReduction(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVEAddReductionSpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) {
		return true, false, fmt.Errorf("arm64 %s does not accept an instruction suffix: %q", op, ins.Raw)
	}
	form, err := arm64ParseSVEAddReductionForm(op, spec, ins)
	if err != nil {
		return true, false, err
	}
	return true, false, c.lowerARM64SVEAddReductionForm(spec, form, ins.Args[len(ins.Args)-1].Reg)
}

func arm64ParseSVEAddReductionForm(op Op, spec arm64SVEAddReductionSpec, ins Instr) (arm64SVEAddReductionForm, error) {
	form := arm64SVEAddReductionForm{}
	if spec.kind == arm64SVEFloatAddAccumulate {
		if len(ins.Args) != 4 || ins.Args[1].Kind != OpReg || ins.Args[3].Kind != OpReg {
			return form, fmt.Errorf("arm64 %s expects Zm.T, Vdn, Pg, Vdn: %q", op, ins.Raw)
		}
		source, sourceBits, sourceOK := arm64SVEFloatElementReg(ins.Args[0])
		initial, initialOK := arm64ParseVReg(ins.Args[1].Reg)
		predicate, predicateOK := arm64ParseSVEPredicate(ins.Args[2])
		destination, destinationOK := arm64ParseVReg(ins.Args[3].Reg)
		if !sourceOK || !initialOK || !predicateOK || predicate > 7 || !destinationOK || initial != destination || strings.Contains(string(ins.Args[1].Reg), ".") || strings.Contains(string(ins.Args[3].Reg), ".") {
			return form, fmt.Errorf("arm64 %s requires an H/S/D source, bare P0..P7, and one destructive bare V register: %q", op, ins.Raw)
		}
		return arm64SVEAddReductionForm{elementBits: arm64SVEFloatReductionElementBits(spec.elementBits, sourceBits), source: source, predicate: predicate, destination: destination}, nil
	}
	if len(ins.Args) != 3 || ins.Args[2].Kind != OpReg {
		return form, fmt.Errorf("arm64 %s expects Zn.T, Pg, Vd: %q", op, ins.Raw)
	}
	predicate, predicateOK := arm64ParseSVEPredicate(ins.Args[1])
	destination, destinationOK := arm64ParseVReg(ins.Args[2].Reg)
	if !predicateOK || predicate > 7 || !destinationOK {
		return form, fmt.Errorf("arm64 %s requires a bare P0..P7 and SIMD destination: %q", op, ins.Raw)
	}
	switch spec.kind {
	case arm64SVEFloatAddReduce, arm64SVEFloatAddQuadReduce:
		source, sourceBits, sourceOK := arm64SVEFloatElementReg(ins.Args[0])
		if !sourceOK {
			return form, fmt.Errorf("arm64 %s source must use H, S, or D elements: %q", op, ins.Raw)
		}
		if spec.kind == arm64SVEFloatAddReduce {
			if strings.Contains(string(ins.Args[2].Reg), ".") {
				return form, fmt.Errorf("arm64 %s destination must be a bare V register: %q", op, ins.Raw)
			}
			sourceBits = arm64SVEFloatReductionElementBits(spec.elementBits, sourceBits)
		} else {
			arrangement, arrangementOK := parseARM64VectorArrangement(ins.Args[2].Reg)
			if !arrangementOK || arrangement.elementBits != sourceBits || arrangement.lanes*arrangement.elementBits != 128 {
				return form, fmt.Errorf("arm64 %s destination must be a full-width SIMD vector matching its source elements: %q", op, ins.Raw)
			}
		}
		return arm64SVEAddReductionForm{elementBits: sourceBits, source: source, predicate: predicate, destination: destination}, nil
	case arm64SVESignedAddReduce, arm64SVEUnsignedAddReduce:
		source, sourceBits, sourceOK := arm64ParseSVEZElementReg(ins.Args[0])
		if !sourceOK || (spec.kind == arm64SVESignedAddReduce && sourceBits == 64) || strings.Contains(string(ins.Args[2].Reg), ".") {
			return form, fmt.Errorf("arm64 %s source/destination widths are outside its Go 1.27 form: %q", op, ins.Raw)
		}
		return arm64SVEAddReductionForm{elementBits: sourceBits, source: source, predicate: predicate, destination: destination}, nil
	default:
		return form, fmt.Errorf("arm64 %s has an unknown SVE add reduction form", op)
	}
}

func arm64SVEFloatReductionElementBits(opcodeBits, sourceBits int) int {
	opcodeSize := map[int]int{16: 1, 32: 2, 64: 3}[opcodeBits]
	sourceSize := map[int]int{16: 1, 32: 2, 64: 3}[sourceBits]
	return 8 << (opcodeSize | sourceSize)
}

func (c *arm64Ctx) lowerARM64SVEAddReductionForm(spec arm64SVEAddReductionSpec, form arm64SVEAddReductionForm, destination Reg) error {
	predicate, predicateType, err := c.loadPRegElements(form.predicate, form.elementBits)
	if err != nil {
		return err
	}
	if spec.kind == arm64SVESignedAddReduce || spec.kind == arm64SVEUnsignedAddReduce {
		source, vectorType, err := c.loadZRegElements(form.source, form.elementBits)
		if err != nil {
			return err
		}
		lanes := 128 / form.elementBits
		intrinsic := map[arm64SVEAddReductionKind]string{arm64SVESignedAddReduce: "saddv", arm64SVEUnsignedAddReduce: "uaddv"}[spec.kind]
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i64 @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s)\n", result, intrinsic, lanes, form.elementBits, predicateType, predicate, vectorType, source)
		return c.storeARM64ScalarToVReg(destination, 64, "%"+result)
	}
	source, vectorType, err := c.loadRawSVEFloatVector(form.source, form.elementBits)
	if err != nil {
		return err
	}
	scalarType, _, lanes, err := arm64SVEFloatType(form.elementBits)
	if err != nil {
		return err
	}
	mangle := fmt.Sprintf("nxv%d%s", lanes, map[int]string{16: "f16", 32: "f32", 64: "f64"}[form.elementBits])
	result := c.newTmp()
	switch spec.kind {
	case arm64SVEFloatAddAccumulate:
		initialBytes, err := c.loadVReg(destination)
		if err != nil {
			return err
		}
		initialVector := c.newTmp()
		initial := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <%d x %s>\n", initialVector, initialBytes, lanes, scalarType)
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x %s> %%%s, i32 0\n", initial, lanes, scalarType, initialVector)
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.fadda.%s(%s %s, %s %%%s, %s %s)\n", result, scalarType, mangle, predicateType, predicate, scalarType, initial, vectorType, source)
		return c.storeARM64SVEFloatScalarToVReg(destination, form.elementBits, "%"+result)
	case arm64SVEFloatAddReduce:
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.faddv.%s(%s %s, %s %s)\n", result, scalarType, mangle, predicateType, predicate, vectorType, source)
		return c.storeARM64SVEFloatScalarToVReg(destination, form.elementBits, "%"+result)
	case arm64SVEFloatAddQuadReduce:
		fmt.Fprintf(c.b, "  %%%s = call <%d x %s> @llvm.aarch64.sve.faddqv.v%d%s.%s(%s %s, %s %s)\n", result, lanes, scalarType, lanes, map[int]string{16: "f16", 32: "f32", 64: "f64"}[form.elementBits], mangle, predicateType, predicate, vectorType, source)
		bytes := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x %s> %%%s to <16 x i8>\n", bytes, lanes, scalarType, result)
		return c.storeVReg(destination, "%"+bytes)
	default:
		return fmt.Errorf("unknown ARM64 SVE add reduction kind %d", spec.kind)
	}
}

func (c *arm64Ctx) storeARM64SVEFloatScalarToVReg(destination Reg, elementBits int, value string) error {
	scalarType, _, lanes, err := arm64SVEFloatType(elementBits)
	if err != nil {
		return err
	}
	fixed := c.newTmp()
	bytes := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <%d x %s> zeroinitializer, %s %s, i32 0\n", fixed, lanes, scalarType, scalarType, value)
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x %s> %%%s to <16 x i8>\n", bytes, lanes, scalarType, fixed)
	return c.storeVReg(destination, "%"+bytes)
}
