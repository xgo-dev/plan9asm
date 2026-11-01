package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVEConvertKind uint8

const (
	arm64SVEConvertFloat arm64SVEConvertKind = iota
	arm64SVEConvertFloatToSigned
	arm64SVEConvertFloatToUnsigned
	arm64SVEConvertSignedToFloat
	arm64SVEConvertUnsignedToFloat
)

type arm64SVEConvertSpec struct {
	kind                 arm64SVEConvertKind
	intrinsic            string
	zeroIntrinsic        string
	zeroKeepsDestination bool
	allowed              map[[2]int]bool
}

var (
	arm64SVEConvertDifferentFloatWidths = arm64SVEWidthPairs(
		[2]int{16, 32}, [2]int{16, 64}, [2]int{32, 16}, [2]int{32, 64}, [2]int{64, 16}, [2]int{64, 32},
	)
	arm64SVEConvertFloatToIntWidths = arm64SVEWidthPairs(
		[2]int{16, 16}, [2]int{16, 32}, [2]int{16, 64}, [2]int{32, 32}, [2]int{32, 64}, [2]int{64, 32}, [2]int{64, 64},
	)
	arm64SVEConvertIntToFloatWidths = arm64SVEWidthPairs(
		[2]int{16, 16}, [2]int{32, 16}, [2]int{32, 32}, [2]int{32, 64}, [2]int{64, 16}, [2]int{64, 32}, [2]int{64, 64},
	)
	arm64SVEConvertSpecs = map[Op]arm64SVEConvertSpec{
		"ZFCVT":   {kind: arm64SVEConvertFloat, allowed: arm64SVEConvertDifferentFloatWidths},
		"ZFCVTZS": {kind: arm64SVEConvertFloatToSigned, allowed: arm64SVEConvertFloatToIntWidths},
		"ZFCVTZU": {kind: arm64SVEConvertFloatToUnsigned, allowed: arm64SVEConvertFloatToIntWidths},
		"ZSCVTF":  {kind: arm64SVEConvertSignedToFloat, allowed: arm64SVEConvertIntToFloatWidths},
		"ZUCVTF":  {kind: arm64SVEConvertUnsignedToFloat, allowed: arm64SVEConvertIntToFloatWidths},
		"ZFCVTLT": {kind: arm64SVEConvertFloat, intrinsic: "fcvtlt", allowed: arm64SVEWidthPairs(
			[2]int{16, 32}, [2]int{32, 64},
		)},
		"ZFCVTX": {kind: arm64SVEConvertFloat, intrinsic: "fcvtx", allowed: arm64SVEWidthPairs(
			[2]int{64, 32},
		)},
		"ZFCVTXNT": {kind: arm64SVEConvertFloat, intrinsic: "fcvtxnt", zeroIntrinsic: "fcvtxnt.z", zeroKeepsDestination: true, allowed: arm64SVEWidthPairs(
			[2]int{64, 32},
		)},
	}
)

func arm64SVEWidthPairs(pairs ...[2]int) map[[2]int]bool {
	result := make(map[[2]int]bool, len(pairs))
	for _, pair := range pairs {
		result[pair] = true
	}
	return result
}

func (c *arm64Ctx) lowerARM64SVEConvert(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVEConvertSpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects Zn.T, P0..P7/M|Z, Zd.T without a suffix: %q", op, ins.Raw)
	}
	source, sourceBits, sourceOK := arm64ParseSVEZElementReg(ins.Args[0])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	if !sourceOK || !destinationOK || !spec.allowed[[2]int{sourceBits, destinationBits}] {
		return true, false, fmt.Errorf("arm64 %s does not accept the requested source/destination widths: %q", op, ins.Raw)
	}
	predicate, mergeOK := arm64ParseSVEPredicateMode(ins.Args[1], "M", 7)
	zeroing := false
	if !mergeOK {
		predicate, zeroing = arm64ParseSVEPredicateMode(ins.Args[1], "Z", 7)
		if !zeroing {
			return true, false, fmt.Errorf("arm64 %s requires P0..P7/M or P0..P7/Z: %q", op, ins.Raw)
		}
	}

	sourceValue, sourceType, err := c.loadARM64SVEConvertVector(source, sourceBits, spec.kind == arm64SVEConvertFloat || spec.kind == arm64SVEConvertFloatToSigned || spec.kind == arm64SVEConvertFloatToUnsigned)
	if err != nil {
		return true, false, err
	}
	destinationFloat := spec.kind == arm64SVEConvertFloat || spec.kind == arm64SVEConvertSignedToFloat || spec.kind == arm64SVEConvertUnsignedToFloat
	merge := "zeroinitializer"
	destinationType, err := arm64SVEConvertVectorType(destinationBits, destinationFloat)
	if err != nil {
		return true, false, err
	}
	if !zeroing || spec.zeroKeepsDestination {
		merge, _, err = c.loadARM64SVEConvertVector(destination, destinationBits, destinationFloat)
		if err != nil {
			return true, false, err
		}
	}
	predicateBits := sourceBits
	if destinationBits > predicateBits {
		predicateBits = destinationBits
	}
	predicateValue, predicateType, err := c.loadPRegElements(predicate, predicateBits)
	if err != nil {
		return true, false, err
	}
	name := arm64SVEConvertIntrinsicName(spec, sourceBits, destinationBits, zeroing)
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s(%s %s, %s %s, %s %s)\n",
		result, destinationType, name, destinationType, merge, predicateType, predicateValue, sourceType, sourceValue)
	if destinationFloat {
		return true, false, c.storeRawSVEFloatVector(destination, destinationBits, "%"+result, destinationType)
	}
	return true, false, c.storeZRegElements(destination, destinationBits, "%"+result)
}

func arm64SVEConvertVectorType(elementBits int, floating bool) (string, error) {
	if floating {
		_, vectorType, _, err := arm64SVEFloatType(elementBits)
		return vectorType, err
	}
	vectorType, _, err := arm64SVEVectorType(elementBits)
	return vectorType, err
}

func (c *arm64Ctx) loadARM64SVEConvertVector(register, elementBits int, floating bool) (string, string, error) {
	if floating {
		return c.loadRawSVEFloatVector(register, elementBits)
	}
	return c.loadZRegElements(register, elementBits)
}

func arm64SVEConvertIntrinsicName(spec arm64SVEConvertSpec, sourceBits, destinationBits int, zeroing bool) string {
	floatCode := map[int]string{16: "f16", 32: "f32", 64: "f64"}
	intCode := map[int]string{16: "i16", 32: "i32", 64: "i64"}
	if spec.intrinsic != "" {
		intrinsic := spec.intrinsic
		if zeroing && spec.zeroIntrinsic != "" {
			intrinsic = spec.zeroIntrinsic
		}
		return intrinsic + "." + floatCode[destinationBits] + floatCode[sourceBits]
	}
	switch spec.kind {
	case arm64SVEConvertFloat:
		return "fcvt." + floatCode[destinationBits] + floatCode[sourceBits]
	case arm64SVEConvertFloatToSigned:
		return "fcvtzs." + intCode[destinationBits] + floatCode[sourceBits]
	case arm64SVEConvertFloatToUnsigned:
		return "fcvtzu." + intCode[destinationBits] + floatCode[sourceBits]
	case arm64SVEConvertSignedToFloat:
		return "scvtf." + floatCode[destinationBits] + intCode[sourceBits]
	default:
		return "ucvtf." + floatCode[destinationBits] + intCode[sourceBits]
	}
}

func emitARM64SVEConvertDeclarations(b *strings.Builder) {
	for _, op := range []Op{"ZFCVT", "ZFCVTZS", "ZFCVTZU", "ZSCVTF", "ZUCVTF", "ZFCVTLT", "ZFCVTX", "ZFCVTXNT"} {
		spec := arm64SVEConvertSpecs[op]
		for _, sourceBits := range []int{16, 32, 64} {
			for _, destinationBits := range []int{16, 32, 64} {
				if !spec.allowed[[2]int{sourceBits, destinationBits}] {
					continue
				}
				sourceFloat := spec.kind == arm64SVEConvertFloat || spec.kind == arm64SVEConvertFloatToSigned || spec.kind == arm64SVEConvertFloatToUnsigned
				destinationFloat := spec.kind == arm64SVEConvertFloat || spec.kind == arm64SVEConvertSignedToFloat || spec.kind == arm64SVEConvertUnsignedToFloat
				sourceType, _ := arm64SVEConvertVectorType(sourceBits, sourceFloat)
				destinationType, _ := arm64SVEConvertVectorType(destinationBits, destinationFloat)
				predicateBits := sourceBits
				if destinationBits > predicateBits {
					predicateBits = destinationBits
				}
				_, predicateLanes, _ := arm64SVEVectorType(predicateBits)
				predicateType := fmt.Sprintf("<vscale x %d x i1>", predicateLanes)
				names := []string{arm64SVEConvertIntrinsicName(spec, sourceBits, destinationBits, false)}
				if spec.zeroIntrinsic != "" {
					names = append(names, arm64SVEConvertIntrinsicName(spec, sourceBits, destinationBits, true))
				}
				for _, name := range names {
					fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.%s(%s, %s, %s)\n",
						destinationType, name, destinationType, predicateType, sourceType)
				}
			}
		}
	}
}
