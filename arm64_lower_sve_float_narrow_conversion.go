package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVEFP8WidenSpec struct {
	intrinsic string
	bfloat    bool
}

var arm64SVEFP8WidenSpecs = map[Op]arm64SVEFP8WidenSpec{
	"ZBF1CVT":   {intrinsic: "cvt1", bfloat: true},
	"ZBF1CVTLT": {intrinsic: "cvtlt1", bfloat: true},
	"ZBF2CVT":   {intrinsic: "cvt2", bfloat: true},
	"ZBF2CVTLT": {intrinsic: "cvtlt2", bfloat: true},
	"ZF1CVT":    {intrinsic: "cvt1"},
	"ZF1CVTLT":  {intrinsic: "cvtlt1"},
	"ZF2CVT":    {intrinsic: "cvt2"},
	"ZF2CVTLT":  {intrinsic: "cvtlt2"},
}

func arm64SVEFloatNarrowConversionOp(op Op) bool {
	if _, ok := arm64SVEFP8WidenSpecs[op]; ok {
		return true
	}
	switch op {
	case "ZBFCVT", "ZBFCVTN", "ZBFCVTNT", "ZFCVTN", "ZFCVTNB", "ZFCVTNT":
		return true
	}
	return false
}

func arm64SVEFloatNarrowConversionUsesFP8(op Op, ins Instr) bool {
	if _, ok := arm64SVEFP8WidenSpecs[op]; ok {
		return true
	}
	switch op {
	case "ZBFCVTN", "ZFCVTN", "ZFCVTNB":
		return true
	case "ZFCVTNT":
		return len(ins.Args) == 2 && ins.Args[0].Kind == OpRegList
	}
	return false
}

func (c *arm64Ctx) lowerARM64SVEFloatNarrowConversion(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if !arm64SVEFloatNarrowConversionOp(op) {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) {
		return true, false, fmt.Errorf("arm64 %s does not accept an instruction suffix: %q", op, ins.Raw)
	}
	if spec, ok := arm64SVEFP8WidenSpecs[op]; ok {
		return c.lowerARM64SVEFP8Widen(op, spec, ins)
	}
	if len(ins.Args) == 2 && ins.Args[0].Kind == OpRegList {
		return c.lowerARM64SVEFP8NarrowPair(op, ins)
	}
	return c.lowerARM64SVEFloatNarrowPredicated(op, ins)
}

func (c *arm64Ctx) lowerARM64SVEFP8Widen(op Op, spec arm64SVEFP8WidenSpec, ins Instr) (bool, bool, error) {
	if len(ins.Args) != 2 {
		return true, false, fmt.Errorf("arm64 %s expects Zn.B, Zd.H: %q", op, ins.Raw)
	}
	source, sourceBits, sourceOK := arm64ParseSVEZElementReg(ins.Args[0])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[1])
	if !sourceOK || !destinationOK || sourceBits != 8 || destinationBits != 16 {
		return true, false, fmt.Errorf("arm64 %s requires an FP8 B source and H destination: %q", op, ins.Raw)
	}
	sourceValue, err := c.loadZReg(source)
	if err != nil {
		return true, false, err
	}
	destinationType := "<vscale x 8 x half>"
	suffix := "f16"
	if spec.bfloat {
		destinationType, suffix = "<vscale x 8 x bfloat>", "bf16"
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.fp8.%s.nxv8%s(<vscale x 16 x i8> %s)\n", result, destinationType, spec.intrinsic, suffix, sourceValue)
	if spec.bfloat {
		return true, false, c.storeARM64SVEBFloatVector(destination, "%"+result)
	}
	return true, false, c.storeRawSVEFloatVector(destination, 16, "%"+result, destinationType)
}

func (c *arm64Ctx) lowerARM64SVEFloatNarrowPredicated(op Op, ins Instr) (bool, bool, error) {
	if len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects Zn.S|D, P0..P7/M|Z, Zd.H|S: %q", op, ins.Raw)
	}
	source, sourceBits, sourceOK := arm64SVEFloatElementReg(ins.Args[0])
	destination, destinationBits, destinationOK := arm64SVEFloatElementReg(ins.Args[2])
	predicate, mergeOK := arm64ParseSVEPredicateMode(ins.Args[1], "M", 7)
	zeroing := false
	if !mergeOK {
		predicate, zeroing = arm64ParseSVEPredicateMode(ins.Args[1], "Z", 7)
	}
	validWidths := sourceBits == 32 && destinationBits == 16
	if op == "ZFCVTNT" {
		validWidths = validWidths || sourceBits == 64 && destinationBits == 32
	}
	if !sourceOK || !destinationOK || (!mergeOK && !zeroing) || !validWidths || (op != "ZBFCVT" && op != "ZBFCVTNT" && op != "ZFCVTNT") {
		return true, false, fmt.Errorf("arm64 %s operands are outside its complete Go 1.27 predicated narrowing forms: %q", op, ins.Raw)
	}
	sourceValue, sourceType, err := c.loadRawSVEFloatVector(source, sourceBits)
	if err != nil {
		return true, false, err
	}
	predicateValue, predicateType, err := c.loadPRegElements(predicate, sourceBits)
	if err != nil {
		return true, false, err
	}
	destinationType := map[int]string{16: "<vscale x 8 x half>", 32: "<vscale x 4 x float>"}[destinationBits]
	mergeValue := "zeroinitializer"
	intrinsic := "fcvt.f16f32"
	bfloat := op == "ZBFCVT" || op == "ZBFCVTNT"
	if bfloat {
		destinationType = "<vscale x 8 x bfloat>"
		intrinsic = "fcvt.bf16f32.v2"
	}
	keepDestination := mergeOK || op == "ZBFCVTNT" || op == "ZFCVTNT"
	if keepDestination {
		if bfloat {
			mergeValue, err = c.loadARM64SVEBFloatVector(destination)
		} else {
			mergeValue, _, err = c.loadRawSVEFloatVector(destination, destinationBits)
		}
		if err != nil {
			return true, false, err
		}
	}
	if op == "ZBFCVTNT" {
		intrinsic = "fcvtnt.bf16f32.v2"
		if zeroing {
			intrinsic = "fcvtnt.z.bf16f32"
		}
	} else if op == "ZFCVTNT" {
		intrinsic = map[[2]int]string{{32, 16}: "fcvtnt.f16f32", {64, 32}: "fcvtnt.f32f64"}[[2]int{sourceBits, destinationBits}]
		if zeroing {
			intrinsic = strings.Replace(intrinsic, "fcvtnt.", "fcvtnt.z.", 1)
		}
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s(%s %s, %s %s, %s %s)\n", result, destinationType, intrinsic, destinationType, mergeValue, predicateType, predicateValue, sourceType, sourceValue)
	if bfloat {
		return true, false, c.storeARM64SVEBFloatVector(destination, "%"+result)
	}
	return true, false, c.storeRawSVEFloatVector(destination, destinationBits, "%"+result, destinationType)
}

func (c *arm64Ctx) lowerARM64SVEFP8NarrowPair(op Op, ins Instr) (bool, bool, error) {
	if len(ins.Args) != 2 {
		return true, false, fmt.Errorf("arm64 %s expects one x2 range and one B destination: %q", op, ins.Raw)
	}
	first, second, sourceBits, sourceOK := arm64ParseSVEEvenVectorPair(ins.Args[0])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[1])
	wantBits := 16
	if op == "ZFCVTNB" || op == "ZFCVTNT" {
		wantBits = 32
	}
	if !sourceOK || !destinationOK || sourceBits != wantBits || destinationBits != 8 || (op != "ZBFCVTN" && op != "ZFCVTN" && op != "ZFCVTNB" && op != "ZFCVTNT") {
		return true, false, fmt.Errorf("arm64 %s requires its exact even/odd x2 floating range and B destination: %q", op, ins.Raw)
	}
	var firstValue, secondValue, sourceType string
	var err error
	if op == "ZBFCVTN" {
		firstValue, err = c.loadARM64SVEBFloatVector(first)
		if err == nil {
			secondValue, err = c.loadARM64SVEBFloatVector(second)
		}
		sourceType = "<vscale x 8 x bfloat>"
	} else {
		firstValue, sourceType, err = c.loadRawSVEFloatVector(first, sourceBits)
		if err == nil {
			secondValue, _, err = c.loadRawSVEFloatVector(second, sourceBits)
		}
	}
	if err != nil {
		return true, false, err
	}
	intrinsic := map[Op]string{
		"ZBFCVTN": "cvtn.nxv8bf16",
		"ZFCVTN":  "cvtn.nxv8f16",
		"ZFCVTNB": "cvtnb.nxv4f32",
		"ZFCVTNT": "cvtnt.nxv4f32",
	}[op]
	result := c.newTmp()
	if op == "ZFCVTNT" {
		oldDestination, err := c.loadZReg(destination)
		if err != nil {
			return true, false, err
		}
		fmt.Fprintf(c.b, "  %%%s = call <vscale x 16 x i8> @llvm.aarch64.sve.fp8.%s(<vscale x 16 x i8> %s, %s %s, %s %s)\n", result, intrinsic, oldDestination, sourceType, firstValue, sourceType, secondValue)
	} else {
		fmt.Fprintf(c.b, "  %%%s = call <vscale x 16 x i8> @llvm.aarch64.sve.fp8.%s(%s %s, %s %s)\n", result, intrinsic, sourceType, firstValue, sourceType, secondValue)
	}
	return true, false, c.storeZReg(destination, "%"+result)
}

func (c *arm64Ctx) loadARM64SVEBFloatVector(register int) (string, error) {
	integer, integerType, err := c.loadZRegElements(register, 16)
	if err != nil {
		return "", err
	}
	converted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <vscale x 8 x bfloat>\n", converted, integerType, integer)
	return "%" + converted, nil
}

func (c *arm64Ctx) storeARM64SVEBFloatVector(register int, value string) error {
	converted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <vscale x 8 x bfloat> %s to <vscale x 8 x i16>\n", converted, value)
	return c.storeZRegElements(register, 16, "%"+converted)
}

func emitARM64SVEFloatNarrowConversionDeclarations(b *strings.Builder) {
	for _, intrinsic := range []string{"cvt1", "cvtlt1", "cvt2", "cvtlt2"} {
		fmt.Fprintf(b, "declare <vscale x 8 x half> @llvm.aarch64.sve.fp8.%s.nxv8f16(<vscale x 16 x i8>)\n", intrinsic)
		fmt.Fprintf(b, "declare <vscale x 8 x bfloat> @llvm.aarch64.sve.fp8.%s.nxv8bf16(<vscale x 16 x i8>)\n", intrinsic)
	}
	b.WriteString("declare <vscale x 8 x bfloat> @llvm.aarch64.sve.fcvt.bf16f32.v2(<vscale x 8 x bfloat>, <vscale x 4 x i1>, <vscale x 4 x float>)\n")
	b.WriteString("declare <vscale x 8 x bfloat> @llvm.aarch64.sve.fcvtnt.bf16f32.v2(<vscale x 8 x bfloat>, <vscale x 4 x i1>, <vscale x 4 x float>)\n")
	b.WriteString("declare <vscale x 8 x bfloat> @llvm.aarch64.sve.fcvtnt.z.bf16f32(<vscale x 8 x bfloat>, <vscale x 4 x i1>, <vscale x 4 x float>)\n")
	b.WriteString("declare <vscale x 8 x half> @llvm.aarch64.sve.fcvtnt.f16f32(<vscale x 8 x half>, <vscale x 4 x i1>, <vscale x 4 x float>)\n")
	b.WriteString("declare <vscale x 8 x half> @llvm.aarch64.sve.fcvtnt.z.f16f32(<vscale x 8 x half>, <vscale x 4 x i1>, <vscale x 4 x float>)\n")
	b.WriteString("declare <vscale x 4 x float> @llvm.aarch64.sve.fcvtnt.f32f64(<vscale x 4 x float>, <vscale x 2 x i1>, <vscale x 2 x double>)\n")
	b.WriteString("declare <vscale x 4 x float> @llvm.aarch64.sve.fcvtnt.z.f32f64(<vscale x 4 x float>, <vscale x 2 x i1>, <vscale x 2 x double>)\n")
	b.WriteString("declare <vscale x 16 x i8> @llvm.aarch64.sve.fp8.cvtn.nxv8bf16(<vscale x 8 x bfloat>, <vscale x 8 x bfloat>)\n")
	b.WriteString("declare <vscale x 16 x i8> @llvm.aarch64.sve.fp8.cvtn.nxv8f16(<vscale x 8 x half>, <vscale x 8 x half>)\n")
	b.WriteString("declare <vscale x 16 x i8> @llvm.aarch64.sve.fp8.cvtnb.nxv4f32(<vscale x 4 x float>, <vscale x 4 x float>)\n")
	b.WriteString("declare <vscale x 16 x i8> @llvm.aarch64.sve.fp8.cvtnt.nxv4f32(<vscale x 16 x i8>, <vscale x 4 x float>, <vscale x 4 x float>)\n")
}
