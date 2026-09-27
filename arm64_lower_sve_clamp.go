package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVEClampKind uint8

const (
	arm64SVEClampInteger arm64SVEClampKind = iota
	arm64SVEClampFloat
	arm64SVEClampBFloat
)

type arm64SVEClampSpec struct {
	intrinsic string
	kind      arm64SVEClampKind
}

var arm64SVEClampSpecs = map[Op]arm64SVEClampSpec{
	"ZSCLAMP":  {intrinsic: "sclamp", kind: arm64SVEClampInteger},
	"ZUCLAMP":  {intrinsic: "uclamp", kind: arm64SVEClampInteger},
	"ZFCLAMP":  {intrinsic: "fclamp", kind: arm64SVEClampFloat},
	"ZBFCLAMP": {intrinsic: "fclamp", kind: arm64SVEClampBFloat},
}

func (c *arm64Ctx) lowerARM64SVEClamp(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVEClampSpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects Zm.T, Zn.T, Zd.T without a suffix: %q", op, ins.Raw)
	}
	maximum, maximumBits, maximumOK := arm64ParseSVEZElementReg(ins.Args[0])
	minimum, minimumBits, minimumOK := arm64ParseSVEZElementReg(ins.Args[1])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	if !maximumOK || !minimumOK || !destinationOK || maximumBits != destinationBits || minimumBits != destinationBits || !arm64SVEClampWidthOK(spec.kind, destinationBits) {
		return true, false, fmt.Errorf("arm64 %s has invalid or mismatched element widths: %q", op, ins.Raw)
	}

	switch spec.kind {
	case arm64SVEClampInteger:
		return true, false, c.lowerARM64SVEIntegerClamp(spec, destinationBits, destination, minimum, maximum)
	case arm64SVEClampFloat:
		return true, false, c.lowerARM64SVEFloatClamp(spec, destinationBits, destination, minimum, maximum)
	case arm64SVEClampBFloat:
		return true, false, c.lowerARM64SVEBFloatClamp(spec, destination, minimum, maximum)
	default:
		return true, false, fmt.Errorf("arm64 %s has an unknown clamp kind", op)
	}
}

func arm64SVEClampWidthOK(kind arm64SVEClampKind, bits int) bool {
	switch kind {
	case arm64SVEClampInteger:
		return bits == 8 || bits == 16 || bits == 32 || bits == 64
	case arm64SVEClampFloat:
		return bits == 16 || bits == 32 || bits == 64
	case arm64SVEClampBFloat:
		return bits == 16
	default:
		return false
	}
}

func (c *arm64Ctx) lowerARM64SVEIntegerClamp(spec arm64SVEClampSpec, bits, destination, minimum, maximum int) error {
	value, vectorType, err := c.loadZRegElements(destination, bits)
	if err != nil {
		return err
	}
	minimumValue, _, err := c.loadZRegElements(minimum, bits)
	if err != nil {
		return err
	}
	maximumValue, _, err := c.loadZRegElements(maximum, bits)
	if err != nil {
		return err
	}
	lanes := 128 / bits
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s, %s %s)\n", result, vectorType, spec.intrinsic, lanes, bits, vectorType, value, vectorType, minimumValue, vectorType, maximumValue)
	return c.storeZRegElements(destination, bits, "%"+result)
}

func (c *arm64Ctx) lowerARM64SVEFloatClamp(spec arm64SVEClampSpec, bits, destination, minimum, maximum int) error {
	value, vectorType, err := c.loadRawSVEFloatVector(destination, bits)
	if err != nil {
		return err
	}
	minimumValue, _, err := c.loadRawSVEFloatVector(minimum, bits)
	if err != nil {
		return err
	}
	maximumValue, _, err := c.loadRawSVEFloatVector(maximum, bits)
	if err != nil {
		return err
	}
	lanes := 128 / bits
	suffix := map[int]string{16: "f16", 32: "f32", 64: "f64"}[bits]
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%d%s(%s %s, %s %s, %s %s)\n", result, vectorType, spec.intrinsic, lanes, suffix, vectorType, value, vectorType, minimumValue, vectorType, maximumValue)
	return c.storeRawSVEFloatVector(destination, bits, "%"+result, vectorType)
}

func (c *arm64Ctx) lowerARM64SVEBFloatClamp(spec arm64SVEClampSpec, destination, minimum, maximum int) error {
	integerType := "<vscale x 8 x i16>"
	vectorType := "<vscale x 8 x bfloat>"
	values := make([]string, 3)
	for i, reg := range []int{destination, minimum, maximum} {
		integerValue, _, err := c.loadZRegElements(reg, 16)
		if err != nil {
			return err
		}
		converted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", converted, integerType, integerValue, vectorType)
		values[i] = "%" + converted
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv8bf16(%s %s, %s %s, %s %s)\n", result, vectorType, spec.intrinsic, vectorType, values[0], vectorType, values[1], vectorType, values[2])
	integerResult := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to %s\n", integerResult, vectorType, result, integerType)
	return c.storeZRegElements(destination, 16, "%"+integerResult)
}
