package plan9asm

import (
	"fmt"
	"strings"
)

var arm64SVEIntegerMatrixMultiplyIntrinsics = map[Op]string{
	"ZSMMLA":  "smmla",
	"ZUMMLA":  "ummla",
	"ZUSMMLA": "usmmla",
}

func (c *arm64Ctx) lowerARM64SVEMatrixMultiply(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if _, integer := arm64SVEIntegerMatrixMultiplyIntrinsics[op]; !integer && op != "ZBFMMLA" && op != "ZFMMLA" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects its complete Go 1.27 three-vector form without a suffix: %q", op, ins.Raw)
	}
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
	first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	if !secondOK || !firstOK || !destinationOK || secondBits != firstBits || !arm64SVEMatrixMultiplyWidthOK(op, firstBits, destinationBits) {
		return true, false, fmt.Errorf("arm64 %s has invalid or mismatched Go 1.27 matrix element widths: %q", op, ins.Raw)
	}
	return true, false, c.lowerARM64SVEMatrixMultiplyForm(op, firstBits, destinationBits, first, second, destination)
}

func arm64SVEMatrixMultiplyWidthOK(op Op, sourceBits, destinationBits int) bool {
	switch op {
	case "ZSMMLA", "ZUMMLA", "ZUSMMLA":
		return sourceBits == 8 && destinationBits == 32
	case "ZBFMMLA":
		return sourceBits == 16 && (destinationBits == 16 || destinationBits == 32)
	case "ZFMMLA":
		return (sourceBits == 8 && (destinationBits == 16 || destinationBits == 32)) ||
			(sourceBits == 16 && (destinationBits == 16 || destinationBits == 32)) ||
			(sourceBits == 32 && destinationBits == 32) ||
			(sourceBits == 64 && destinationBits == 64)
	default:
		return false
	}
}

func (c *arm64Ctx) lowerARM64SVEMatrixMultiplyForm(op Op, sourceBits, destinationBits, firstReg, secondReg, destinationReg int) error {
	if intrinsic, integer := arm64SVEIntegerMatrixMultiplyIntrinsics[op]; integer {
		accumulator, destinationType, err := c.loadZRegElements(destinationReg, 32)
		if err != nil {
			return err
		}
		first, sourceType, err := c.loadZRegElements(firstReg, 8)
		if err != nil {
			return err
		}
		second, _, err := c.loadZRegElements(secondReg, 8)
		if err != nil {
			return err
		}
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv4i32(%s %s, %s %s, %s %s)\n", result, destinationType, intrinsic, destinationType, accumulator, sourceType, first, sourceType, second)
		return c.storeZRegElements(destinationReg, 32, "%"+result)
	}

	destinationScalar := map[int]string{16: "half", 32: "float", 64: "double"}[destinationBits]
	sourceScalar := map[int]string{16: "half", 32: "float", 64: "double"}[sourceBits]
	if op == "ZBFMMLA" {
		sourceScalar = "bfloat"
		if destinationBits == 16 {
			destinationScalar = "bfloat"
		}
	}
	accumulator, destinationType, err := c.loadARM64SVEMatrixFloatVector(destinationReg, destinationBits, destinationScalar)
	if err != nil {
		return err
	}
	first, sourceType, err := c.loadARM64SVEMatrixFloatVector(firstReg, sourceBits, sourceScalar)
	if err != nil {
		return err
	}
	second, _, err := c.loadARM64SVEMatrixFloatVector(secondReg, sourceBits, sourceScalar)
	if err != nil {
		return err
	}
	result := c.newTmp()
	if op == "ZBFMMLA" && destinationBits == 16 {
		fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q(%s %s, %s %s, %s %s)\n", result, destinationType, "bfmmla $0.h, $2.h, $3.h", "=&w,0,w,w", destinationType, accumulator, sourceType, first, sourceType, second)
		return c.storeARM64SVEMatrixFloatVector(destinationReg, destinationBits, destinationType, "%"+result)
	}
	if op == "ZFMMLA" && (sourceBits == 8 || sourceBits == 16 && destinationBits == 16) {
		sourceSuffix := map[int]string{8: "b", 16: "h"}[sourceBits]
		destinationSuffix := map[int]string{16: "h", 32: "s"}[destinationBits]
		assembly := fmt.Sprintf("fmmla $0.%s, $2.%s, $3.%s", destinationSuffix, sourceSuffix, sourceSuffix)
		fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q(%s %s, %s %s, %s %s)\n", result, destinationType, assembly, "=&w,0,w,w", destinationType, accumulator, sourceType, first, sourceType, second)
		return c.storeARM64SVEMatrixFloatVector(destinationReg, destinationBits, destinationType, "%"+result)
	}
	intrinsic := arm64SVEMatrixFloatIntrinsic(op, sourceBits, destinationBits)
	fmt.Fprintf(c.b, "  %%%s = call %s @%s(%s %s, %s %s, %s %s)\n", result, destinationType, intrinsic, destinationType, accumulator, sourceType, first, sourceType, second)
	return c.storeARM64SVEMatrixFloatVector(destinationReg, destinationBits, destinationType, "%"+result)
}

func arm64SVEMatrixFloatIntrinsic(op Op, sourceBits, destinationBits int) string {
	if op == "ZBFMMLA" {
		return "llvm.aarch64.sve.bfmmla"
	}
	suffix := map[int]string{16: "f16", 32: "f32", 64: "f64"}[destinationBits]
	lanes := 128 / destinationBits
	name := fmt.Sprintf("llvm.aarch64.sve.fmmla.nxv%d%s", lanes, suffix)
	if sourceBits != destinationBits {
		name += ".nxv8f16"
	}
	return name
}

func (c *arm64Ctx) loadARM64SVEMatrixFloatVector(reg, bits int, scalar string) (value, vectorType string, err error) {
	integer, integerType, err := c.loadZRegElements(reg, bits)
	if err != nil {
		return "", "", err
	}
	lanes := 128 / bits
	if bits == 8 {
		return integer, integerType, nil
	}
	vectorType = fmt.Sprintf("<vscale x %d x %s>", lanes, scalar)
	converted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", converted, integerType, integer, vectorType)
	return "%" + converted, vectorType, nil
}

func (c *arm64Ctx) storeARM64SVEMatrixFloatVector(reg, bits int, vectorType, value string) error {
	integerType, _, err := arm64SVEVectorType(bits)
	if err != nil {
		return err
	}
	converted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", converted, vectorType, value, integerType)
	return c.storeZRegElements(reg, bits, "%"+converted)
}

func arm64SVEMatrixMultiplyFeatures(op Op, ins Instr) []string {
	if len(ins.Args) != 3 {
		return nil
	}
	_, sourceBits, sourceOK := arm64ParseSVEZElementReg(ins.Args[0])
	_, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	if !sourceOK || !destinationOK || !arm64SVEMatrixMultiplyWidthOK(op, sourceBits, destinationBits) {
		return nil
	}
	switch op {
	case "ZSMMLA", "ZUMMLA", "ZUSMMLA":
		return []string{"+sve", "+i8mm"}
	case "ZBFMMLA":
		if destinationBits == 16 {
			return []string{"+sve", "+sve-b16mm"}
		}
		return []string{"+sve", "+bf16"}
	case "ZFMMLA":
		switch {
		case sourceBits == 8 && destinationBits == 16:
			return []string{"+sve", "+sve2", "+fp8", "+f8f16mm"}
		case sourceBits == 8 && destinationBits == 32:
			return []string{"+sve", "+sve2", "+fp8", "+f8f32mm"}
		case sourceBits == 16 && destinationBits == 16:
			return []string{"+sve", "+sve2p2", "+f16mm"}
		case sourceBits == 16 && destinationBits == 32:
			return []string{"+sve", "+sve-f16f32mm"}
		case sourceBits == 32:
			return []string{"+sve", "+f32mm"}
		case sourceBits == 64:
			return []string{"+sve", "+f64mm"}
		}
	}
	return nil
}
