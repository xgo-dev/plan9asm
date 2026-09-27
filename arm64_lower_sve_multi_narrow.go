package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVEMultiNarrowSpec struct {
	intrinsic      string
	shifted        bool
	signedInput    bool
	unsignedOutput bool
}

var arm64SVEMultiNarrowSpecs = map[Op]arm64SVEMultiNarrowSpec{
	"ZSQCVTN":   {intrinsic: "sqcvtn"},
	"ZSQCVTUN":  {intrinsic: "sqcvtun"},
	"ZUQCVTN":   {intrinsic: "uqcvtn"},
	"ZSQRSHRN":  {intrinsic: "sqrshrn", shifted: true, signedInput: true},
	"ZSQRSHRUN": {intrinsic: "sqrshrun", shifted: true, signedInput: true, unsignedOutput: true},
	"ZUQRSHRN":  {intrinsic: "uqrshrn", shifted: true, unsignedOutput: true},
}

func arm64ParseSVEEvenVectorPair(operand Operand) (first, second, elementBits int, ok bool) {
	if operand.Kind != OpRegList || !operand.RegListRange || len(operand.RegList) != 2 {
		return 0, 0, 0, false
	}
	first, elementBits, firstOK := arm64ParseSVEZElementReg(Operand{Kind: OpReg, Reg: operand.RegList[0]})
	second, secondBits, secondOK := arm64ParseSVEZElementReg(Operand{Kind: OpReg, Reg: operand.RegList[1]})
	return first, second, elementBits, firstOK && secondOK && secondBits == elementBits && first%2 == 0 && second == first+1
}

func (c *arm64Ctx) lowerARM64SVEMultiNarrow(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVEMultiNarrowSpecs[op]
	if !ok {
		return false, false, nil
	}
	wantArgs := 2
	if spec.shifted {
		wantArgs = 3
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != wantArgs {
		return true, false, fmt.Errorf("arm64 %s expects one complete Go 1.27 even/odd x2 range narrowing form without a suffix: %q", op, ins.Raw)
	}
	sourceOperand := 0
	shift := int64(0)
	if spec.shifted {
		if ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" || ins.Args[0].ImmIsFloat {
			return true, false, fmt.Errorf("arm64 %s requires a concrete shift immediate: %q", op, ins.Raw)
		}
		shift, sourceOperand = ins.Args[0].Imm, 1
	}
	first, second, sourceBits, sourceOK := arm64ParseSVEEvenVectorPair(ins.Args[sourceOperand])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[sourceOperand+1])
	validWidths := sourceBits == 32 && destinationBits == 16
	if spec.shifted {
		validWidths = sourceBits == 16 && destinationBits == 8 || sourceBits == 32 && destinationBits == 16
		if shift < 1 || shift > int64(destinationBits) {
			validWidths = false
		}
	}
	if !sourceOK || !destinationOK || !validWidths {
		return true, false, fmt.Errorf("arm64 %s requires an even/odd S-to-H pair, or a legal H-to-B shift pair: %q", op, ins.Raw)
	}
	firstValue, sourceType, err := c.loadZRegElements(first, sourceBits)
	if err != nil {
		return true, false, err
	}
	secondValue, _, err := c.loadZRegElements(second, sourceBits)
	if err != nil {
		return true, false, err
	}
	destinationType, _, err := arm64SVEVectorType(destinationBits)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	if spec.shifted && destinationBits == 8 {
		result = c.lowerARM64SVEMultiShiftNarrowBytes(spec, firstValue, secondValue, shift)
	} else if spec.shifted {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.x2.nxv%di%d(%s %s, %s %s, i32 %d)\n", result, destinationType, spec.intrinsic, 128/sourceBits, sourceBits, sourceType, firstValue, sourceType, secondValue, shift)
	} else {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.x2.nxv4i32(%s %s, %s %s)\n", result, destinationType, spec.intrinsic, sourceType, firstValue, sourceType, secondValue)
	}
	return true, false, c.storeZRegElements(destination, destinationBits, "%"+result)
}

func (c *arm64Ctx) lowerARM64SVEMultiShiftNarrowBytes(spec arm64SVEMultiNarrowSpec, first, second string, shift int64) string {
	narrowed := make([]string, 2)
	for index, source := range []string{first, second} {
		wide := c.newTmp()
		extension := "zext"
		shiftOp := "lshr"
		if spec.signedInput {
			extension, shiftOp = "sext", "ashr"
		}
		fmt.Fprintf(c.b, "  %%%s = %s <vscale x 8 x i16> %s to <vscale x 8 x i32>\n", wide, extension, source)
		rounded := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add <vscale x 8 x i32> %%%s, splat (i32 %d)\n", rounded, wide, int64(1)<<(shift-1))
		shifted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s <vscale x 8 x i32> %%%s, splat (i32 %d)\n", shifted, shiftOp, rounded, shift)

		minimum, maximum := int64(-128), int64(127)
		comparisonPrefix := "s"
		if spec.unsignedOutput {
			minimum, maximum = 0, 255
			if !spec.signedInput {
				comparisonPrefix = "u"
			}
		}
		clampedLow := shifted
		if minimum != 0 || spec.signedInput {
			below := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp %slt <vscale x 8 x i32> %%%s, splat (i32 %d)\n", below, comparisonPrefix, shifted, minimum)
			clampedLow = c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = select <vscale x 8 x i1> %%%s, <vscale x 8 x i32> splat (i32 %d), <vscale x 8 x i32> %%%s\n", clampedLow, below, minimum, shifted)
		}
		above := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp %sgt <vscale x 8 x i32> %%%s, splat (i32 %d)\n", above, comparisonPrefix, clampedLow, maximum)
		clamped := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select <vscale x 8 x i1> %%%s, <vscale x 8 x i32> splat (i32 %d), <vscale x 8 x i32> %%%s\n", clamped, above, maximum, clampedLow)
		narrowed[index] = c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc <vscale x 8 x i32> %%%s to <vscale x 8 x i8>\n", narrowed[index], clamped)
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call <vscale x 16 x i8> @llvm.vector.interleave2.nxv16i8(<vscale x 8 x i8> %%%s, <vscale x 8 x i8> %%%s)\n", result, narrowed[0], narrowed[1])
	return result
}
