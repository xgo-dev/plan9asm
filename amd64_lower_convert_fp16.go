package plan9asm

import (
	"fmt"
	"strings"
)

// FP16 map5/map6 conversions are both load forms. The lane types determine
// access and result widths; encoded VL distinguishes the two X destinations.
func (c *amd64Ctx) lowerRawFP16Conversion(ins Instr, spec amd64HalfConversionSpec) (bool, bool, error) {
	if !ins.x86Encoded {
		return true, false, fmt.Errorf("%s has no named Go assembler form: %q", ins.Op, ins.Raw)
	}
	vl := ins.x86VectorBytes
	if !spec.scalar && vl != 16 && vl != 32 && vl != 64 {
		return true, false, fmt.Errorf("%s has invalid encoded vector length %d", ins.Op, vl)
	}
	operandCount := 2
	if spec.scalar {
		operandCount = 3
	}
	if len(ins.Args) != operandCount && len(ins.Args) != operandCount+1 {
		return true, false, fmt.Errorf("%s requires source, [K mask,] destination", ins.Op)
	}
	base := strings.SplitN(string(ins.Op), ".", 2)[0]
	suffix := strings.TrimPrefix(string(ins.Op), base)
	sae := suffix == ".SAE" || suffix == ".SAE.Z"
	if sae {
		suffix = strings.TrimPrefix(suffix, ".SAE")
	}
	properties, valid := parseAMD64FMA3Suffix(strings.TrimPrefix(suffix, "."))
	if !valid || spec.inputBits == 16 && properties.rounding != "" || spec.outputBits == 16 && sae {
		return true, false, fmt.Errorf("%s has invalid conversion controls", ins.Op)
	}
	masked := len(ins.Args) == operandCount+1
	if properties.zeroing && !masked || masked && !amd64NonzeroKOperand(ins.Args[len(ins.Args)-2]) {
		return true, false, fmt.Errorf("%s requires K1-K7 for masking", ins.Op)
	}
	if spec.scalar {
		return c.lowerRawScalarHalfConversion(ins, spec, properties, sae)
	}
	source, destination := ins.Args[0], ins.Args[len(ins.Args)-1]
	lanes := vl / 4
	inputBytes, outputBytes := lanes*spec.inputBits/8, lanes*spec.outputBits/8
	sourceRegisterBytes, destinationRegisterBytes := inputBytes, outputBytes
	if sourceRegisterBytes < 16 {
		sourceRegisterBytes = 16
	}
	if destinationRegisterBytes < 16 {
		destinationRegisterBytes = 16
	}
	if !c.isGoEVEXVectorRegister(destination, destinationRegisterBytes) {
		return true, false, fmt.Errorf("%s has an invalid destination register", ins.Op)
	}
	if source.Kind == OpReg {
		if !c.isGoEVEXVectorRegister(source, sourceRegisterBytes) || properties.broadcast {
			return true, false, fmt.Errorf("%s has invalid source width or register broadcast", ins.Op)
		}
	} else if !isAMD64MemoryOperand(source) || sae || properties.rounding != "" {
		return true, false, fmt.Errorf("%s has invalid memory or rounding operands", ins.Op)
	}
	if (sae || properties.rounding != "") && vl != 64 {
		return true, false, fmt.Errorf("%s explicit rounding/SAE requires 512-bit VL", ins.Op)
	}

	mask := ""
	var err error
	if masked {
		mask, err = c.loadK(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
	}
	var input string
	if source.Kind == OpReg || !masked && !properties.broadcast {
		input, err = c.loadPackedExtendInputs(source, sourceRegisterBytes, lanes, spec.inputBits)
	} else {
		input, err = c.loadMaskedPackedCompareLanes(source, inputBytes, spec.inputBits, properties.broadcast, mask)
	}
	if err != nil {
		return true, false, err
	}
	result := c.emitHalfConversion(lanes, spec, input, properties.rounding)
	if masked {
		old, err := c.loadPackedExtendInputs(destination, destinationRegisterBytes, lanes, spec.outputBits)
		if err != nil {
			return true, false, err
		}
		result = amd64ApplyIntegerLaneMask(c, lanes, spec.outputBits, result, old, mask, properties.zeroing)
	}
	bytes := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", bytes, lanes, spec.outputBits, result, outputBytes)
	return true, false, c.storePackedHalfResult(destination, destinationRegisterBytes, outputBytes, "%"+bytes)
}

func (c *amd64Ctx) emitHalfConversion(lanes int, spec amd64HalfConversionSpec, input, rounding string) string {
	inputType := amd64FMA3LLVMType(1, spec.inputBits)
	outputType := amd64FMA3LLVMType(1, spec.outputBits)
	conversion := "fpext"
	if spec.outputBits == 16 {
		conversion = "fptrunc"
	}
	floats, converted, bits := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x %s>\n", floats, lanes, spec.inputBits, input, lanes, inputType)
	fmt.Fprintf(c.b, "  %%%s = %s <%d x %s> %%%s to <%d x %s>\n", converted, conversion, lanes, inputType, floats, lanes, outputType)
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x %s> %%%s to <%d x i%d>\n", bits, lanes, outputType, converted, lanes, spec.outputBits)
	result := "%" + bits
	if spec.outputBits == 16 {
		result = c.adjustFP16NarrowRounding(lanes, inputType, "%"+floats, "%"+converted, result, rounding)
	}
	return result
}

// Directed rounding differs from nearest-even by at most one half ULP.
// Comparing the exactly widened result lets integer correction preserve
// signed zero, subnormals, NaNs and directed overflow without changing the
// host FP environment. LLVM 22's AArch64 constrained fptrunc does not honor
// these static rounding modes for half, so it cannot serve as this oracle.
func (c *amd64Ctx) adjustFP16NarrowRounding(lanes int, inputType, original, halves, bits, rounding string) string {
	if rounding == "" || rounding == "RN_SAE" {
		return bits
	}
	widened, below, above, negative := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = fpext <%d x half> %s to <%d x %s>\n", widened, lanes, halves, lanes, inputType)
	fmt.Fprintf(c.b, "  %%%s = fcmp olt <%d x %s> %%%s, %s\n", below, lanes, inputType, widened, original)
	fmt.Fprintf(c.b, "  %%%s = fcmp ogt <%d x %s> %%%s, %s\n", above, lanes, inputType, widened, original)
	fmt.Fprintf(c.b, "  %%%s = icmp slt <%d x i16> %s, zeroinitializer\n", negative, lanes, bits)
	one := amd64SplatInteger(c, lanes, 16, "1")
	plus, minus := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add <%d x i16> %s, %s\n", plus, lanes, bits, one)
	fmt.Fprintf(c.b, "  %%%s = sub <%d x i16> %s, %s\n", minus, lanes, bits, one)
	condition, adjusted := "%"+above, "%"+minus
	choice := c.newTmp()
	switch rounding {
	case "RD_SAE":
		fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, <%d x i16> %%%s, <%d x i16> %%%s\n", choice, lanes, negative, lanes, plus, lanes, minus)
		adjusted = "%" + choice
	case "RU_SAE":
		fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, <%d x i16> %%%s, <%d x i16> %%%s\n", choice, lanes, negative, lanes, minus, lanes, plus)
		condition, adjusted = "%"+below, "%"+choice
	case "RZ_SAE":
		fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, <%d x i1> %%%s, <%d x i1> %%%s\n", choice, lanes, negative, lanes, below, lanes, above)
		condition = "%" + choice
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %s, <%d x i16> %s, <%d x i16> %s\n", result, lanes, condition, lanes, adjusted, lanes, bits)
	return "%" + result
}
