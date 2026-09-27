package plan9asm

import (
	"fmt"
	"strings"
)

type amd64HalfConversionSuffix struct {
	sae     bool
	zeroing bool
}

type amd64HalfConversionSpec struct {
	inputBits, outputBits int
	rawOnly               bool
	scalar                bool
}

var amd64HalfConversionSpecs = map[string]amd64HalfConversionSpec{
	"VCVTPH2PS":  {inputBits: 16, outputBits: 32},
	"VCVTPS2PH":  {inputBits: 32, outputBits: 16},
	"VCVTPH2PSX": {inputBits: 16, outputBits: 32, rawOnly: true},
	"VCVTPS2PHX": {inputBits: 32, outputBits: 16, rawOnly: true},
	"VCVTSH2SS":  {inputBits: 16, outputBits: 32, rawOnly: true, scalar: true},
	"VCVTSS2SH":  {inputBits: 32, outputBits: 16, rawOnly: true, scalar: true},
	"VCVTSH2SD":  {inputBits: 16, outputBits: 64, rawOnly: true, scalar: true},
	"VCVTSD2SH":  {inputBits: 64, outputBits: 16, rawOnly: true, scalar: true},
}

func parseAMD64HalfConversionSuffix(rawOp, baseOp string) (amd64HalfConversionSuffix, error) {
	var result amd64HalfConversionSuffix
	if rawOp == baseOp {
		return result, nil
	}
	suffixes := strings.Split(strings.TrimPrefix(rawOp, baseOp+"."), ".")
	for index, suffix := range suffixes {
		switch suffix {
		case "SAE":
			if result.sae || index != 0 {
				return result, fmt.Errorf("amd64 %s has invalid or duplicate .SAE suffix", baseOp)
			}
			result.sae = true
		case "Z":
			if result.zeroing || index != len(suffixes)-1 {
				return result, fmt.Errorf("amd64 %s has invalid or duplicate .Z suffix", baseOp)
			}
			result.zeroing = true
		default:
			return result, fmt.Errorf("amd64 %s has unsupported suffix .%s", baseOp, suffix)
		}
	}
	return result, nil
}

// lowerPackedHalfConversion implements every Go 1.27 _yvcvtph2ps and
// _yvcvtps2ph row, including VEX signed immediates, EVEX masks, zeroing, SAE,
// exact-width memory accesses, and the distinct X/Y/Z narrowing widths.
func (c *amd64Ctx) lowerPackedHalfConversion(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	spec, supported := amd64HalfConversionSpecs[baseOp]
	if !supported {
		return false, false, nil
	}
	if spec.rawOnly {
		return c.lowerRawFP16Conversion(ins, spec)
	}
	properties, err := parseAMD64HalfConversionSuffix(rawOp, baseOp)
	if err != nil {
		return true, false, fmt.Errorf("%w: %q", err, ins.Raw)
	}
	if baseOp == "VCVTPH2PS" {
		return c.lowerPackedHalfToSingle(ins, properties)
	}
	return c.lowerPackedSingleToHalf(ins, properties)
}

func (c *amd64Ctx) lowerPackedHalfToSingle(ins Instr, properties amd64HalfConversionSuffix) (bool, bool, error) {
	if len(ins.Args) != 2 && len(ins.Args) != 3 {
		return true, false, fmt.Errorf("amd64 VCVTPH2PS expects source, [K mask,] destination: %q", ins.Raw)
	}
	masked := len(ins.Args) == 3
	if properties.zeroing && !masked {
		return true, false, fmt.Errorf("amd64 VCVTPH2PS .Z requires K1-K7: %q", ins.Raw)
	}
	if masked && !amd64NonzeroKOperand(ins.Args[1]) {
		return true, false, fmt.Errorf("amd64 VCVTPH2PS masked form expects K1-K7: %q", ins.Raw)
	}
	destination := ins.Args[len(ins.Args)-1]
	if destination.Kind != OpReg {
		return true, false, fmt.Errorf("amd64 VCVTPH2PS destination must be X, Y, or Z: %q", ins.Raw)
	}
	destinationBytes := amd64VectorByteWidth(destination.Reg)
	if destinationBytes != 16 && destinationBytes != 32 && destinationBytes != 64 || !c.isGoEVEXVectorRegister(destination, destinationBytes) {
		return true, false, fmt.Errorf("amd64 VCVTPH2PS destination is outside Go 1.27's vector-register class: %q", ins.Raw)
	}
	sourceRegisterBytes := 16
	if destinationBytes == 64 {
		sourceRegisterBytes = 32
	}
	source := ins.Args[0]
	if source.Kind == OpReg {
		if !c.isGoEVEXVectorRegister(source, sourceRegisterBytes) {
			return true, false, fmt.Errorf("amd64 VCVTPH2PS source width does not match its destination: %q", ins.Raw)
		}
	} else if !isAMD64MemoryOperand(source) {
		return true, false, fmt.Errorf("amd64 VCVTPH2PS source must be X/Y or memory: %q", ins.Raw)
	}
	if properties.sae && (destinationBytes != 64 || source.Kind != OpReg) {
		return true, false, fmt.Errorf("amd64 VCVTPH2PS .SAE requires a Y register source and Z destination: %q", ins.Raw)
	}

	lanes := destinationBytes / 4
	inputBits, err := c.loadPackedExtendInputs(source, sourceRegisterBytes, lanes, 16)
	if err != nil {
		return true, false, err
	}
	halves := c.newTmp()
	converted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i16> %s to <%d x half>\n", halves, lanes, inputBits, lanes)
	fmt.Fprintf(c.b, "  %%%s = fpext <%d x half> %%%s to <%d x float>\n", converted, lanes, halves, lanes)
	bits := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x float> %%%s to <%d x i32>\n", bits, lanes, converted, lanes)
	result := "%" + bits
	if masked {
		mask, err := c.loadK(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		oldBytes, err := c.loadPackedCompareBytes(destination, destinationBytes)
		if err != nil {
			return true, false, err
		}
		old := c.bitcastVectorBytesToIntegerLanes(destinationBytes, lanes, 32, oldBytes)
		result = amd64ApplyIntegerLaneMask(c, lanes, 32, result, old, mask, properties.zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i32> %s to <%d x i8>\n", out, lanes, result, destinationBytes)
	return true, false, c.storeVectorBytes(destination.Reg, destinationBytes, "%"+out)
}

func (c *amd64Ctx) lowerPackedSingleToHalf(ins Instr, properties amd64HalfConversionSuffix) (bool, bool, error) {
	if len(ins.Args) != 3 && len(ins.Args) != 4 {
		return true, false, fmt.Errorf("amd64 VCVTPS2PH expects imm8, source, [K mask,] destination: %q", ins.Raw)
	}
	if ins.Args[0].Kind != OpImm || ins.Args[0].Imm < -128 || ins.Args[0].Imm > 255 {
		return true, false, fmt.Errorf("amd64 VCVTPS2PH expects a signed-or-unsigned imm8: %q", ins.Raw)
	}
	masked := len(ins.Args) == 4
	if properties.zeroing && !masked {
		return true, false, fmt.Errorf("amd64 VCVTPS2PH .Z requires K1-K7: %q", ins.Raw)
	}
	if masked && !amd64NonzeroKOperand(ins.Args[2]) {
		return true, false, fmt.Errorf("amd64 VCVTPS2PH masked form expects K1-K7: %q", ins.Raw)
	}
	if masked && c.goarch == "386" {
		return true, false, fmt.Errorf("386 VCVTPS2PH does not expose Go 1.27's four-operand EVEX forms: %q", ins.Raw)
	}
	source := ins.Args[1]
	if source.Kind != OpReg {
		return true, false, fmt.Errorf("amd64 VCVTPS2PH source must be X, Y, or Z: %q", ins.Raw)
	}
	sourceBytes := amd64VectorByteWidth(source.Reg)
	if sourceBytes != 16 && sourceBytes != 32 && sourceBytes != 64 || !c.isGoEVEXVectorRegister(source, sourceBytes) {
		return true, false, fmt.Errorf("amd64 VCVTPS2PH source is outside Go 1.27's vector-register class: %q", ins.Raw)
	}
	destination := ins.Args[len(ins.Args)-1]
	destinationRegisterBytes := 16
	if sourceBytes == 64 {
		destinationRegisterBytes = 32
	}
	if destination.Kind == OpReg {
		if !c.isGoEVEXVectorRegister(destination, destinationRegisterBytes) {
			return true, false, fmt.Errorf("amd64 VCVTPS2PH destination width does not match its source: %q", ins.Raw)
		}
	} else if !isAMD64MemoryOperand(destination) {
		return true, false, fmt.Errorf("amd64 VCVTPS2PH destination must be X/Y or memory: %q", ins.Raw)
	}
	if properties.zeroing && destination.Kind != OpReg {
		return true, false, fmt.Errorf("amd64 VCVTPS2PH .Z requires a register destination: %q", ins.Raw)
	}
	requiresEVEX := masked || properties.sae || sourceBytes == 64 || amd64HalfConversionHighRegister(source)
	if destination.Kind == OpReg && amd64HalfConversionHighRegister(destination) {
		requiresEVEX = true
	}
	if ins.Args[0].Imm < 0 && requiresEVEX {
		return true, false, fmt.Errorf("amd64 VCVTPS2PH EVEX forms require an unsigned imm8: %q", ins.Raw)
	}
	if properties.sae && (sourceBytes != 64 || source.Kind != OpReg) {
		return true, false, fmt.Errorf("amd64 VCVTPS2PH .SAE requires a Z register source: %q", ins.Raw)
	}

	lanes := sourceBytes / 4
	sourceBits, err := c.loadPackedExtendInputs(source, sourceBytes, lanes, 32)
	if err != nil {
		return true, false, err
	}
	floats := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i32> %s to <%d x float>\n", floats, lanes, sourceBits, lanes)
	converted := c.newTmp()
	rounding := int(ins.Args[0].Imm) & 7
	fmt.Fprintf(c.b, "  %%%s = fptrunc <%d x float> %%%s to <%d x half>\n", converted, lanes, floats, lanes)
	bits := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x half> %%%s to <%d x i16>\n", bits, lanes, converted, lanes)
	result := "%" + bits
	if rounding > 0 && rounding < 4 {
		mode := [...]string{"RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE"}[rounding]
		result = c.adjustFP16NarrowRounding(lanes, "float", "%"+floats, "%"+converted, result, mode)
	}
	outputBytes := sourceBytes / 2
	if masked {
		mask, err := c.loadK(ins.Args[2].Reg)
		if err != nil {
			return true, false, err
		}
		old, err := c.loadPackedExtendInputs(destination, destinationRegisterBytes, lanes, 16)
		if err != nil {
			return true, false, err
		}
		result = amd64ApplyIntegerLaneMask(c, lanes, 16, result, old, mask, properties.zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i16> %s to <%d x i8>\n", out, lanes, result, outputBytes)
	return true, false, c.storePackedHalfResult(destination, destinationRegisterBytes, outputBytes, "%"+out)
}

func amd64HalfConversionHighRegister(operand Operand) bool {
	if operand.Kind != OpReg {
		return false
	}
	width := amd64VectorByteWidth(operand.Reg)
	index, ok := amd64VectorRegisterIndex(operand.Reg, width)
	return ok && index >= 16
}

func (c *amd64Ctx) storePackedHalfResult(destination Operand, registerBytes, outputBytes int, value string) error {
	if destination.Kind != OpReg {
		return c.storeVectorBytesOperand(destination, outputBytes, value)
	}
	if outputBytes == registerBytes {
		return c.storePackedMoveOperand(destination, registerBytes, value)
	}
	widened := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i8> %s, <%d x i8> zeroinitializer, <%d x i32> <", widened, outputBytes, value, outputBytes, registerBytes)
	for lane := 0; lane < registerBytes; lane++ {
		if lane > 0 {
			c.b.WriteString(", ")
		}
		fmt.Fprintf(c.b, "i32 %d", lane)
	}
	c.b.WriteString(">\n")
	return c.storePackedMoveOperand(destination, registerBytes, "%"+widened)
}
