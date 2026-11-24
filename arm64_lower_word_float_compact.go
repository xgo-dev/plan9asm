package plan9asm

import (
	"fmt"
	"math"
)

// --- arm64_lower_word_bfloat_matrix.go ---
// arm64RawBFloatMatrix is the 128-bit Advanced SIMD BFMMLA encoding. LLVM's
// architecture intrinsic retains BF16 matrix ordering and rounding semantics.
type arm64RawBFloatMatrix struct {
	destination int
	left        int
	right       int
}

func decodeARM64RawBFloatMatrix(word uint32) (arm64RawBFloatMatrix, bool) {
	const registers = uint32(31<<16 | 31<<5 | 31)
	if word&^registers != 0x6e40ec00 {
		return arm64RawBFloatMatrix{}, false
	}
	return arm64RawBFloatMatrix{
		destination: int(word) & 31,
		left:        int(word>>5) & 31,
		right:       int(word>>16) & 31,
	}, true
}

func (c *arm64Ctx) lowerRawBFloatMatrix(form arm64RawBFloatMatrix) error {
	accumulatorReg := Reg(fmt.Sprintf("V%d", form.destination))
	accumulatorArrangement := arm64VectorArrangement{elementBits: 32, lanes: 4}
	inputArrangement := arm64VectorArrangement{elementBits: 16, lanes: 8}

	accumulator, err := c.loadARM64VectorFloat(accumulatorReg, accumulatorArrangement)
	if err != nil {
		return err
	}
	loadBFloat := func(register int) (string, error) {
		integer, err := c.loadARM64VectorInteger(
			Reg(fmt.Sprintf("V%d", register)), inputArrangement)
		if err != nil {
			return "", err
		}
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <8 x i16> %s to <8 x bfloat>\n", value, integer)
		return "%" + value, nil
	}
	left, err := loadBFloat(form.left)
	if err != nil {
		return err
	}
	right, err := loadBFloat(form.right)
	if err != nil {
		return err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b,
		"  %%%s = call <4 x float> @llvm.aarch64.neon.bfmmla(<4 x float> %s, <8 x bfloat> %s, <8 x bfloat> %s)\n",
		result, accumulator, left, right)
	return c.storeARM64VectorFloat(accumulatorReg, accumulatorArrangement, "%"+result)
}

// --- arm64_lower_word_float_abs_neg.go ---
type arm64RawFloatAbsNeg struct {
	negate      bool
	arrangement arm64VectorArrangement
	source      int
	destination int
}

// decodeARM64RawFloatAbsNeg recognizes the FP16 Advanced SIMD forms that Go's
// named VFABS/VFNEG optab cannot express. S2/S4/D2 WORD encodings are decoded
// by x/arch and flow through the complete named-form lowerer.
func decodeARM64RawFloatAbsNeg(word uint32) (arm64RawFloatAbsNeg, bool) {
	const registers = uint32(31 | 31<<5)
	key := word &^ registers
	negate := false
	switch key {
	case 0x0ef8f800, 0x4ef8f800:
	case 0x2ef8f800, 0x6ef8f800:
		negate = true
	default:
		return arm64RawFloatAbsNeg{}, false
	}
	lanes := 4
	if word&(1<<30) != 0 {
		lanes = 8
	}
	return arm64RawFloatAbsNeg{
		negate:      negate,
		arrangement: arm64VectorArrangement{elementBits: 16, lanes: lanes},
		source:      int(word>>5) & 31,
		destination: int(word) & 31,
	}, true
}

func (c *arm64Ctx) lowerRawFloatAbsNeg(form arm64RawFloatAbsNeg) error {
	source, err := c.loadARM64VectorFloat(Reg(fmt.Sprintf("V%d", form.source)), form.arrangement)
	if err != nil {
		return err
	}
	result := c.newTmp()
	vectorType := fmt.Sprintf("<%d x half>", form.arrangement.lanes)
	if form.negate {
		fmt.Fprintf(c.b, "  %%%s = fneg %s %s\n", result, vectorType, source)
	} else {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.fabs.v%df16(%s %s)\n", result, vectorType, form.arrangement.lanes, vectorType, source)
	}
	return c.storeARM64VectorFloat(Reg(fmt.Sprintf("V%d", form.destination)), form.arrangement, "%"+result)
}

// --- arm64_lower_word_float_conditional_compare.go ---
func decodeARM64RawConditionalCompare(word uint32) (arm64ConditionalCompareForm, bool) {
	const variable = uint32(31<<5 | 31<<16 | 3<<22 | 15<<12 | 1<<4 | 15)
	if word & ^variable != 0x1e200400 {
		return arm64ConditionalCompareForm{}, false
	}
	bits := 0
	switch word >> 22 & 3 {
	case 0:
		bits = 32
	case 1:
		bits = 64
	case 3:
		bits = 16
	default:
		return arm64ConditionalCompareForm{}, false
	}
	conditions := [...]string{"EQ", "NE", "CS", "CC", "MI", "PL", "VS", "VC", "HI", "LS", "GE", "LT", "GT", "LE", "AL", "NV"}
	return arm64ConditionalCompareForm{
		arm64ScalarCompareForm: arm64ScalarCompareForm{
			bits: bits, signaling: word&(1<<4) != 0,
			left:  Reg(fmt.Sprintf("F%d", word>>5&31)),
			right: Reg(fmt.Sprintf("F%d", word>>16&31)),
		},
		condition: conditions[word>>12&15],
		nzcv:      uint8(word & 15),
	}, true
}

// --- arm64_lower_word_float_immediate.go ---
type arm64RawFloatImmediate struct {
	arrangement arm64VectorArrangement
	laneValue   uint64
	destination int
}

var arm64RawFloatImmediateArrangements = map[uint32]arm64VectorArrangement{
	0x0f00fc00: {elementBits: 16, lanes: 4},
	0x4f00fc00: {elementBits: 16, lanes: 8},
	0x0f00f400: {elementBits: 32, lanes: 2},
	0x4f00f400: {elementBits: 32, lanes: 4},
	0x6f00f400: {elementBits: 64, lanes: 2},
}

func decodeARM64RawFloatImmediate(word uint32) (arm64RawFloatImmediate, bool) {
	const variable = uint32(7<<16 | 31<<5 | 31)
	arrangement, ok := arm64RawFloatImmediateArrangements[word&^variable]
	if !ok {
		return arm64RawFloatImmediate{}, false
	}
	immediate := byte(((word >> 16) & 7 << 5) | ((word >> 5) & 31))
	value := arm64ExpandedFloatImmediate(immediate)
	laneValue := math.Float64bits(value)
	switch arrangement.elementBits {
	case 16:
		laneValue = uint64(arm64Float16Bits(value))
	case 32:
		laneValue = uint64(math.Float32bits(float32(value)))
	}
	return arm64RawFloatImmediate{
		arrangement: arrangement,
		laneValue:   laneValue,
		destination: int(word) & 31,
	}, true
}

func arm64ExpandedFloatImmediate(immediate byte) float64 {
	sign := 1.0
	if immediate&0x80 != 0 {
		sign = -1
	}
	exponent := (1-int(immediate>>6&1))*4 + int(immediate>>4&3) - 3
	significand := float64(16+int(immediate&15)) / 16
	return sign * math.Ldexp(significand, exponent)
}

func (c *arm64Ctx) lowerRawFloatImmediate(form arm64RawFloatImmediate) error {
	return c.lowerARM64VectorFloatImmediateBits(
		form.arrangement,
		form.laneValue,
		Reg(fmt.Sprintf("V%d", form.destination)),
	)
}

// --- arm64_lower_word_float_minmax_across.go ---
type arm64RawFloatMinMaxAcross struct {
	operation   string
	arrangement arm64VectorArrangement
	source      int
	destination int
}

var arm64RawFloatMinMaxAcrossSpecs = map[uint32]struct {
	operation   string
	arrangement arm64VectorArrangement
}{
	0x0e30c800: {"maxnum", arm64VectorArrangement{16, 4}},
	0x4e30c800: {"maxnum", arm64VectorArrangement{16, 8}},
	0x6e30c800: {"maxnum", arm64VectorArrangement{32, 4}},
	0x0eb0c800: {"minnum", arm64VectorArrangement{16, 4}},
	0x4eb0c800: {"minnum", arm64VectorArrangement{16, 8}},
	0x6eb0c800: {"minnum", arm64VectorArrangement{32, 4}},
	0x0e30f800: {"maximum", arm64VectorArrangement{16, 4}},
	0x4e30f800: {"maximum", arm64VectorArrangement{16, 8}},
	0x6e30f800: {"maximum", arm64VectorArrangement{32, 4}},
	0x0eb0f800: {"minimum", arm64VectorArrangement{16, 4}},
	0x4eb0f800: {"minimum", arm64VectorArrangement{16, 8}},
	0x6eb0f800: {"minimum", arm64VectorArrangement{32, 4}},
}

func decodeARM64RawFloatMinMaxAcross(word uint32) (arm64RawFloatMinMaxAcross, bool) {
	const registers = uint32(31 | 31<<5)
	spec, ok := arm64RawFloatMinMaxAcrossSpecs[word&^registers]
	if !ok {
		return arm64RawFloatMinMaxAcross{}, false
	}
	return arm64RawFloatMinMaxAcross{
		operation:   spec.operation,
		arrangement: spec.arrangement,
		source:      int(word>>5) & 31,
		destination: int(word) & 31,
	}, true
}

func (c *arm64Ctx) lowerRawFloatMinMaxAcross(form arm64RawFloatMinMaxAcross) error {
	return c.lowerARM64FloatMinMaxAcrossValues(
		form.operation,
		form.arrangement,
		Reg(fmt.Sprintf("V%d", form.source)),
		Reg(fmt.Sprintf("F%d", form.destination)),
	)
}

// --- arm64_lower_word_float_round.go ---
type arm64RawVectorFloatRound struct {
	operation   string
	arrangement arm64VectorArrangement
	source      int
	destination int
}

func decodeARM64RawVectorFloatRound(word uint32) (arm64RawVectorFloatRound, bool) {
	operation := ""
	switch word & 0xbfbffc00 {
	case 0x2e218800:
		operation = "round"
	case 0x2e219800:
		operation = "rint"
	case 0x2ea19800:
		operation = "nearbyint"
	default:
		return arm64RawVectorFloatRound{}, false
	}
	elementBits := 32
	if word&(1<<22) != 0 {
		elementBits = 64
	}
	vectorBits := 64
	if word&(1<<30) != 0 {
		vectorBits = 128
	}
	if elementBits == 64 && vectorBits == 64 {
		return arm64RawVectorFloatRound{}, false
	}
	return arm64RawVectorFloatRound{
		operation:   operation,
		arrangement: arm64VectorArrangement{elementBits: elementBits, lanes: vectorBits / elementBits},
		source:      int(word>>5) & 31,
		destination: int(word) & 31,
	}, true
}

func (c *arm64Ctx) lowerRawVectorFloatRound(form arm64RawVectorFloatRound) error {
	arrangementName := arm64VectorArrangementName(form.arrangement)
	sourceReg := Reg(fmt.Sprintf("V%d.%s", form.source, arrangementName))
	destinationReg := Reg(fmt.Sprintf("V%d.%s", form.destination, arrangementName))
	source, err := c.loadARM64VectorFloat(sourceReg, form.arrangement)
	if err != nil {
		return err
	}
	floatType := "float"
	suffix := fmt.Sprintf("v%df32", form.arrangement.lanes)
	if form.arrangement.elementBits == 64 {
		floatType = "double"
		suffix = fmt.Sprintf("v%df64", form.arrangement.lanes)
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call <%d x %s> @llvm.%s.%s(<%d x %s> %s)\n",
		result, form.arrangement.lanes, floatType, form.operation, suffix,
		form.arrangement.lanes, floatType, source)
	return c.storeARM64VectorFloat(destinationReg, form.arrangement, "%"+result)
}

// --- arm64_lower_word_half_fma.go ---
// The named Go FMA forms cover S and D operands. Go source can also contain
// raw half-precision encodings; each has four independent five-bit registers.
type arm64RawHalfFMA struct {
	op          string
	destination int
	first       int
	addend      int
	second      int
}

var arm64RawHalfFMABases = map[uint32]string{
	0x1fc00000: "FMADD",
	0x1fc08000: "FMSUB",
	0x1fe00000: "FNMADD",
	0x1fe08000: "FNMSUB",
}

func decodeARM64RawHalfFMA(word uint32) (arm64RawHalfFMA, bool) {
	const registers = uint32(31 | 31<<5 | 31<<10 | 31<<16)
	op, ok := arm64RawHalfFMABases[word&^registers]
	if !ok {
		return arm64RawHalfFMA{}, false
	}
	return arm64RawHalfFMA{
		op:          op,
		destination: int(word) & 31,
		first:       int(word>>5) & 31,
		addend:      int(word>>10) & 31,
		second:      int(word>>16) & 31,
	}, true
}

func (c *arm64Ctx) lowerRawHalfFMA(form arm64RawHalfFMA) error {
	load := func(register int) (string, error) {
		return c.loadARM64ScalarFloatReg(Reg(fmt.Sprintf("F%d", register)), 16)
	}
	first, err := load(form.first)
	if err != nil {
		return err
	}
	second, err := load(form.second)
	if err != nil {
		return err
	}
	addend, err := load(form.addend)
	if err != nil {
		return err
	}

	if form.op == "FMSUB" {
		negated := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fneg half %s\n", negated, first)
		first = "%" + negated
	} else if form.op == "FNMSUB" {
		negated := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fneg half %s\n", negated, addend)
		addend = "%" + negated
	}

	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call half @llvm.fma.f16(half %s, half %s, half %s)\n",
		result, first, second, addend)
	value := "%" + result
	if form.op == "FNMADD" {
		negated := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fneg half %s\n", negated, value)
		value = "%" + negated
	}
	return c.storeARM64ScalarFloatReg(Reg(fmt.Sprintf("F%d", form.destination)), 16, value)
}

// --- arm64_lower_word_scalar_float_compare.go ---
type arm64RawScalarFloatCompare struct {
	bits      int
	signaling bool
	zero      bool
	first     int
	second    int
}

func decodeARM64RawScalarFloatCompare(word uint32) (arm64RawScalarFloatCompare, bool) {
	const (
		firstRegister  = uint32(31 << 5)
		secondRegister = uint32(31 << 16)
		floatType      = uint32(3 << 22)
		signalingBit   = uint32(1 << 4)
		zeroBit        = uint32(1 << 3)
		variableFields = firstRegister | secondRegister | floatType | signalingBit | zeroBit
		compareBase    = uint32(0x1e202000)
	)
	if word&^variableFields != compareBase {
		return arm64RawScalarFloatCompare{}, false
	}

	bits := 0
	switch word >> 22 & 3 {
	case 0:
		bits = 32
	case 1:
		bits = 64
	case 3:
		bits = 16
	default:
		return arm64RawScalarFloatCompare{}, false
	}
	second := int(word>>16) & 31
	zero := word&zeroBit != 0
	if zero {
		// FCMP/FCMPE compare against +0.0 and ignore the encoded Rm field.
		second = 0
	}
	return arm64RawScalarFloatCompare{
		bits:      bits,
		signaling: word&signalingBit != 0,
		zero:      zero,
		first:     int(word>>5) & 31,
		second:    second,
	}, true
}

func (c *arm64Ctx) lowerRawScalarFloatCompare(form arm64RawScalarFloatCompare) error {
	_, _, ok := arm64ScalarFloatType(form.bits)
	if !ok {
		return fmt.Errorf("arm64 unsupported scalar float width %d", form.bits)
	}
	left, err := c.loadARM64ScalarFloatReg(Reg(fmt.Sprintf("F%d", form.first)), form.bits)
	if err != nil {
		return err
	}
	right := ""
	if !form.zero {
		right, err = c.loadARM64ScalarFloatReg(Reg(fmt.Sprintf("F%d", form.second)), form.bits)
		if err != nil {
			return err
		}
	}
	c.emitARM64ScalarFloatCompare(form.bits, form.signaling, left, right)
	return nil
}

// --- arm64_lower_word_scalar_float_immediate.go ---
type arm64RawScalarFloatImmediate struct {
	bits        int
	value       float64
	destination int
}

func decodeARM64RawScalarFloatImmediate(word uint32) (arm64RawScalarFloatImmediate, bool) {
	const (
		floatType      = uint32(3 << 22)
		immediateField = uint32(255 << 13)
		destination    = uint32(31)
		variableFields = floatType | immediateField | destination
		immediateBase  = uint32(0x1e201000)
	)
	if word&^variableFields != immediateBase {
		return arm64RawScalarFloatImmediate{}, false
	}

	bits := 0
	switch word >> 22 & 3 {
	case 0:
		bits = 32
	case 1:
		bits = 64
	case 3:
		bits = 16
	default:
		return arm64RawScalarFloatImmediate{}, false
	}
	immediate := byte(word >> 13)
	return arm64RawScalarFloatImmediate{
		bits:        bits,
		value:       arm64ExpandedFloatImmediate(immediate),
		destination: int(word) & 31,
	}, true
}

func (c *arm64Ctx) lowerRawScalarFloatImmediate(form arm64RawScalarFloatImmediate) error {
	destination := Reg(fmt.Sprintf("F%d", form.destination))
	return c.storeARM64ScalarFloatReg(
		destination,
		form.bits,
		formatLLVMFloat64Literal(form.value),
	)
}

// --- arm64_lower_word_scalar_float_select.go ---
type arm64RawScalarFloatSelect struct {
	bits        int
	condition   int
	first       int
	second      int
	destination int
}

var arm64RawScalarFloatSelectWidths = map[uint32]int{
	0x1ee00c00: 16,
	0x1e200c00: 32,
	0x1e600c00: 64,
}

var arm64RawConditionNames = [...]string{
	"EQ", "NE", "HS", "LO",
	"MI", "PL", "VS", "VC",
	"HI", "LS", "GE", "LT",
	"GT", "LE", "AL", "NV",
}

func decodeARM64RawScalarFloatSelect(word uint32) (arm64RawScalarFloatSelect, bool) {
	const operands = uint32(31 | 31<<5 | 15<<12 | 31<<16)
	bits, ok := arm64RawScalarFloatSelectWidths[word&^operands]
	if !ok {
		return arm64RawScalarFloatSelect{}, false
	}
	return arm64RawScalarFloatSelect{
		bits:        bits,
		condition:   int(word>>12) & 15,
		first:       int(word>>5) & 31,
		second:      int(word>>16) & 31,
		destination: int(word) & 31,
	}, true
}

func (c *arm64Ctx) lowerRawScalarFloatSelect(form arm64RawScalarFloatSelect) error {
	return c.lowerARM64FloatSelectValues(
		form.bits,
		arm64RawConditionNames[form.condition],
		Reg(fmt.Sprintf("F%d", form.first)),
		Reg(fmt.Sprintf("F%d", form.second)),
		Reg(fmt.Sprintf("F%d", form.destination)),
	)
}

func (c *arm64Ctx) lowerARM64FloatSelectValues(bits int, condition string, firstReg, secondReg, destination Reg) error {
	first, err := c.loadARM64ScalarFloatReg(firstReg, bits)
	if err != nil {
		return err
	}
	second, err := c.loadARM64ScalarFloatReg(secondReg, bits)
	if err != nil {
		return err
	}
	predicate, err := c.condValue(condition)
	if err != nil {
		return err
	}
	typeName := "half"
	if bits == 32 {
		typeName = "float"
	} else if bits == 64 {
		typeName = "double"
	}
	selected := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, %s %s, %s %s\n", selected, predicate, typeName, first, typeName, second)
	return c.storeARM64ScalarFloatReg(destination, bits, "%"+selected)
}

// --- arm64_lower_word_scalar_half_unary.go ---
type arm64RawScalarHalfUnary struct {
	operation   string
	source      int
	destination int
}

// Go 1.27 has named FABS/FNEG/FSQRT/FRINT scalar forms for S and D, but
// no H optab forms. The full FP16 scalar unary encoding family therefore
// reaches us as WORD directives.
func decodeARM64RawScalarHalfUnary(word uint32) (arm64RawScalarHalfUnary, bool) {
	const registers = uint32(31 | 31<<5)
	operations := map[uint32]string{
		0x1ee0c000: "fabs",
		0x1ee14000: "neg",
		0x1ee1c000: "sqrt",
		0x1ee64000: "round",
		0x1ee7c000: "nearbyint",
		0x1ee54000: "floor",
		0x1ee44000: "roundeven",
		0x1ee4c000: "ceil",
		0x1ee74000: "rint",
		0x1ee5c000: "trunc",
	}
	operation, ok := operations[word&^registers]
	if !ok {
		return arm64RawScalarHalfUnary{}, false
	}
	return arm64RawScalarHalfUnary{
		operation:   operation,
		source:      int(word>>5) & 31,
		destination: int(word) & 31,
	}, true
}

func (c *arm64Ctx) lowerRawScalarHalfUnary(form arm64RawScalarHalfUnary) error {
	sourceReg := Reg(fmt.Sprintf("F%d", form.source))
	destinationReg := Reg(fmt.Sprintf("F%d", form.destination))
	source, err := c.loadARM64ScalarFloatReg(sourceReg, 16)
	if err != nil {
		return err
	}
	result := c.newTmp()
	if form.operation == "neg" {
		fmt.Fprintf(c.b, "  %%%s = fneg half %s\n", result, source)
	} else {
		fmt.Fprintf(c.b, "  %%%s = call half @llvm.%s.f16(half %s)\n", result, form.operation, source)
	}
	return c.storeARM64ScalarFloatReg(destinationReg, 16, "%"+result)
}
