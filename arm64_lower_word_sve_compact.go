package plan9asm

import (
	"fmt"
	"math"
)

// --- arm64_lower_word_sve_dupm.go ---
// ZDUPM shares the thirteen-bit logical-immediate grammar with SVE bitwise
// instructions. The element width is encoded by the immediate itself.
func decodeARM64RawSVEDupM(word uint32) (Instr, bool) {
	if word&0xfffc0000 != 0x05c00000 {
		return Instr{}, false
	}
	elementBits, immediate, ok := decodeARM64SVELogicalImmediate(int(word>>5) & 0x1fff)
	if !ok {
		return Instr{}, false
	}
	width := map[int]string{8: "B", 16: "H", 32: "S", 64: "D"}[elementBits]
	destination := word & 31
	return Instr{
		Op: "ZDUPM",
		Args: []Operand{
			{Kind: OpImm, Imm: int64(immediate)},
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%s", destination, width))},
		},
		Raw: fmt.Sprintf("WORD $%#08x", word),
	}, true
}

// --- arm64_lower_word_sve_extra_shift.go ---
// Derive the raw lookup tables from the same family specs used by named
// validation and lowering. Immediate and reverse-vector operands share the
// predicated mask, but use different interpretations of bits 9:5.
var arm64SVEExtraShiftPredicated, arm64SVEExtraShiftUnpredicated = arm64SVEExtraShiftRawTables()

func arm64SVEExtraShiftRawTables() (map[uint32]Op, map[uint32]Op) {
	predicated, unpredicated := make(map[uint32]Op), make(map[uint32]Op)
	for op, spec := range arm64SVEImmediateShiftSpecs {
		if spec.predicated {
			predicated[spec.rawBase] = op
		} else {
			unpredicated[spec.rawBase] = op
		}
	}
	for op, spec := range arm64SVEReverseShiftIntrinsics {
		predicated[spec.rawBase] = op
	}
	return predicated, unpredicated
}

func decodeARM64RawSVEExtraShift(word uint32) (Instr, bool) {
	op, predicated := arm64SVEExtraShiftPredicated[word&0xff3fe000]
	lowBit := 5
	if !predicated {
		var ok bool
		op, ok = arm64SVEExtraShiftUnpredicated[word&0xff20fc00]
		if !ok {
			return Instr{}, false
		}
		lowBit = 16
	}
	_, reverse := arm64SVEReverseShiftIntrinsics[op]
	elementBits, shift, valid := decodeARM64SVEShiftImmediate(word, lowBit)
	if reverse {
		elementBits = 8 << (word >> 22 & 3)
	} else if !valid {
		return Instr{}, false
	} else if arm64SVEImmediateShiftSpecs[op].minimum == 0 {
		shift = elementBits - shift
	}
	width := map[int]byte{8: 'B', 16: 'H', 32: 'S', 64: 'D'}[elementBits]
	reg := func(number uint32) Operand {
		return Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", number, width))}
	}
	destination := reg(word & 31)
	first := Operand{Kind: OpImm, Imm: int64(shift)}
	if reverse {
		first = reg(word >> 5 & 31)
	}
	args := []Operand{first}
	if predicated {
		args = append(args, destination, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d.M", word>>10&7))})
	} else {
		args = append(args, reg(word>>5&31))
	}
	args = append(args, destination)
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("WORD $%#08x", word)}, true
}

func (c *arm64Ctx) lowerARM64RawSVEExtraShift(ins Instr) error {
	spec, immediate := arm64SVEImmediateShiftSpecs[ins.Op]
	if !immediate {
		_, _, err := c.lowerARM64SVEExtraShift(ins.Op, ins)
		return err
	}
	source, bits, _ := arm64ParseSVEZElementReg(ins.Args[1])
	destination, _, _ := arm64ParseSVEZElementReg(ins.Args[len(ins.Args)-1])
	predicate := 0
	if spec.predicated {
		predicate, _ = arm64ParseSVEPredicateMerge(ins.Args[2])
	}
	// Arm WORD encodings allow right shifts by the full element width;
	// Go's named immediate grammar intentionally retains its tighter bound.
	return c.lowerARM64SVEExtraImmediateShiftForm(spec, bits, source, destination, predicate, ins.Args[0].Imm)
}

// --- arm64_lower_word_sve_float_arithmetic.go ---
type arm64SVEFloatArithmeticSpec struct {
	kind       arm64RawSVEFloatKind
	vector     uint32
	predicated uint32
	immediate  uint32
	constants  [2]float64
	indexed    [3]uint32
}

// All named arithmetic forms and raw encodings use the same immediate
// choices. Raw normalization feeds the existing typed semantic forms.
var arm64SVEFloatArithmeticSpecs = map[Op]arm64SVEFloatArithmeticSpec{
	"ZFADD": {kind: arm64RawSVEFloatAdd, vector: 0x65000000, predicated: 0x65008000,
		immediate: 0x65188000, constants: [2]float64{0.5, 1}},
	"ZFSUB": {kind: arm64RawSVEFloatSub, vector: 0x65000400, predicated: 0x65018000,
		immediate: 0x65198000, constants: [2]float64{0.5, 1}},
	"ZFSUBR": {kind: arm64RawSVEFloatSubReverse, predicated: 0x65038000,
		immediate: 0x651b8000, constants: [2]float64{0.5, 1}},
	"ZFMUL": {kind: arm64RawSVEFloatMul, vector: 0x65000800, predicated: 0x65028000,
		immediate: 0x651a8000, constants: [2]float64{0.5, 2}, indexed: [3]uint32{0x64202000, 0x64a02000, 0x64e02000}},
}

type arm64SVEFloatArithmeticRawTables struct {
	vector, predicated, immediate map[uint32]arm64SVEFloatArithmeticSpec
	indexed                       map[uint32]int
}

var arm64SVEFloatArithmeticRaw = func() arm64SVEFloatArithmeticRawTables {
	tables := arm64SVEFloatArithmeticRawTables{
		vector: make(map[uint32]arm64SVEFloatArithmeticSpec), predicated: make(map[uint32]arm64SVEFloatArithmeticSpec),
		immediate: make(map[uint32]arm64SVEFloatArithmeticSpec), indexed: make(map[uint32]int),
	}
	for _, spec := range arm64SVEFloatArithmeticSpecs {
		if spec.vector != 0 {
			tables.vector[spec.vector] = spec
		}
		tables.predicated[spec.predicated], tables.immediate[spec.immediate] = spec, spec
		for size, base := range spec.indexed {
			if base != 0 {
				tables.indexed[base] = size + 1
			}
		}
	}
	return tables
}()

func decodeARM64RawSVEFloatArithmetic(word uint32) (arm64RawSVEFloat, bool) {
	form := arm64RawSVEFloat{elementBits: 8 << (word >> 22 & 3), destination: int(word & 31)}
	if spec, ok := arm64SVEFloatArithmeticRaw.vector[word&0xff20fc00]; ok {
		form.kind = spec.kind
		form.first, form.second = int(word>>5&31), int(word>>16&31)
	} else if spec, ok := arm64SVEFloatArithmeticRaw.predicated[word&0xff3fe000]; ok {
		form.kind, form.predicated = spec.kind, true
		form.first, form.predicate = int(word>>5&31), int(word>>10&7)
	} else if spec, ok := arm64SVEFloatArithmeticRaw.immediate[word&0xff3fe3c0]; ok {
		form.kind, form.predicated, form.hasImmediate = spec.kind, true, true
		form.first, form.predicate = form.destination, int(word>>10&7)
		form.immediate = spec.constants[word>>5&1]
	} else {
		size, ok := arm64SVEFloatArithmeticRaw.indexed[word&0xffe0fc00]
		if !ok {
			size, ok = arm64SVEFloatArithmeticRaw.indexed[word&0xffa0fc00]
			if !ok || size != 1 {
				return arm64RawSVEFloat{}, false
			}
		}
		form.kind, form.hasLane, form.elementBits = arm64RawSVEFloatMul, true, 8<<size
		form.first, form.second, form.lane = int(word>>5&31), int(word>>16&7), int(word>>19&3)
		if size == 1 {
			form.lane |= int(word >> 20 & 4)
		} else if size == 3 {
			form.second, form.lane = int(word>>16&15), int(word>>20&1)
		}
	}
	return form, form.elementBits >= 16
}

// --- arm64_lower_word_sve_float_immediate.go ---
// Go 1.27's ZFDUP/ZFCPY rows share an 8-bit floating immediate and H/S/D
// elements. ZFCPY adds P0..P15/M. LLVM's FMOV spellings are aliases.
func decodeARM64RawSVEFloatImmediate(word uint32) (Instr, bool) {
	op := Op("ZFDUP")
	switch {
	case word&0xff3fe000 == 0x2539c000:
	case word&0xff30e000 == 0x0510c000:
		op = "ZFCPY"
	default:
		return Instr{}, false
	}
	width := map[uint32]string{1: "H", 2: "S", 3: "D"}[word>>22&3]
	if width == "" {
		return Instr{}, false
	}
	immediate := byte(word >> 5)
	value := arm64ExpandedFloatImmediate(immediate)
	destination := int(word) & 31
	args := []Operand{{Kind: OpImm, Imm: int64(math.Float64bits(value)), ImmIsFloat: true}}
	if op == "ZFCPY" {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d.M", word>>16&15))})
	}
	args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%s", destination, width))})
	return Instr{
		Op: op, Args: args, Raw: fmt.Sprintf("WORD $%#08x", word),
	}, true
}

// --- arm64_lower_word_sve_float_minmax_reduce.go ---
type arm64RawSVEFloatMinMaxReduction struct {
	spec        arm64SVEFloatMinMaxSpec
	form        arm64SVEFloatMinMaxForm
	destination Reg
}

// SVE's four predicated floating min/max reductions share one encoding
// grammar. The opcode nibble chooses max/min and NaN behavior; size chooses
// H/S/D; the remaining variable fields are Zd, Zn, and Pg.
func decodeARM64RawSVEFloatMinMaxReduction(word uint32) (arm64RawSVEFloatMinMaxReduction, bool) {
	if word&0xff30e000 != 0x65002000 {
		return arm64RawSVEFloatMinMaxReduction{}, false
	}

	size := int(word>>22) & 3
	opcode := int(word>>16) & 15
	if size == 0 || opcode < 4 || opcode > 7 {
		return arm64RawSVEFloatMinMaxReduction{}, false
	}

	operations := [...]string{"ZFMAXNMV", "ZFMINNMV", "ZFMAXV", "ZFMINV"}
	suffixes := [...]string{"", "H", "S", "D"}
	op := Op(operations[opcode-4] + suffixes[size])
	spec, ok := arm64SVEFloatMinMaxSpecs[op]
	if !ok {
		return arm64RawSVEFloatMinMaxReduction{}, false
	}

	destination := int(word) & 31
	return arm64RawSVEFloatMinMaxReduction{
		spec: spec,
		form: arm64SVEFloatMinMaxForm{
			elementBits: 8 << size,
			first:       int(word>>5) & 31,
			predicate:   int(word>>10) & 7,
			destination: destination,
		},
		destination: Reg(fmt.Sprintf("V%d", destination)),
	}, true
}

// --- arm64_lower_word_sve_float_multiply_accumulate.go ---
// Go 1.27 exposes all eight predicated fused floating-point multiply forms
// with the same register fields. The first two source operands have a different
// field order for the accumulating (MLA/MLS) and destructive (MAD/MSB) forms.
var arm64RawSVEFloatMultiplyAccumulateBases = map[uint32]Op{
	0x65208000: "ZFMAD",
	0x65200000: "ZFMLA",
	0x65202000: "ZFMLS",
	0x6520a000: "ZFMSB",
	0x6520c000: "ZFNMAD",
	0x65204000: "ZFNMLA",
	0x65206000: "ZFNMLS",
	0x6520e000: "ZFNMSB",
}

func decodeARM64RawSVEFloatMultiplyAccumulate(word uint32) (Instr, bool) {
	const variableFields = uint32(0x00df1fff)
	op, ok := arm64RawSVEFloatMultiplyAccumulateBases[word&^variableFields]
	if !ok {
		return Instr{}, false
	}
	width := map[uint32]string{1: "H", 2: "S", 3: "D"}[word>>22&3]
	if width == "" {
		return Instr{}, false
	}
	first := word >> 16 & 31
	second := word >> 5 & 31
	switch op {
	case "ZFMAD", "ZFMSB", "ZFNMAD", "ZFNMSB":
		first, second = second, first
	}
	predicate := word >> 10 & 7
	destination := word & 31
	return Instr{
		Op: op,
		Args: []Operand{
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%s", first, width))},
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%s", second, width))},
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d.M", predicate))},
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%s", destination, width))},
		},
		Raw: fmt.Sprintf("WORD $%#08x", word),
	}, true
}

// --- arm64_lower_word_sve_float_reciprocal_step.go ---
// Go 1.27's ZFRECPS and ZFRSQRTS rows each have one H/S/D three-vector
// format. Normalize raw WORD encodings to the same typed lowering as the
// corresponding named instruction.
var arm64RawSVEFloatReciprocalStep = map[uint32]Op{
	0x65001800: "ZFRECPS",
	0x65001c00: "ZFRSQRTS",
}

func decodeARM64RawSVEFloatReciprocalStep(word uint32) (Instr, bool) {
	op, ok := arm64RawSVEFloatReciprocalStep[word&0xff20fc00]
	if !ok {
		return Instr{}, false
	}
	size := word >> 22 & 3
	if size == 0 {
		return Instr{}, false
	}
	width := " HSD"[size]
	args := []Operand{
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", word>>16&31, width))},
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", word>>5&31, width))},
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", word&31, width))},
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("WORD $%#08x", word)}, true
}

// --- arm64_lower_word_sve_integer_add_reduce.go ---
type arm64RawSVEIntegerAddReduction struct {
	spec        arm64SVEAddReductionSpec
	form        arm64SVEAddReductionForm
	destination Reg
}

// SADDV and UADDV share the predicated integer-add reduction encoding.
// Signed D is reserved; unsigned D is valid. The remaining variable fields
// are the scalar destination, predicate, and scalable source registers.
func decodeARM64RawSVEIntegerAddReduction(word uint32) (arm64RawSVEIntegerAddReduction, bool) {
	if word&0xff3ee000 != 0x04002000 {
		return arm64RawSVEIntegerAddReduction{}, false
	}

	size := int(word>>22) & 3
	unsigned := word&(1<<16) != 0
	if size == 3 && !unsigned {
		return arm64RawSVEIntegerAddReduction{}, false
	}

	kind := arm64SVESignedAddReduce
	if unsigned {
		kind = arm64SVEUnsignedAddReduce
	}
	destination := int(word) & 31
	return arm64RawSVEIntegerAddReduction{
		spec: arm64SVEAddReductionSpec{kind: kind},
		form: arm64SVEAddReductionForm{
			elementBits: 8 << size,
			source:      int(word>>5) & 31,
			predicate:   int(word>>10) & 7,
			destination: destination,
		},
		destination: Reg(fmt.Sprintf("V%d", destination)),
	}, true
}

// --- arm64_lower_word_sve_integer_dot.go ---
type arm64RawSVEIntegerDotRow struct {
	op      Op
	width   int
	indexed bool
}

var arm64RawSVEIntegerDotRows, arm64RawSVEIntegerDotBytePairRows = arm64SVEIntegerDotRawTables()

func arm64SVEIntegerDotRawTables() (ordinary, bytePairs map[uint32]arm64RawSVEIntegerDotRow) {
	ordinary = make(map[uint32]arm64RawSVEIntegerDotRow)
	bytePairs = make(map[uint32]arm64RawSVEIntegerDotRow)
	for op, spec := range arm64SVEIntegerDotSpecs {
		for width, bases := range spec.rawBases {
			for indexed, base := range bases {
				if base == 0 {
					continue
				}
				row := arm64RawSVEIntegerDotRow{op, width, indexed != 0}
				if width == 0 && row.indexed {
					bytePairs[base] = row
				} else {
					ordinary[base] = row
				}
			}
		}
	}
	return
}

func decodeARM64RawSVEIntegerDot(word uint32) (Instr, bool) {
	row, ok := arm64RawSVEIntegerDotRows[word&0xffe0fc00]
	if !ok {
		row, ok = arm64RawSVEIntegerDotBytePairRows[word&0xffa0fc00]
		if !ok {
			return Instr{}, false
		}
	}
	widths := arm64SVEIntegerDotWidthForms[row.width]
	first, index := word>>16&31, ""
	if row.indexed {
		first &= uint32(widths.maximumVector)
		lane := word >> 19 & 3
		if widths.destination == 16 {
			lane |= word >> 20 & 4
		} else if widths.destination == 64 {
			lane = word >> 20 & 1
		}
		index = fmt.Sprintf("[%d]", lane)
	}
	sourceWidth, destinationWidth := "B", "S"
	if widths.source == 16 {
		sourceWidth = "H"
	}
	if widths.destination == 16 {
		destinationWidth = "H"
	} else if widths.destination == 64 {
		destinationWidth = "D"
	}
	return Instr{Op: row.op, Raw: fmt.Sprintf("WORD $%#08x", word), Args: []Operand{
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%s%s", first, sourceWidth, index))},
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%s", word>>5&31, sourceWidth))},
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%s", word&31, destinationWidth))},
	}}, true
}

// --- arm64_lower_word_sve_integer_minmax.go ---
// SVE signed/unsigned min/max share four opcodes and four element widths.
// Go 1.27 exposes both the predicated register and destructive immediate
// forms; decode either into the same typed named-instruction lowerer.
func decodeARM64RawSVEIntegerMinMax(word uint32) (Instr, bool) {
	predicated := word&0xff30e000 == 0x04000000
	immediate := word&0xff3ce000 == 0x2528c000
	if !predicated && !immediate {
		return Instr{}, false
	}

	var opcode int
	if predicated {
		opcode = int(word>>16) & 15
		if opcode < 8 || opcode > 11 {
			return Instr{}, false
		}
		opcode -= 8
	} else {
		opcode = int(word>>16) & 3
	}
	operations := [...]Op{"ZSMAX", "ZUMAX", "ZSMIN", "ZUMIN"}
	op := operations[opcode]
	arrangements := [...]string{"B", "H", "S", "D"}
	width := int(word>>22) & 3
	destination := Reg(fmt.Sprintf("Z%d.%s", word&31, arrangements[width]))

	var args []Operand
	if predicated {
		second := Reg(fmt.Sprintf("Z%d.%s", word>>5&31, arrangements[width]))
		predicate := Reg(fmt.Sprintf("P%d.M", word>>10&7))
		args = []Operand{
			{Kind: OpReg, Reg: second},
			{Kind: OpReg, Reg: destination},
			{Kind: OpReg, Reg: predicate},
			{Kind: OpReg, Reg: destination},
		}
	} else {
		value := int64(uint8(word >> 5))
		if opcode == 0 || opcode == 2 {
			value = int64(int8(word >> 5))
		}
		args = []Operand{
			{Kind: OpImm, Imm: value},
			{Kind: OpReg, Reg: destination},
			{Kind: OpReg, Reg: destination},
		}
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("WORD $%#08x", word)}, true
}

// --- arm64_lower_word_sve_integer_minmax_reduce.go ---
// SVE's four predicated integer min/max reductions share one encoding
// grammar. The opcode chooses signedness and min/max; size chooses B/H/S/D.
func decodeARM64RawSVEIntegerMinMaxReduction(word uint32) (Instr, bool) {
	if word&0xff30e000 != 0x04002000 {
		return Instr{}, false
	}
	opcode := int(word>>16) & 15
	if opcode < 8 || opcode > 11 {
		return Instr{}, false
	}
	width := int(word>>22) & 3
	operations := [...]string{"ZSMAXV", "ZUMAXV", "ZSMINV", "ZUMINV"}
	arrangements := [...]string{"B", "H", "S", "D"}
	op := Op(operations[opcode-8] + arrangements[width])
	source := Reg(fmt.Sprintf("Z%d.%s", word>>5&31, arrangements[width]))
	predicate := Reg(fmt.Sprintf("P%d", word>>10&7))
	destination := Reg(fmt.Sprintf("V%d", word&31))
	return Instr{
		Op: op,
		Args: []Operand{
			{Kind: OpReg, Reg: source},
			{Kind: OpReg, Reg: predicate},
			{Kind: OpReg, Reg: destination},
		},
		Raw: fmt.Sprintf("WORD $%#08x", word),
	}, true
}

// --- arm64_lower_word_sve_integer_unary.go ---
func decodeARM64RawSVEIntegerUnary(word uint32) (Instr, bool) {
	for op, spec := range arm64SVEIntegerUnarySpecs {
		variableFields := uint32(0x00c01fff) // size, Pg, Zn, Zd
		if spec.unpred {
			variableFields = 0x00c003ff // size, Zn, Zd
		}
		base, mode := word&^variableFields, "M"
		if base != spec.rawMerge {
			if spec.rawZero == 0 || base != spec.rawZero {
				continue
			}
			mode = "Z"
		}
		bits := 8 << (word >> 22 & 3)
		if bits < spec.minBits || spec.maxBits != 0 && bits > spec.maxBits {
			return Instr{}, false
		}
		width := "BHSD"[word>>22&3]
		args := []Operand{{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", word>>5&31, width))}}
		if !spec.unpred {
			args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d.%s", word>>10&7, mode))})
		}
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", word&31, width))})
		return Instr{Op: op, Args: args, Raw: fmt.Sprintf("WORD $%#08x", word)}, true
	}
	return Instr{}, false
}

// --- arm64_lower_word_sve_ld1b.go ---
type arm64RawSVELD1B struct {
	elementBits int
	predicate   int
	base        int
	index       int
	vector      int
}

func decodeARM64RawSVELD1B(word uint32) (arm64RawSVELD1B, bool) {
	if word&0xff80e000 != 0xa4004000 {
		return arm64RawSVELD1B{}, false
	}
	return arm64RawSVELD1B{
		elementBits: 8 << ((word >> 21) & 3),
		predicate:   int((word >> 10) & 7),
		base:        int((word >> 5) & 31),
		index:       int((word >> 16) & 31),
		vector:      int(word & 31),
	}, true
}

func (c *arm64Ctx) lowerRawSVELD1B(form arm64RawSVELD1B) error {
	predicate, err := c.loadPReg(form.predicate)
	if err != nil {
		return err
	}
	_, lanes, err := arm64SVEVectorType(form.elementBits)
	if err != nil {
		return err
	}
	narrowPredicate := predicate
	if form.elementBits != 8 {
		narrowPredicate = c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call <vscale x %d x i1> @llvm.aarch64.sve.convert.from.svbool.nxv%di1(<vscale x 16 x i1> %s)\n", narrowPredicate, lanes, lanes, predicate)
		narrowPredicate = "%" + narrowPredicate
	}
	baseReg := Reg(fmt.Sprintf("R%d", form.base))
	if form.base == 31 {
		baseReg = SP
	}
	base, err := c.loadReg(baseReg)
	if err != nil {
		return err
	}
	index := ZR
	if form.index != 31 {
		index = Reg(fmt.Sprintf("R%d", form.index))
	}
	indexValue, err := c.loadReg(index)
	if err != nil {
		return err
	}
	address := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add i64 %s, %s\n", address, base, indexValue)
	pointer := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %%%s to ptr\n", pointer, address)
	loaded := c.newTmp()
	vectorType := fmt.Sprintf("<vscale x %d x i8>", lanes)
	predicateType := fmt.Sprintf("<vscale x %d x i1>", lanes)
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.masked.load.nxv%di8.p0(ptr align 1 %%%s, %s %s, %s zeroinitializer)\n", loaded, vectorType, lanes, pointer, predicateType, narrowPredicate, vectorType)
	value := "%" + loaded
	if form.elementBits != 8 {
		widenedType := fmt.Sprintf("<vscale x %d x i%d>", lanes, form.elementBits)
		widened := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext %s %s to %s\n", widened, vectorType, value, widenedType)
		value = "%" + widened
	}
	if form.elementBits != 8 {
		bytes := c.newTmp()
		widenedType := fmt.Sprintf("<vscale x %d x i%d>", lanes, form.elementBits)
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <vscale x 16 x i8>\n", bytes, widenedType, value)
		value = "%" + bytes
	}
	return c.storeZReg(form.vector, value)
}

// --- arm64_lower_word_sve_ldr_str.go ---
type arm64RawSVELoadStore struct {
	load      bool
	predicate bool
	immediate int
	base      int
	vector    int
}

// decodeARM64RawSVELoadStore covers the complete unpredicated SVE LDR/STR
// scalar-base formats for Z and P registers. The signed imm9 is measured in
// vector bytes for Z registers and predicate bytes (VL/8) for P registers.
func decodeARM64RawSVELoadStore(word uint32) (arm64RawSVELoadStore, bool) {
	form := arm64RawSVELoadStore{}
	switch word & 0xffc0e000 {
	case 0x85804000:
		form.load = true
	case 0xe5804000:
		form.load = false
	case 0x85800000, 0xe5800000:
		if word&16 != 0 { // Pt is four bits, unlike Zt.
			return arm64RawSVELoadStore{}, false
		}
		form.predicate = true
		form.load = word&(1<<30) == 0
	default:
		return arm64RawSVELoadStore{}, false
	}
	imm9 := int(word>>16&0x3f)<<3 | int(word>>10&7)
	if imm9&0x100 != 0 {
		imm9 -= 0x200
	}
	form.immediate = imm9
	form.base = int(word>>5) & 31
	form.vector = int(word) & 31
	return form, true
}

func (c *arm64Ctx) lowerRawSVELoadStore(form arm64RawSVELoadStore) error {
	baseReg := Reg(fmt.Sprintf("R%d", form.base))
	if form.base == 31 {
		baseReg = Reg("RSP")
	}
	prefix, operation := "Z", "STR"
	if form.predicate {
		prefix = "P"
	}
	if form.load {
		operation = "LDR"
	}
	register := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", prefix, form.vector))}
	displacement := fmt.Sprintf("VL*%d", form.immediate)
	if form.immediate < 0 {
		displacement = fmt.Sprintf("-VL*%d", -form.immediate)
	}
	memory := Operand{Kind: OpMem, Mem: MemRef{Base: baseReg, OffRaw: displacement}}
	args := []Operand{register, memory}
	if form.load {
		args = []Operand{memory, register}
	}
	ins := Instr{Op: Op(prefix + operation), Args: args}
	if form.predicate {
		_, _, err := c.lowerARM64SVEPredicateLoadStore(ins.Op, ins)
		return err
	}
	_, _, err := c.lowerARM64SVEWholeVectorMemory(ins.Op, ins)
	return err
}

// --- arm64_lower_word_sve_multiply_accumulate.go ---
type arm64RawSVEMultiplyAccumulateRow struct {
	op   Op
	size uint32
}

var arm64RawSVEMultiplyAccumulatePredicatedOps, arm64RawSVEMultiplyAccumulateIndexedRows = arm64SVEMultiplyAccumulateRawTables()

func arm64SVEMultiplyAccumulateRawTables() (map[uint32]Op, map[uint32]arm64RawSVEMultiplyAccumulateRow) {
	predicated := make(map[uint32]Op)
	indexed := make(map[uint32]arm64RawSVEMultiplyAccumulateRow)
	for op, spec := range arm64SVEMultiplyAccumulateSpecs {
		predicated[spec.predicatedRaw] = op
		for size, base := range spec.indexedRaw {
			if base == 0 {
				continue
			}
			indexed[base] = arm64RawSVEMultiplyAccumulateRow{op, uint32(size + 1)}
		}
	}
	return predicated, indexed
}

func decodeARM64RawSVEMultiplyAccumulate(word uint32) (Instr, bool) {
	op, predicated := arm64RawSVEMultiplyAccumulatePredicatedOps[word&0xff20e000]
	size, multiplier, lane := word>>22&3, word>>16&31, ""
	if !predicated {
		// Halfword lane[2] replaces size[0]; word and doubleword retain
		// their fixed size bits. Never let those forms alias the H decoder.
		row, ok := arm64RawSVEMultiplyAccumulateIndexedRows[word&0xffe0fc00]
		if !ok {
			row, ok = arm64RawSVEMultiplyAccumulateIndexedRows[word&0xffa0fc00]
			if !ok || row.size != 1 {
				return Instr{}, false
			}
		}
		op, size = row.op, row.size
		index := word >> 19 & 3
		multiplier &= 7
		if size == 1 {
			index |= word >> 20 & 4
		} else if size == 3 {
			multiplier = word >> 16 & 15
			index = word >> 20 & 1
		}
		lane = fmt.Sprintf("[%d]", index)
	}
	width := "BHSD"[size]
	args := []Operand{
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c%s", multiplier, width, lane))},
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", word>>5&31, width))},
	}
	if arm64SVEMultiplyAccumulateSpecs[op].destructiveProduct {
		// MAD/MSB encode the addend in bits 9:5, unlike MLA/MLS's
		// multiplicand. Normalize both encodings to Go's operand order.
		args[0], args[1] = args[1], args[0]
	}
	if predicated {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d.M", word>>10&7))})
	}
	args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", word&31, width))})
	return Instr{Op: op, Raw: fmt.Sprintf("WORD $%#08x", word), Args: args}, true
}

// --- arm64_lower_word_sve_ptest.go ---
// PTEST has one byte-granularity form; both predicate numbers are four-bit
// fields. Route the raw encoding through the named flag-producing lowerer.
func decodeARM64RawSVEPTest(word uint32) (Instr, bool) {
	if word&0xffffc21f != 0x2550c000 {
		return Instr{}, false
	}
	tested := Reg(fmt.Sprintf("P%d.B", word>>5&15))
	governing := Reg(fmt.Sprintf("P%d", word>>10&15))
	return Instr{
		Op:   "PPTEST",
		Args: []Operand{{Kind: OpReg, Reg: tested}, {Kind: OpReg, Reg: governing}},
		Raw:  fmt.Sprintf("WORD $%#08x", word),
	}, true
}

// --- arm64_lower_word_sve_ptrue.go ---
type arm64RawSVEPTrue struct {
	elementBits int
	pattern     int
	destination int
}

func decodeARM64RawSVEPTrue(word uint32) (arm64RawSVEPTrue, bool) {
	if word&0xff3ffc10 != 0x2518e000 {
		return arm64RawSVEPTrue{}, false
	}
	pattern := int(word>>5) & 31
	// Unknown pattern encodings architecturally produce an empty predicate;
	// they are not undefined instructions (Arm PTRUE / DecodePredCount).
	return arm64RawSVEPTrue{
		elementBits: 8 << (int(word>>22) & 3),
		pattern:     pattern,
		destination: int(word) & 15,
	}, true
}

func (c *arm64Ctx) lowerRawSVEPTrue(form arm64RawSVEPTrue) error {
	lanes := 128 / form.elementBits
	predicateType := fmt.Sprintf("<vscale x %d x i1>", lanes)
	predicate := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.ptrue.nxv%di1(i32 %d)\n", predicate, predicateType, lanes, form.pattern)
	value := "%" + predicate
	if form.elementBits != 8 {
		converted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call <vscale x 16 x i1> @llvm.aarch64.sve.convert.to.svbool.nxv%di1(%s %s)\n",
			converted, lanes, predicateType, value)
		value = "%" + converted
	}
	return c.storePReg(form.destination, value)
}

// --- arm64_lower_word_sve_unpack.go ---
// The four SVE widening-unpack operations use one grammar. The size field
// selects B-to-H, H-to-S, or S-to-D; opcode bits select sign and half.
func decodeARM64RawSVEUnpack(word uint32) (Instr, bool) {
	if word&0xff3cfc00 != 0x05303800 {
		return Instr{}, false
	}
	width := int(word>>22) & 3
	if width == 0 {
		return Instr{}, false
	}
	opcode := int(word>>16) & 3
	operations := [...]Op{"ZSUNPKLO", "ZSUNPKHI", "ZUUNPKLO", "ZUUNPKHI"}
	arrangements := [...]string{"", "B", "H", "S", "D"}
	source := Reg(fmt.Sprintf("Z%d.%s", word>>5&31, arrangements[width]))
	destination := Reg(fmt.Sprintf("Z%d.%s", word&31, arrangements[width+1]))
	return Instr{
		Op:   operations[opcode],
		Args: []Operand{{Kind: OpReg, Reg: source}, {Kind: OpReg, Reg: destination}},
		Raw:  fmt.Sprintf("WORD $%#08x", word),
	}, true
}

// --- arm64_lower_word_sve_whilelo.go ---
// These are the four Go 1.27 encoder rows for each SVE predicate WHILE
// condition: scalar X, scalar W, predicate pair and SVE2.1 predicate counter.
// The raw decoder feeds the same typed grammar and lowering as named PWHILE*
// instructions instead of maintaining a second implementation of their flags.
type arm64RawSVEWhileSpec struct {
	condition string
	scalarX   uint32
	scalarW   uint32
	pair      uint32
	counter   uint32
}

var arm64RawSVEWhileSpecs = [...]arm64RawSVEWhileSpec{
	{"GE", 0x25201000, 0x25200000, 0x25205010, 0x25204010},
	{"GT", 0x25201010, 0x25200010, 0x25205011, 0x25204018},
	{"HI", 0x25201810, 0x25200810, 0x25205811, 0x25204818},
	{"HS", 0x25201800, 0x25200800, 0x25205810, 0x25204810},
	{"LE", 0x25201410, 0x25200410, 0x25205411, 0x25204418},
	{"LO", 0x25201c00, 0x25200c00, 0x25205c10, 0x25204c10},
	{"LS", 0x25201c10, 0x25200c10, 0x25205c11, 0x25204c18},
	{"LT", 0x25201400, 0x25200400, 0x25205410, 0x25204410},
}

func arm64RawSVEWhileGP(index uint32) Reg {
	if index == 31 {
		return ZR
	}
	return Reg(fmt.Sprintf("R%d", index))
}

func decodeARM64RawSVEWhile(word uint32) (Instr, bool) {
	width := "BHSD"[word>>22&3]
	// Go Plan 9 syntax lists Rm, Rn, then Pd. Raw AArch64 bits 5:9 encode
	// Rn and bits 16:20 encode Rm, so this reversal is intentional.
	args := []Operand{
		{Kind: OpReg, Reg: arm64RawSVEWhileGP(word >> 16 & 31)},
		{Kind: OpReg, Reg: arm64RawSVEWhileGP(word >> 5 & 31)},
	}
	for _, spec := range arm64RawSVEWhileSpecs {
		op := Op("PWHILE" + spec.condition)
		if word&0xff20fc10 == spec.scalarX || word&0xff20fc10 == spec.scalarW {
			if word&0x00001000 == 0 {
				op += "W"
			}
			args = append(args, Operand{
				Kind: OpReg,
				Reg:  Reg(fmt.Sprintf("P%d.%c", word&15, width)),
			})
			return Instr{Op: op, Args: args, Raw: fmt.Sprintf("WORD $%#08x", word)}, true
		}
		if word&0xff20fc11 == spec.pair {
			predicate := word & 14
			args = append(args, Operand{
				Kind: OpRegList,
				RegList: []Reg{
					Reg(fmt.Sprintf("P%d.%c", predicate, width)),
					Reg(fmt.Sprintf("P%d.%c", predicate+1, width)),
				},
			})
			return Instr{Op: op, Args: args, Raw: fmt.Sprintf("WORD $%#08x", word)}, true
		}
		if word&0xff20dc18 == spec.counter {
			multiplier := 2
			if word&0x2000 != 0 {
				multiplier = 4
			}
			args = append([]Operand{{Kind: OpIdent, Ident: fmt.Sprintf("VLX%d", multiplier)}}, args...)
			args = append(args, Operand{
				Kind: OpReg,
				Reg:  Reg(fmt.Sprintf("PN%d.%c", 8+(word&7), width)),
			})
			return Instr{Op: op, Args: args, Raw: fmt.Sprintf("WORD $%#08x", word)}, true
		}
	}
	return Instr{}, false
}
