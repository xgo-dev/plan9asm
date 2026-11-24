package plan9asm

import (
	"fmt"
	"math"
	"math/bits"
	"strconv"
	"strings"
)

// --- arm64_lower_barrier.go ---
// lowerARM64Barrier implements Go's ADMB optab row, the ADSB/AISB aliases
// installed from it, and the operand-free ASB row.
func (c *arm64Ctx) lowerARM64Barrier(op Op, ins Instr) (ok bool, terminated bool, err error) {
	switch op {
	case "SB":
		if strings.ToUpper(string(ins.Op)) != "SB" || len(ins.Args) != 0 {
			return true, false, fmt.Errorf("arm64 SB accepts no operands or suffix: %q", ins.Raw)
		}
		// Preserve Go's actual SB encoding even when the LLVM baseline does
		// not enable its mnemonic. HINT #7 is a different instruction, not a
		// feature fallback. The source decides whether SB may execute.
		c.emitMachineNeutralNativeIR("  call void asm sideeffect %q, %q()\n", ".inst 0xd50330ff", "~{memory}")
		return true, false, nil
	case "DMB", "DSB", "ISB":
	default:
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 1 ||
		ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" || ins.Args[0].ImmIsFloat {
		return true, false, fmt.Errorf("arm64 %s expects exactly one constant operand with no suffix: %q", op, ins.Raw)
	}
	encoded := uint64(ins.Args[0].Imm) & 0xf
	// Preserve the architectural operation instead of substituting a weaker
	// generic LLVM fence. The memory clobber also prevents compiler reordering
	// across DMB/DSB and is conservative for ISB.
	c.emitMachineNeutralNativeIR("  call void asm sideeffect %q, %q()\n", strings.ToLower(string(op))+fmt.Sprintf(" #%d", encoded), "~{memory}")
	return true, false, nil
}

// --- arm64_lower_bit_reverse.go ---
func (c *arm64Ctx) lowerARM64BitReverse(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "RBIT" && op != "RBITW" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) {
		return true, false, fmt.Errorf("arm64 %s does not accept an instruction suffix: %q", op, ins.Raw)
	}
	if len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg ||
		!isARM64GeneralOrZeroReg(ins.Args[0].Reg) || !isARM64GeneralOrZeroReg(ins.Args[1].Reg) {
		return true, false, fmt.Errorf("arm64 %s expects general register, general register: %q", op, ins.Raw)
	}

	if op == "RBITW" {
		source, err := c.eval32(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		reversed := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.bitreverse.i32(i32 %s)\n", reversed, source)
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", wide, reversed)
		return true, false, c.storeReg(ins.Args[1].Reg, "%"+wide)
	}

	source, err := c.loadReg(ins.Args[0].Reg)
	if err != nil {
		return true, false, err
	}
	reversed := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call i64 @llvm.bitreverse.i64(i64 %s)\n", reversed, source)
	return true, false, c.storeReg(ins.Args[1].Reg, "%"+reversed)
}

// --- arm64_lower_compare_negative.go ---
func validateARM64CompareNegativeOperands(source, destination Operand, word bool) error {
	if destination.Kind != OpReg || !(isARM64GeneralOrZeroReg(destination.Reg) || destination.Reg == SP || destination.Reg == Reg("RSP")) {
		return fmt.Errorf("destination is outside Go 1.27's C_ZREG/C_RSP classes")
	}
	switch source.Kind {
	case OpImm:
		return nil
	case OpReg:
		if !isARM64GeneralOrZeroReg(source.Reg) {
			return fmt.Errorf("register source is outside Go 1.27's C_ZREG class")
		}
		return nil
	case OpRegShift:
		if !isARM64GeneralOrZeroReg(source.Reg) || source.ShiftReg != "" {
			return fmt.Errorf("shifted source is outside Go 1.27's C_SHIFT class")
		}
		if source.ShiftOp != ShiftLeft && source.ShiftOp != ShiftRight && source.ShiftOp != ShiftArith {
			return fmt.Errorf("shift operator %q is outside Go 1.27's C_SHIFT class", source.ShiftOp)
		}
		maximum := int64(63)
		if word {
			maximum = 31
		}
		if source.ShiftAmount < 0 || source.ShiftAmount > maximum {
			return fmt.Errorf("shift amount %d is outside 0..%d", source.ShiftAmount, maximum)
		}
		return nil
	case OpRegExtend:
		if !isARM64GeneralOrZeroReg(source.Reg) || source.ShiftReg != "" || source.ShiftAmount < 0 || source.ShiftAmount > 4 {
			return fmt.Errorf("extended source is outside Go 1.27's C_EXTREG class")
		}
		switch source.Ext {
		case ExtendUXTB, ExtendUXTH, ExtendUXTW, ExtendUXTX,
			ExtendSXTB, ExtendSXTH, ExtendSXTW, ExtendSXTX:
			// CMNW uses the low 32 bits of the extended operand.
			return nil
		}
		return fmt.Errorf("extension %q is outside Go 1.27's C_EXTREG class", source.Ext)
	default:
		return fmt.Errorf("source is outside Go 1.27's immediate/C_ZREG/C_SHIFT/C_EXTREG classes")
	}
}

// --- arm64_lower_count_bits.go ---
var arm64VectorCountBitsOps = map[Op]struct{}{
	"VCNT": {},
	"VCLS": {},
	"VCLZ": {},
}

func (c *arm64Ctx) lowerARM64VectorCountBits(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if _, ok := arm64VectorCountBitsOps[op]; !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("arm64 %s expects two same-arrangement vector registers and no suffix: %q", op, ins.Raw)
	}
	sourceArrangement, sourceOK := parseARM64VectorArrangement(ins.Args[0].Reg)
	destinationArrangement, destinationOK := parseARM64VectorArrangement(ins.Args[1].Reg)
	validArrangement := sourceArrangement.elementBits == 8 && (sourceArrangement.lanes == 8 || sourceArrangement.lanes == 16)
	if op != "VCNT" {
		validArrangement = (sourceArrangement.elementBits == 8 || sourceArrangement.elementBits == 16 || sourceArrangement.elementBits == 32) &&
			(sourceArrangement.lanes*sourceArrangement.elementBits == 64 || sourceArrangement.lanes*sourceArrangement.elementBits == 128)
	}
	if !sourceOK || !destinationOK || sourceArrangement != destinationArrangement || !validArrangement {
		return true, false, fmt.Errorf("arm64 %s requires matching Go assembler vector arrangements: %q", op, ins.Raw)
	}
	source, err := c.loadARM64VectorInteger(ins.Args[0].Reg, sourceArrangement)
	if err != nil {
		return true, false, err
	}
	if op == "VCNT" {
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call <%d x i8> @llvm.ctpop.v%di8(<%d x i8> %s)\n", result, sourceArrangement.lanes, sourceArrangement.lanes, sourceArrangement.lanes, source)
		return true, false, c.storeARM64VectorInteger(ins.Args[1].Reg, destinationArrangement, "%"+result)
	}

	vectorType := fmt.Sprintf("<%d x i%d>", sourceArrangement.lanes, sourceArrangement.elementBits)
	countSource := source
	if op == "VCLS" {
		sign := c.newTmp()
		normalized := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ashr %s %s, %s\n", sign, vectorType, source, arm64VectorIntegerSplat(sourceArrangement, int64(sourceArrangement.elementBits-1)))
		fmt.Fprintf(c.b, "  %%%s = xor %s %s, %%%s\n", normalized, vectorType, source, sign)
		countSource = "%" + normalized
	}
	count := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.ctlz.v%di%d(%s %s, i1 false)\n",
		count, vectorType, sourceArrangement.lanes, sourceArrangement.elementBits, vectorType, countSource)
	result := "%" + count
	if op == "VCLS" {
		adjusted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub %s %%%s, %s\n", adjusted, vectorType, count, arm64VectorIntegerSplat(sourceArrangement, 1))
		result = "%" + adjusted
	}
	return true, false, c.storeARM64VectorInteger(ins.Args[1].Reg, destinationArrangement, result)
}

// --- arm64_lower_count_leading.go ---
func (c *arm64Ctx) lowerARM64CountLeading(op Op, ins Instr) (ok bool, terminated bool, err error) {
	signed := op == "CLS" || op == "CLSW"
	word := op == "CLZW" || op == "CLSW"
	if !signed && !word && op != "CLZ" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) {
		return true, false, fmt.Errorf("arm64 %s does not accept an instruction suffix: %q", op, ins.Raw)
	}
	if len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg ||
		!isARM64GeneralOrZeroReg(ins.Args[0].Reg) || !isARM64GeneralOrZeroReg(ins.Args[1].Reg) {
		return true, false, fmt.Errorf("arm64 %s expects general register, general register: %q", op, ins.Raw)
	}

	if word {
		source, err := c.eval32(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		value := source
		if signed {
			sign := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = ashr i32 %s, 31\n", sign, source)
			normalized := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor i32 %s, %%%s\n", normalized, source, sign)
			value = "%" + normalized
		}
		count := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.ctlz.i32(i32 %s, i1 false)\n", count, value)
		result := "%" + count
		if signed {
			adjusted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = sub i32 %s, 1\n", adjusted, result)
			result = "%" + adjusted
		}
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", wide, result)
		return true, false, c.storeReg(ins.Args[1].Reg, "%"+wide)
	}

	source, err := c.loadReg(ins.Args[0].Reg)
	if err != nil {
		return true, false, err
	}
	value := source
	if signed {
		sign := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ashr i64 %s, 63\n", sign, source)
		normalized := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i64 %s, %%%s\n", normalized, source, sign)
		value = "%" + normalized
	}
	count := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call i64 @llvm.ctlz.i64(i64 %s, i1 false)\n", count, value)
	result := "%" + count
	if signed {
		adjusted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub i64 %s, 1\n", adjusted, result)
		result = "%" + adjusted
	}
	return true, false, c.storeReg(ins.Args[1].Reg, result)
}

// --- arm64_lower_cterm.go ---
var arm64CTERMOps = map[Op]bool{
	"CTERMEQ":  true,
	"CTERMEQW": true,
	"CTERMNE":  true,
	"CTERMNEW": true,
}

func (c *arm64Ctx) lowerARM64CTERM(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if !arm64CTERMOps[op] {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg ||
		!isARM64GeneralOrZeroReg(ins.Args[0].Reg) || !isARM64GeneralOrZeroReg(ins.Args[1].Reg) || ins.Args[0].Reg == SP || ins.Args[0].Reg == Reg("RSP") || ins.Args[1].Reg == SP || ins.Args[1].Reg == Reg("RSP") {
		return true, false, fmt.Errorf("arm64 %s requires two R0..R30 or ZR operands: %q", op, ins.Raw)
	}
	first, err := c.loadReg(ins.Args[0].Reg)
	if err != nil {
		return true, false, err
	}
	second, err := c.loadReg(ins.Args[1].Reg)
	if err != nil {
		return true, false, err
	}
	typeName := "i64"
	if strings.HasSuffix(string(op), "W") {
		typeName = "i32"
		first32 := c.newTmp()
		second32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", first32, first)
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", second32, second)
		first = "%" + first32
		second = "%" + second32
	}
	mnemonic := strings.ToLower(strings.TrimSuffix(string(op), "W"))
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, \"r,r\"(%s %s, %s %s)\n", mnemonic+" $0, $1", typeName, first, typeName, second)
	return true, false, nil
}

// --- arm64_lower_extend.go ---
type arm64ScalarExtendSpec struct {
	sourceBits      int
	signed          bool
	wordDestination bool
}

var arm64ScalarExtendSpecs = map[Op]arm64ScalarExtendSpec{
	"SXTB":  {sourceBits: 8, signed: true},
	"SXTBW": {sourceBits: 8, signed: true, wordDestination: true},
	"SXTH":  {sourceBits: 16, signed: true},
	"SXTHW": {sourceBits: 16, signed: true, wordDestination: true},
	"SXTW":  {sourceBits: 32, signed: true},
	"UXTB":  {sourceBits: 8},
	"UXTBW": {sourceBits: 8, wordDestination: true},
	"UXTH":  {sourceBits: 16},
	"UXTHW": {sourceBits: 16, wordDestination: true},
	"UXTW":  {sourceBits: 32},
}

func (c *arm64Ctx) lowerARM64ScalarExtend(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64ScalarExtendSpecs[op]
	if !ok {
		return false, false, nil
	}
	if _, _, err := parseARM64GPDataForm(op, ins); err != nil {
		return true, false, err
	}
	source, err := c.loadRegisterWidth(ins.Args[0].Reg, spec.sourceBits)
	if err != nil {
		return true, false, err
	}
	narrow := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i%d\n", narrow, source, spec.sourceBits)
	destinationBits := 64
	if spec.wordDestination {
		destinationBits = 32
	}
	extended := c.newTmp()
	extension := "zext"
	if spec.signed {
		extension = "sext"
	}
	fmt.Fprintf(c.b, "  %%%s = %s i%d %%%s to i%d\n", extended, extension, spec.sourceBits, narrow, destinationBits)
	value := "%" + extended
	if spec.wordDestination {
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", wide, value)
		value = "%" + wide
	}
	return true, false, c.storeReg(ins.Args[1].Reg, value)
}

// --- arm64_lower_extract.go ---
func (c *arm64Ctx) lowerARM64VectorExtract(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "VEXT" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != "VEXT" || len(ins.Args) != 4 ||
		ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" {
		return true, false, fmt.Errorf("arm64 VEXT expects $offset, Vm.B8/B16, Vn.B8/B16, Vd.B8/B16: %q", ins.Raw)
	}

	var arrangement arm64VectorArrangement
	for index, operand := range ins.Args[1:] {
		if operand.Kind != OpReg {
			return true, false, fmt.Errorf("arm64 VEXT accepts only arranged vector registers: %q", ins.Raw)
		}
		parsed, valid := parseARM64VectorArrangement(operand.Reg)
		if !valid || parsed.elementBits != 8 || parsed.lanes != 8 && parsed.lanes != 16 {
			return true, false, fmt.Errorf("arm64 VEXT arrangement must be B8 or B16: %q", ins.Raw)
		}
		if index == 0 {
			arrangement = parsed
		} else if parsed != arrangement {
			return true, false, fmt.Errorf("arm64 VEXT arrangements must match: %q", ins.Raw)
		}
	}
	offset := int(ins.Args[0].Imm)
	if offset < 0 || offset >= arrangement.lanes {
		return true, false, fmt.Errorf("arm64 VEXT offset must be in [0,%d): %q", arrangement.lanes, ins.Raw)
	}

	// Go's Plan 9 order is $offset, Vm, Vn, Vd. EXT concatenates Vn:Vm
	// and selects one vector starting at the byte offset.
	m, err := c.loadARM64VectorInteger(ins.Args[1].Reg, arrangement)
	if err != nil {
		return true, false, err
	}
	n, err := c.loadARM64VectorInteger(ins.Args[2].Reg, arrangement)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  ; arm64 vector extract\n")
	fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i8> %s, <%d x i8> %s, <%d x i32> <", result, arrangement.lanes, n, arrangement.lanes, m, arrangement.lanes)
	for lane := 0; lane < arrangement.lanes; lane++ {
		if lane != 0 {
			c.b.WriteString(", ")
		}
		fmt.Fprintf(c.b, "i32 %d", offset+lane)
	}
	c.b.WriteString(">\n")
	return true, false, c.storeARM64VectorInteger(ins.Args[3].Reg, arrangement, "%"+result)
}

// --- arm64_lower_float_minmax_across.go ---
var arm64VectorFloatMinMaxAcrossOps = map[Op]string{
	"VFMAXV":   "maximum",
	"VFMINV":   "minimum",
	"VFMAXNMV": "maxnum",
	"VFMINNMV": "minnum",
}

func (c *arm64Ctx) lowerARM64VectorFloatMinMaxAcross(op Op, ins Instr) (ok bool, terminated bool, err error) {
	operation, handled := arm64VectorFloatMinMaxAcrossOps[op]
	if !handled {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 ||
		ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("arm64 %s expects Vsrc.S4, Vdst and no suffix: %q", op, ins.Raw)
	}
	arrangement, valid := parseARM64VectorArrangement(ins.Args[0].Reg)
	destinationIndex, destinationValid := arm64ParseVReg(ins.Args[1].Reg)
	if !valid || arrangement != (arm64VectorArrangement{elementBits: 32, lanes: 4}) ||
		!destinationValid || strings.Contains(string(ins.Args[1].Reg), ".") {
		return true, false, fmt.Errorf("arm64 %s requires an S4 source and bare V destination: %q", op, ins.Raw)
	}
	return true, false, c.lowerARM64FloatMinMaxAcrossValues(
		operation,
		arrangement,
		ins.Args[0].Reg,
		Reg(fmt.Sprintf("F%d", destinationIndex)),
	)
}

func (c *arm64Ctx) lowerARM64FloatMinMaxAcrossValues(
	operation string,
	arrangement arm64VectorArrangement,
	sourceReg Reg,
	destination Reg,
) error {
	source, err := c.loadARM64VectorFloat(sourceReg, arrangement)
	if err != nil {
		return err
	}
	floatType := arm64RawFloatType(arrangement.elementBits)
	first := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractelement <%d x %s> %s, i32 0\n", first, arrangement.lanes, floatType, source)
	result := "%" + first
	for lane := 1; lane < arrangement.lanes; lane++ {
		element := c.newTmp()
		combined := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x %s> %s, i32 %d\n", element, arrangement.lanes, floatType, source, lane)
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.%s.f%d(%s %s, %s %%%s)\n",
			combined, floatType, operation, arrangement.elementBits, floatType, result, floatType, element)
		result = "%" + combined
	}
	return c.storeARM64ScalarFloatReg(destination, arrangement.elementBits, result)
}

// --- arm64_lower_float_widen_raw.go ---
type arm64RawVectorFloatWiden struct {
	sourceBits  int
	upper       bool
	source      int
	destination int
}

func decodeARM64RawVectorFloatWiden(word uint32) (arm64RawVectorFloatWiden, bool) {
	if word&0xbfbffc00 != 0x0e217800 {
		return arm64RawVectorFloatWiden{}, false
	}
	sourceBits := 16
	if word&(1<<22) != 0 {
		sourceBits = 32
	}
	return arm64RawVectorFloatWiden{
		sourceBits:  sourceBits,
		upper:       word&(1<<30) != 0,
		source:      int(word>>5) & 31,
		destination: int(word) & 31,
	}, true
}

func (c *arm64Ctx) lowerRawVectorFloatWiden(form arm64RawVectorFloatWiden) error {
	return c.lowerARM64VectorFloatWidenForm(form.sourceBits, form.upper,
		Reg(fmt.Sprintf("V%d", form.source)), Reg(fmt.Sprintf("V%d", form.destination)))
}

// --- arm64_lower_fmovq.go ---
// loadFMOVQFrame reconstructs the 16 contiguous bytes addressed by off(FP)
// from the scalar LLVM fields used to model Go parameters and results.
func (c *arm64Ctx) loadFMOVQFrame(off int64) (string, error) {
	packed, err := c.loadFPFrameBits(off, 16)
	if err != nil {
		return "", err
	}
	vector := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast i128 %s to <16 x i8>\n", vector, packed)
	return "%" + vector, nil
}

// storeFMOVQFrame splits a vector into the scalar LLVM frame slots that cover
// the 16 contiguous bytes addressed by off(FP).
func (c *arm64Ctx) storeFMOVQFrame(off int64, value string) error {
	packed := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to i128\n", packed, value)
	return c.storeFPFrameBits(off, 16, "%"+packed)
}

// --- arm64_lower_integer_abs_neg.go ---
func (c *arm64Ctx) lowerARM64VectorIntegerAbsNeg(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "VABS" && op != "VNEG" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 ||
		ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("arm64 %s expects two same-arrangement vector registers and no suffix: %q", op, ins.Raw)
	}
	sourceArrangement, sourceOK := parseARM64VectorArrangement(ins.Args[0].Reg)
	destinationArrangement, destinationOK := parseARM64VectorArrangement(ins.Args[1].Reg)
	validArrangement := sourceArrangement.elementBits != 64 || sourceArrangement.lanes == 2
	if !sourceOK || !destinationOK || sourceArrangement != destinationArrangement || !validArrangement {
		return true, false, fmt.Errorf("arm64 %s requires matching B8, B16, H4, H8, S2, S4, or D2 arrangements: %q", op, ins.Raw)
	}

	return true, false, c.lowerARM64IntegerAbsNeg(ins.Args[0].Reg, ins.Args[1].Reg, sourceArrangement, op == "VABS", false)
}

func (c *arm64Ctx) lowerARM64IntegerAbsNeg(sourceReg, destination Reg, arrangement arm64VectorArrangement, absolute, saturating bool) error {
	vectorType := fmt.Sprintf("<%d x i%d>", arrangement.lanes, arrangement.elementBits)
	source, err := c.loadARM64VectorInteger(sourceReg, arrangement)
	if err != nil {
		return err
	}
	negated := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sub %s zeroinitializer, %s\n", negated, vectorType, source)
	result := "%" + negated
	if absolute {
		negative := c.newTmp()
		absolute := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp slt %s %s, zeroinitializer\n", negative, vectorType, source)
		fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %%%s, %s %s\n",
			absolute, arrangement.lanes, negative, vectorType, negated, vectorType, source)
		result = "%" + absolute
	}
	if saturating {
		// In two's complement, zero and the signed minimum are the only values
		// equal to their own negation. Excluding zero identifies saturation; a
		// logical shift of the minimum produces the signed maximum.
		equalNegation := c.newTmp()
		nonzero := c.newTmp()
		overflow := c.newTmp()
		saturated := c.newTmp()
		selected := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, %%%s\n", equalNegation, vectorType, source, negated)
		fmt.Fprintf(c.b, "  %%%s = icmp ne %s %s, zeroinitializer\n", nonzero, vectorType, source)
		fmt.Fprintf(c.b, "  %%%s = and <%d x i1> %%%s, %%%s\n", overflow, arrangement.lanes, equalNegation, nonzero)
		fmt.Fprintf(c.b, "  %%%s = lshr %s %%%s, %s\n", saturated, vectorType, negated, arm64VectorIntegerSplat(arrangement, 1))
		fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %%%s, %s %s\n",
			selected, arrangement.lanes, overflow, vectorType, saturated, vectorType, result)
		result = "%" + selected
	}
	return c.storeARM64VectorInteger(destination, arrangement, result)
}

func arm64VectorIntegerSplat(arrangement arm64VectorArrangement, value int64) string {
	parts := make([]string, arrangement.lanes)
	for i := range parts {
		parts[i] = fmt.Sprintf("i%d %d", arrangement.elementBits, value)
	}
	return "<" + strings.Join(parts, ", ") + ">"
}

// --- arm64_lower_integer_add_long_across.go ---
func (c *arm64Ctx) lowerARM64VectorAddLongAcross(op Op, ins Instr) (ok bool, terminated bool, err error) {
	intrinsic := ""
	switch op {
	case "VSADDLV":
		intrinsic = "saddlv"
	case "VUADDLV":
		intrinsic = "uaddlv"
	default:
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 ||
		ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("arm64 %s expects an arranged vector source and bare V destination: %q", op, ins.Raw)
	}
	arrangement, valid := parseARM64VectorArrangement(ins.Args[0].Reg)
	if !valid || !((arrangement.elementBits == 8 && (arrangement.lanes == 8 || arrangement.lanes == 16)) ||
		(arrangement.elementBits == 16 && (arrangement.lanes == 4 || arrangement.lanes == 8)) ||
		(arrangement.elementBits == 32 && arrangement.lanes == 4)) {
		return true, false, fmt.Errorf("arm64 %s accepts only B8, B16, H4, H8, or S4 source: %q", op, ins.Raw)
	}
	if strings.Contains(string(ins.Args[1].Reg), ".") {
		return true, false, fmt.Errorf("arm64 %s destination must be a bare V register: %q", op, ins.Raw)
	}
	if _, valid := arm64ParseVReg(ins.Args[1].Reg); !valid {
		return true, false, fmt.Errorf("arm64 %s destination must be a bare V register: %q", op, ins.Raw)
	}

	source, err := c.loadARM64VectorInteger(ins.Args[0].Reg, arrangement)
	if err != nil {
		return true, false, err
	}
	resultBits := arrangement.elementBits * 2
	intrinsicResultBits := resultBits
	if intrinsicResultBits < 32 {
		// LLVM 22 cannot legalize an i16 result from the AArch64 across-lane
		// intrinsic. The instruction writes an H register, but the intrinsic
		// must return i32; only its low 16 bits are architecturally defined.
		intrinsicResultBits = 32
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call i%d @llvm.aarch64.neon.%s.i%d.v%di%d(<%d x i%d> %s)\n",
		result, intrinsicResultBits, intrinsic, intrinsicResultBits, arrangement.lanes, arrangement.elementBits,
		arrangement.lanes, arrangement.elementBits, source)
	resultValue := "%" + result
	if intrinsicResultBits != resultBits {
		truncated := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i%d %s to i%d\n",
			truncated, intrinsicResultBits, resultValue, resultBits)
		resultValue = "%" + truncated
	}
	return true, false, c.storeARM64ScalarToVReg(ins.Args[1].Reg, resultBits, resultValue)
}

// --- arm64_lower_integer_minmax_across.go ---
func (c *arm64Ctx) lowerARM64VectorIntegerMinMaxAcross(op Op, ins Instr) (ok bool, terminated bool, err error) {
	predicate, handled := map[Op]string{
		"VSMAXV": "sgt",
		"VSMINV": "slt",
		"VUMAXV": "ugt",
		"VUMINV": "ult",
	}[op]
	if !handled {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 ||
		ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("arm64 %s expects an arranged vector source, bare V destination, and no suffix: %q", op, ins.Raw)
	}
	arrangement, valid := parseARM64VectorArrangement(ins.Args[0].Reg)
	if !valid || !((arrangement.elementBits == 8 && (arrangement.lanes == 8 || arrangement.lanes == 16)) ||
		(arrangement.elementBits == 16 && (arrangement.lanes == 4 || arrangement.lanes == 8)) ||
		(arrangement.elementBits == 32 && arrangement.lanes == 4)) {
		return true, false, fmt.Errorf("arm64 %s accepts only B8, B16, H4, H8, or S4 source: %q", op, ins.Raw)
	}
	if strings.Contains(string(ins.Args[1].Reg), ".") {
		return true, false, fmt.Errorf("arm64 %s destination must be a bare V register: %q", op, ins.Raw)
	}
	if _, valid := arm64ParseVReg(ins.Args[1].Reg); !valid {
		return true, false, fmt.Errorf("arm64 %s destination must be a bare V register: %q", op, ins.Raw)
	}

	source, err := c.loadARM64VectorInteger(ins.Args[0].Reg, arrangement)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %s, i32 0\n", result, arrangement.lanes, arrangement.elementBits, source)
	current := "%" + result
	for lane := 1; lane < arrangement.lanes; lane++ {
		element := c.newTmp()
		condition := c.newTmp()
		selected := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %s, i32 %d\n", element, arrangement.lanes, arrangement.elementBits, source, lane)
		fmt.Fprintf(c.b, "  %%%s = icmp %s i%d %s, %%%s\n", condition, predicate, arrangement.elementBits, current, element)
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d %s, i%d %%%s\n", selected, condition, arrangement.elementBits, current, arrangement.elementBits, element)
		current = "%" + selected
	}
	physicalLanes := 128 / arrangement.elementBits
	vector := c.newTmp()
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> zeroinitializer, i%d %s, i32 0\n",
		vector, physicalLanes, arrangement.elementBits, arrangement.elementBits, current)
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %%%s to <16 x i8>\n", out, physicalLanes, arrangement.elementBits, vector)
	return true, false, c.storeVReg(ins.Args[1].Reg, "%"+out)
}

// --- arm64_lower_integer_multiply.go ---
func (c *arm64Ctx) lowerARM64VectorIntegerMultiply(op Op, ins Instr) (ok bool, terminated bool, err error) {
	accumulate, handled := map[Op]string{
		"VMUL": "",
		"VMLA": "add",
		"VMLS": "sub",
	}[op]
	if !handled {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects three same-arrangement vector registers and no suffix: %q", op, ins.Raw)
	}
	var arrangement arm64VectorArrangement
	for i, arg := range ins.Args {
		if arg.Kind != OpReg {
			return true, false, fmt.Errorf("arm64 %s accepts only vector registers: %q", op, ins.Raw)
		}
		parsed, valid := parseARM64VectorArrangement(arg.Reg)
		if !valid || parsed.elementBits == 64 {
			return true, false, fmt.Errorf("arm64 %s accepts only B8/B16/H4/H8/S2/S4 arrangements: %q", op, ins.Raw)
		}
		if i == 0 {
			arrangement = parsed
		} else if parsed != arrangement {
			return true, false, fmt.Errorf("arm64 %s arrangements must match: %q", op, ins.Raw)
		}
	}
	first, err := c.loadARM64VectorInteger(ins.Args[0].Reg, arrangement)
	if err != nil {
		return true, false, err
	}
	second, err := c.loadARM64VectorInteger(ins.Args[1].Reg, arrangement)
	if err != nil {
		return true, false, err
	}
	vectorType := fmt.Sprintf("<%d x i%d>", arrangement.lanes, arrangement.elementBits)
	product := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = mul %s %s, %s\n", product, vectorType, second, first)
	result := "%" + product
	if accumulate != "" {
		accumulator, err := c.loadARM64VectorInteger(ins.Args[2].Reg, arrangement)
		if err != nil {
			return true, false, err
		}
		combined := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s %s %s, %%%s\n", combined, accumulate, vectorType, accumulator, product)
		result = "%" + combined
	}
	return true, false, c.storeARM64VectorInteger(ins.Args[2].Reg, arrangement, result)
}

// --- arm64_lower_inverted_logical.go ---
func (c *arm64Ctx) lowerARM64InvertedLogical(op Op, ins Instr) (ok bool, terminated bool, err error) {
	word := op == "ORNW" || op == "EONW"
	exclusive := op == "EON" || op == "EONW"
	if !word && !exclusive && op != "ORN" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) {
		return true, false, fmt.Errorf("arm64 %s does not accept an instruction suffix: %q", op, ins.Raw)
	}
	if len(ins.Args) != 2 && len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects 2 or 3 operands: %q", op, ins.Raw)
	}
	if !arm64BitClearSourceValid(ins.Args[0], word) {
		return true, false, fmt.Errorf("arm64 %s invalid first operand: %q", op, ins.Raw)
	}

	destination := ins.Args[len(ins.Args)-1]
	if destination.Kind != OpReg {
		return true, false, fmt.Errorf("arm64 %s destination must be a register: %q", op, ins.Raw)
	}
	destinationGeneral := isARM64GeneralOrZeroReg(destination.Reg)
	destinationStack := destination.Reg == SP || destination.Reg == Reg("RSP")
	if !destinationGeneral && !(len(ins.Args) == 3 && ins.Args[0].Kind == OpImm && destinationStack) {
		return true, false, fmt.Errorf("arm64 %s invalid destination register: %q", op, ins.Raw)
	}

	leftOperand := destination
	if len(ins.Args) == 3 {
		leftOperand = ins.Args[1]
		if leftOperand.Kind != OpReg || !isARM64GeneralOrZeroReg(leftOperand.Reg) {
			return true, false, fmt.Errorf("arm64 %s second operand must be a general register: %q", op, ins.Raw)
		}
	}

	typeName := "i64"
	right, err := c.eval64(ins.Args[0], false)
	if word {
		typeName = "i32"
		right, err = c.eval32(ins.Args[0])
	}
	if err != nil {
		return true, false, err
	}
	left, err := c.eval64(leftOperand, false)
	if word {
		left, err = c.eval32(leftOperand)
	}
	if err != nil {
		return true, false, err
	}

	inverted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor %s %s, -1\n", inverted, typeName, right)
	llvmOp := "or"
	if exclusive {
		llvmOp = "xor"
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s %s %s, %%%s\n", result, llvmOp, typeName, left, inverted)
	value := "%" + result
	if word {
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", wide, value)
		value = "%" + wide
	}
	return true, false, c.storeReg(destination.Reg, value)
}

// --- arm64_lower_multiply_accumulate.go ---
type arm64MultiplyAccumulateSpec struct {
	word, long, signed, subtract bool
}

// The complete Go AMADD row: four C_ZREG operands in Rm, Ra, Rn, Rd order.
var arm64MultiplyAccumulateOps = map[Op]arm64MultiplyAccumulateSpec{
	"MADD":   {},
	"MSUB":   {subtract: true},
	"MADDW":  {word: true},
	"MSUBW":  {word: true, subtract: true},
	"SMADDL": {long: true, signed: true},
	"SMSUBL": {long: true, signed: true, subtract: true},
	"UMADDL": {long: true},
	"UMSUBL": {long: true, subtract: true},
}

func (c *arm64Ctx) lowerARM64MultiplyAccumulate(spec arm64MultiplyAccumulateSpec, ins Instr) error {
	// Read all inputs before writing Rd: it may alias any source. In Go
	// syntax the middle source is the addend, not the second multiplicand.
	if spec.long {
		return c.lowerARM64MultiplyAddLong(spec.signed, spec.subtract,
			ins.Args[0], ins.Args[2], ins.Args[1], ins.Args[3].Reg)
	}
	evaluate := func(operand Operand) (string, error) {
		if spec.word {
			return c.eval32(operand)
		}
		return c.eval64(operand, false)
	}
	m, err := evaluate(ins.Args[0])
	if err != nil {
		return err
	}
	a, err := evaluate(ins.Args[1])
	if err != nil {
		return err
	}
	n, err := evaluate(ins.Args[2])
	if err != nil {
		return err
	}
	width := "i64"
	if spec.word {
		width = "i32"
	}
	operation := "add"
	if spec.subtract {
		operation = "sub"
	}
	product, result := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = mul %s %s, %s\n", product, width, m, n)
	fmt.Fprintf(c.b, "  %%%s = %s %s %s, %%%s\n", result, operation, width, a, product)
	if spec.word {
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", wide, result)
		result = wide
	}
	return c.storeReg(ins.Args[3].Reg, "%"+result)
}

// --- arm64_lower_pc_relative.go ---
func (c *arm64Ctx) lowerPCRelativeAddress(bi int, op Op, ins Instr) (ok bool, terminated bool, err error) {
	switch op {
	case "ADR", "ADRP":
	default:
		return false, false, nil
	}
	if strings.Contains(strings.ToUpper(string(ins.Op)), ".") {
		return true, false, fmt.Errorf("arm64 %s does not accept a suffix: %q", op, ins.Raw)
	}
	if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg || !isARM64GeneralOrZeroReg(ins.Args[1].Reg) {
		return true, false, fmt.Errorf("arm64 %s expects label|n(PC), general register: %q", op, ins.Raw)
	}

	target, targetOK := c.resolveBranchTarget(bi, ins.Args[0])
	if !targetOK || (ins.Args[0].Kind != OpIdent && ins.Args[0].Kind != OpSym &&
		(ins.Args[0].Kind != OpMem || ins.Args[0].Mem.Base != PC)) {
		return true, false, fmt.Errorf("arm64 %s expects label|n(PC), general register: %q", op, ins.Raw)
	}
	if ins.Args[0].Kind == OpSym && strings.HasSuffix(ins.Args[0].Sym, "(SB)") {
		return true, false, fmt.Errorf("arm64 %s expects a local label or n(PC): %q", op, ins.Raw)
	}

	value, err := c.arm64LocalPCAddress(target, op, ins.Raw)
	if err != nil {
		return true, false, err
	}
	if op == "ADRP" {
		page := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %s, -4096\n", page, value)
		value = "%" + page
	}
	return true, false, c.storeReg(ins.Args[1].Reg, value)
}

func (c *arm64Ctx) arm64LocalPCAddress(target string, op Op, source string) (string, error) {
	knownTarget := false
	for _, block := range c.blocks {
		if block.name == target {
			knownTarget = true
			break
		}
	}
	if !knownTarget {
		return "", fmt.Errorf("arm64 %s undefined local target %q: %q", op, target, source)
	}

	address := c.newTmp()
	if pointer, ok := c.arm64RawDataPointer(target); ok {
		fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i64\n", address, pointer)
	} else {
		fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr blockaddress(%s, %%%s) to i64\n", address, llvmGlobal(c.sig.Name), arm64LLVMBlockName(target))
	}
	return "%" + address, nil
}

func (c *arm64Ctx) arm64RawDataPointer(target string) (string, bool) {
	global, ok := c.rawDataGlobals[target]
	if !ok {
		return "", false
	}
	pointer := llvmGlobal(global)
	if offset := c.rawDataOffsets[target]; offset != 0 {
		pointer = fmt.Sprintf("getelementptr (i8, ptr %s, i64 %d)", pointer, offset)
	}
	return pointer, true
}

// --- arm64_lower_shift_left.go ---
// lowerARM64VectorShiftLeft implements Go's complete AVSHL immediate optab
// row for all seven accepted 64- and 128-bit vector arrangements.
func (c *arm64Ctx) lowerARM64VectorShiftLeft(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "VSHL" {
		return false, false, nil
	}
	form, err := parseARM64VectorShift(op, ins)
	if err != nil {
		return true, false, err
	}
	sourceArrangement, shift := form.arrangement, form.shift
	source, err := c.loadARM64VectorInteger(ins.Args[1].Reg, sourceArrangement)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shl <%d x i%d> %s, %s\n", result, sourceArrangement.lanes, sourceArrangement.elementBits, source, arm64VectorIntegerSplat(sourceArrangement, shift))
	return true, false, c.storeARM64VectorInteger(form.destination, sourceArrangement, "%"+result)
}

// --- arm64_lower_shift_narrow.go ---
func (c *arm64Ctx) lowerARM64VectorShiftNarrow(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "VSHRN" && op != "VSHRN2" && op != "VRSHRN" && op != "VRSHRN2" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 ||
		ins.Args[0].Kind != OpImm || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
		return true, false, fmt.Errorf("arm64 %s expects immediate, wide vector source, narrow vector destination, and no suffix: %q", op, ins.Raw)
	}

	sourceArrangement, sourceOK := parseARM64VectorArrangement(ins.Args[1].Reg)
	destinationArrangement, destinationOK := parseARM64VectorArrangement(ins.Args[2].Reg)
	highHalf := op == "VSHRN2" || op == "VRSHRN2"
	rounding := op == "VRSHRN" || op == "VRSHRN2"
	wantDestinationLanes := sourceArrangement.lanes
	if highHalf {
		wantDestinationLanes *= 2
	}
	shift := ins.Args[0].Imm
	if !sourceOK || !destinationOK ||
		sourceArrangement.lanes*sourceArrangement.elementBits != 128 ||
		sourceArrangement.elementBits != destinationArrangement.elementBits*2 ||
		destinationArrangement.lanes != wantDestinationLanes ||
		shift < 1 || shift > int64(destinationArrangement.elementBits) {
		return true, false, fmt.Errorf("arm64 %s requires $1..$N with H8->B8/S4->H4/D2->S2 (or the doubled *2 destination): %q", op, ins.Raw)
	}

	source, err := c.loadARM64VectorInteger(ins.Args[1].Reg, sourceArrangement)
	if err != nil {
		return true, false, err
	}
	sourceType := fmt.Sprintf("<%d x i%d>", sourceArrangement.lanes, sourceArrangement.elementBits)
	shifted := c.newTmp()
	shiftValue := arm64VectorIntegerSplat(sourceArrangement, shift)
	if rounding {
		// RSHRN rounds the signed source before narrowing. The addition is
		// intentionally wrapping at the source width, matching the ARM
		// instruction's two's-complement operation for non-saturating forms.
		bias := arm64VectorIntegerSplat(sourceArrangement, int64(1)<<(shift-1))
		rounded := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add %s %s, %s\n", rounded, sourceType, source, bias)
		fmt.Fprintf(c.b, "  %%%s = ashr %s %%%s, %s\n", shifted, sourceType, rounded, shiftValue)
	} else {
		fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %s\n", shifted, sourceType, source, shiftValue)
	}
	destinationType := fmt.Sprintf("<%d x i%d>", sourceArrangement.lanes, destinationArrangement.elementBits)
	narrowed := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to %s\n", narrowed, sourceType, shifted, destinationType)
	if !highHalf {
		return true, false, c.storeARM64VectorInteger(ins.Args[2].Reg, destinationArrangement, "%"+narrowed)
	}

	// VSHRN2 preserves the existing low half and inserts the narrowed values
	// into the high half of the destination vector.
	result, err := c.loadARM64VectorInteger(ins.Args[2].Reg, destinationArrangement)
	if err != nil {
		return true, false, err
	}
	fullDestinationType := fmt.Sprintf("<%d x i%d>", destinationArrangement.lanes, destinationArrangement.elementBits)
	for lane := 0; lane < sourceArrangement.lanes; lane++ {
		element := c.newTmp()
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %%%s, i32 %d\n", element, destinationType, narrowed, lane)
		fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, i%d %%%s, i32 %d\n",
			inserted, fullDestinationType, result, destinationArrangement.elementBits, element, sourceArrangement.lanes+lane)
		result = "%" + inserted
	}
	return true, false, c.storeARM64VectorInteger(ins.Args[2].Reg, destinationArrangement, result)
}

// --- arm64_lower_signed_lane.go ---
// ARM64's SMOV family extracts a signed vector lane into a general register.
// The 32-bit destination form accepts byte and halfword lanes; the 64-bit
// destination form also accepts word lanes. A W-register write clears the
// upper half of the physical X register after sign-extending within 32 bits.
func (c *arm64Ctx) lowerARM64SignedLaneExtract(op Op, ins Instr) (bool, bool, error) {
	wide := false
	switch op {
	case "SMOV":
		wide = true
	case "SMOVW":
	default:
		return false, false, nil
	}

	if len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("arm64 %s expects a vector lane and general register: %q", op, ins.Raw)
	}
	source, destination := ins.Args[0].Reg, ins.Args[1].Reg
	if _, ok := arm64ParseVReg(source); !ok || !isARM64GeneralOrZeroReg(destination) {
		return true, false, fmt.Errorf("arm64 %s requires a vector lane and general register: %q", op, ins.Raw)
	}
	kind, lane, ok := arm64ParseVRegLane(source)
	if !ok {
		return true, false, fmt.Errorf("arm64 %s requires a valid vector lane: %q", op, ins.Raw)
	}
	bits := 0
	lanes := 0
	switch kind {
	case 'B':
		bits, lanes = 8, 16
	case 'H':
		bits, lanes = 16, 8
	case 'S':
		if wide {
			bits, lanes = 32, 4
		}
	}
	if bits == 0 {
		return true, false, fmt.Errorf("arm64 %s has an invalid lane width: %q", op, ins.Raw)
	}

	vector, err := c.loadVReg(source)
	if err != nil {
		return true, false, err
	}
	lanesValue := vector
	if bits != 8 {
		bitcast := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <%d x i%d>\n", bitcast, vector, lanes, bits)
		lanesValue = "%" + bitcast
	}
	extracted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %s, i32 %d\n", extracted, lanes, bits, lanesValue, lane)

	value := "%" + extracted
	if wide {
		extended := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sext i%d %s to i64\n", extended, bits, value)
		value = "%" + extended
	} else {
		signedWord := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sext i%d %s to i32\n", signedWord, bits, value)
		clearedUpper := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", clearedUpper, signedWord)
		value = "%" + clearedUpper
	}
	return true, false, c.storeReg(destination, value)
}

// --- arm64_lower_sve_aes_mix.go ---
var arm64SVEAESMixIntrinsics = map[Op]string{
	"ZAESIMC": "aesimc",
	"ZAESMC":  "aesmc",
}

func (c *arm64Ctx) lowerARM64SVEAESMix(op Op, ins Instr) (ok bool, terminated bool, err error) {
	intrinsic, ok := arm64SVEAESMixIntrinsics[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 {
		return true, false, fmt.Errorf("arm64 %s expects Zdn.B, Zdn.B without a suffix: %q", op, ins.Raw)
	}
	first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[0])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[1])
	if !firstOK || !destinationOK || firstBits != 8 || destinationBits != 8 || first != destination {
		return true, false, fmt.Errorf("arm64 %s requires the same B-element source/destination register: %q", op, ins.Raw)
	}
	value, vectorType, err := c.loadZRegElements(destination, 8)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s(%s %s)\n", result, vectorType, intrinsic, vectorType, value)
	return true, false, c.storeZRegElements(destination, 8, "%"+result)
}

// --- arm64_lower_sve_bfdot.go ---
type arm64SVEBFDOTForm struct {
	first       int
	second      int
	destination int
	lane        int
	indexed     bool
}

func (c *arm64Ctx) lowerARM64SVEBFDOT(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZBFDOT" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 ZBFDOT expects one complete Go 1.27 form without a suffix: %q", ins.Raw)
	}
	form := arm64SVEBFDOTForm{}
	if first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[0]); firstOK {
		if firstBits != 16 {
			return true, false, fmt.Errorf("arm64 ZBFDOT vector source must use H elements: %q", ins.Raw)
		}
		form.first = first
	} else {
		first, firstBits, lane, firstOK := arm64ParseSVEZIndexedElementRegUnbounded(ins.Args[0])
		if !firstOK || firstBits != 16 || first > 7 || lane > 3 {
			return true, false, fmt.Errorf("arm64 ZBFDOT indexed source must use Z0..Z7.H[0..3]: %q", ins.Raw)
		}
		form.first = first
		form.lane = lane
		form.indexed = true
	}
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[1])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	if !secondOK || secondBits != 16 || !destinationOK || destinationBits != 32 {
		return true, false, fmt.Errorf("arm64 ZBFDOT operands must use H source elements and an S accumulator: %q", ins.Raw)
	}
	form.second = second
	form.destination = destination
	return true, false, c.lowerARM64SVEBFDOTForm(form)
}

func (c *arm64Ctx) lowerARM64SVEBFDOTForm(form arm64SVEBFDOTForm) error {
	accumulator, accumulatorType, err := c.loadRawSVEFloatVector(form.destination, 32)
	if err != nil {
		return err
	}
	loadBFloat := func(register int) (string, error) {
		integer, integerType, err := c.loadZRegElements(register, 16)
		if err != nil {
			return "", err
		}
		converted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <vscale x 8 x bfloat>\n", converted, integerType, integer)
		return "%" + converted, nil
	}
	second, err := loadBFloat(form.second)
	if err != nil {
		return err
	}
	first, err := loadBFloat(form.first)
	if err != nil {
		return err
	}
	result := c.newTmp()
	if form.indexed {
		fmt.Fprintf(c.b, "  %%%s = call <vscale x 4 x float> @llvm.aarch64.sve.bfdot.lane.v2(<vscale x 4 x float> %s, <vscale x 8 x bfloat> %s, <vscale x 8 x bfloat> %s, i32 %d)\n", result, accumulator, second, first, form.lane)
	} else {
		fmt.Fprintf(c.b, "  %%%s = call <vscale x 4 x float> @llvm.aarch64.sve.bfdot(<vscale x 4 x float> %s, <vscale x 8 x bfloat> %s, <vscale x 8 x bfloat> %s)\n", result, accumulator, second, first)
	}
	return c.storeRawSVEFloatVector(form.destination, 32, "%"+result, accumulatorType)
}

// --- arm64_lower_sve_bit_permute.go ---
var arm64SVEBitPermuteIntrinsics = map[Op]string{
	"ZBDEP": "bdep.x",
	"ZBEXT": "bext.x",
	"ZBGRP": "bgrp.x",
}

func (c *arm64Ctx) lowerARM64SVEBitPermute(op Op, ins Instr) (ok bool, terminated bool, err error) {
	intrinsic, ok := arm64SVEBitPermuteIntrinsics[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects Zm.T, Zn.T, Zd.T without a suffix: %q", op, ins.Raw)
	}
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
	first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	if !secondOK || !firstOK || !destinationOK || firstBits != secondBits || destinationBits != firstBits {
		return true, false, fmt.Errorf("arm64 %s requires matching B/H/S/D operands: %q", op, ins.Raw)
	}
	firstValue, vectorType, err := c.loadZRegElements(first, firstBits)
	if err != nil {
		return true, false, err
	}
	secondValue, _, err := c.loadZRegElements(second, firstBits)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / firstBits
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s)\n", result, vectorType, intrinsic, lanes, firstBits, vectorType, firstValue, vectorType, secondValue)
	return true, false, c.storeZRegElements(destination, firstBits, "%"+result)
}

// --- arm64_lower_sve_carry_long.go ---
var arm64SVECarryLongIntrinsics = map[Op]string{
	"ZADCLB": "adclb",
	"ZADCLT": "adclt",
	"ZSBCLB": "sbclb",
	"ZSBCLT": "sbclt",
}

func (c *arm64Ctx) lowerARM64SVECarryLong(op Op, ins Instr) (ok bool, terminated bool, err error) {
	intrinsic, ok := arm64SVECarryLongIntrinsics[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects Zm.S|D, Zn.S|D, Zda.S|D without a suffix: %q", op, ins.Raw)
	}
	third, thirdBits, thirdOK := arm64ParseSVEZElementReg(ins.Args[0])
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[1])
	accumulator, accumulatorBits, accumulatorOK := arm64ParseSVEZElementReg(ins.Args[2])
	if !thirdOK || !secondOK || !accumulatorOK || (accumulatorBits != 32 && accumulatorBits != 64) || secondBits != accumulatorBits || thirdBits != accumulatorBits {
		return true, false, fmt.Errorf("arm64 %s requires matching S/D operands: %q", op, ins.Raw)
	}
	accumulatorValue, vectorType, err := c.loadZRegElements(accumulator, accumulatorBits)
	if err != nil {
		return true, false, err
	}
	secondValue, _, err := c.loadZRegElements(second, accumulatorBits)
	if err != nil {
		return true, false, err
	}
	thirdValue, _, err := c.loadZRegElements(third, accumulatorBits)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / accumulatorBits
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s, %s %s)\n", result, vectorType, intrinsic, lanes, accumulatorBits, vectorType, accumulatorValue, vectorType, secondValue, vectorType, thirdValue)
	return true, false, c.storeZRegElements(accumulator, accumulatorBits, "%"+result)
}

// --- arm64_lower_sve_cdot.go ---
type arm64SVECDOTForm struct {
	first, second, destination  int
	sourceBits, destinationBits int
	rotation                    int
	lane                        int
	indexed                     bool
}

func (c *arm64Ctx) lowerARM64SVECDOT(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZCDOT" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 4 || ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" || ins.Args[0].ImmIsFloat {
		return true, false, fmt.Errorf("arm64 ZCDOT expects $0|$90|$180|$270 and one complete Go 1.27 vector or indexed form: %q", ins.Raw)
	}
	rotation := int(ins.Args[0].Imm)
	if rotation != 0 && rotation != 90 && rotation != 180 && rotation != 270 {
		return true, false, fmt.Errorf("arm64 ZCDOT rotation must be $0, $90, $180, or $270: %q", ins.Raw)
	}
	form := arm64SVECDOTForm{rotation: rotation}
	if first, sourceBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1]); firstOK {
		form.first, form.sourceBits = first, sourceBits
	} else {
		first, sourceBits, lane, firstOK := arm64ParseSVEZIndexedElementRegUnbounded(ins.Args[1])
		if !firstOK {
			return true, false, fmt.Errorf("arm64 ZCDOT requires a B/H vector or indexed source: %q", ins.Raw)
		}
		form.first, form.sourceBits, form.lane, form.indexed = first, sourceBits, lane, true
	}
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[2])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[3])
	validWidths := (form.sourceBits == 8 && destinationBits == 32) || (form.sourceBits == 16 && destinationBits == 64)
	if !secondOK || !destinationOK || secondBits != form.sourceBits || !validWidths {
		return true, false, fmt.Errorf("arm64 ZCDOT requires B sources with an S accumulator or H sources with a D accumulator: %q", ins.Raw)
	}
	if form.indexed {
		maxRegister, maxLane := 7, 3
		if form.sourceBits == 16 {
			maxRegister, maxLane = 15, 1
		}
		if form.first > maxRegister || form.lane > maxLane {
			return true, false, fmt.Errorf("arm64 ZCDOT indexed source exceeds its register or lane range: %q", ins.Raw)
		}
	}
	form.second, form.destination, form.destinationBits = second, destination, destinationBits
	return true, false, c.lowerARM64SVECDOTForm(form)
}

func (c *arm64Ctx) lowerARM64SVECDOTForm(form arm64SVECDOTForm) error {
	accumulator, accumulatorType, err := c.loadZRegElements(form.destination, form.destinationBits)
	if err != nil {
		return err
	}
	first, sourceType, err := c.loadZRegElements(form.first, form.sourceBits)
	if err != nil {
		return err
	}
	second, _, err := c.loadZRegElements(form.second, form.sourceBits)
	if err != nil {
		return err
	}
	lanes := 128 / form.destinationBits
	result := c.newTmp()
	if form.indexed {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.cdot.lane.nxv%di%d(%s %s, %s %s, %s %s, i32 %d, i32 %d)\n", result, accumulatorType, lanes, form.destinationBits, accumulatorType, accumulator, sourceType, second, sourceType, first, form.lane, form.rotation)
	} else {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.cdot.nxv%di%d(%s %s, %s %s, %s %s, i32 %d)\n", result, accumulatorType, lanes, form.destinationBits, accumulatorType, accumulator, sourceType, second, sourceType, first, form.rotation)
	}
	return c.storeZRegElements(form.destination, form.destinationBits, "%"+result)
}

// --- arm64_lower_sve_character_match.go ---
var arm64SVECharacterMatchIntrinsics = map[Op]string{
	"ZMATCH":  "match",
	"ZNMATCH": "nmatch",
}

// decodeARM64RawSVECharacterMatch mirrors Go 1.27's ZMATCH/ZNMATCH B/H
// encoder rows. Only the two element sizes and the predicate/register fields
// vary; the remaining bits must match the architecture encoding exactly.
func decodeARM64RawSVECharacterMatch(word uint32) (Instr, bool) {
	const (
		base        = uint32(0x45208000)
		operandBits = uint32(0x005f1fff)
		negativeBit = uint32(1 << 4)
		halfwordBit = uint32(1 << 22)
	)
	if word&^operandBits != base {
		return Instr{}, false
	}

	op := Op("ZMATCH")
	if word&negativeBit != 0 {
		op = "ZNMATCH"
	}
	element := "B"
	if word&halfwordBit != 0 {
		element = "H"
	}
	second := int(word>>16) & 31
	first := int(word>>5) & 31
	governing := int(word>>10) & 7
	destination := int(word) & 15
	args := []Operand{
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%s", second, element))},
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%s", first, element))},
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d.Z", governing))},
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d.%s", destination, element))},
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("WORD $%#08x", word)}, true
}

func (c *arm64Ctx) lowerARM64SVECharacterMatch(op Op, ins Instr) (ok bool, terminated bool, err error) {
	intrinsic, ok := arm64SVECharacterMatchIntrinsics[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 4 {
		return true, false, fmt.Errorf("arm64 %s expects Zm.B|H, Zn.B|H, Pg/Z, Pd.B|H without a suffix: %q", op, ins.Raw)
	}
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
	first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
	governing, governingOK := arm64ParseSVEPredicateMode(ins.Args[2], "Z", 7)
	destination, destinationBits, destinationOK := arm64ParseSVEPredicateElement(ins.Args[3])
	if !secondOK || !firstOK || !governingOK || !destinationOK || (firstBits != 8 && firstBits != 16) || secondBits != firstBits || destinationBits != firstBits {
		return true, false, fmt.Errorf("arm64 %s requires matching B/H vectors and result predicate under P0..P7/Z: %q", op, ins.Raw)
	}
	governingValue, predicateType, err := c.loadPRegElements(governing, firstBits)
	if err != nil {
		return true, false, err
	}
	firstValue, vectorType, err := c.loadZRegElements(first, firstBits)
	if err != nil {
		return true, false, err
	}
	secondValue, _, err := c.loadZRegElements(second, secondBits)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / firstBits
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s, %s %s)\n", result, predicateType, intrinsic, lanes, firstBits, predicateType, governingValue, vectorType, firstValue, vectorType, secondValue)
	return true, false, c.storePRegElements(destination, destinationBits, "%"+result)
}

// --- arm64_lower_sve_compact.go ---
func decodeARM64RawSVECompact(word uint32) (Instr, bool) {
	// The B/H (SVE2.2) and S/D (SVE) rows differ only in size[23:22].
	if word&0xff3fe000 != 0x05218000 {
		return Instr{}, false
	}
	width := "BHSD"[word>>22&3]
	return Instr{Op: "ZCOMPACT", Raw: fmt.Sprintf("WORD $%#08x", word), Args: []Operand{
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", word>>5&31, width))},
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d", word>>10&7))},
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", word&31, width))},
	}}, true
}

func arm64SVECompactNeedsSVE2P2(ins Instr) bool {
	if len(ins.Args) != 3 {
		return false
	}
	_, bits, ok := arm64ParseSVEZElementReg(ins.Args[0])
	return ok && bits <= 16
}

func (c *arm64Ctx) lowerARM64SVECompact(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZCOMPACT" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 ZCOMPACT expects Zn.T, Pg, Zd.T without a suffix: %q", ins.Raw)
	}
	source, sourceBits, sourceOK := arm64ParseSVEZElementReg(ins.Args[0])
	predicate, predicateOK := arm64ParseSVEPredicateBare(ins.Args[1], 7)
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	if !sourceOK || !predicateOK || !destinationOK || sourceBits != destinationBits {
		return true, false, fmt.Errorf("arm64 ZCOMPACT requires matching B/H/S/D vectors and P0..P7: %q", ins.Raw)
	}
	predicateValue, predicateType, err := c.loadPRegElements(predicate, sourceBits)
	if err != nil {
		return true, false, err
	}
	sourceValue, vectorType, err := c.loadZRegElements(source, sourceBits)
	if err != nil {
		return true, false, err
	}
	_, lanes, err := arm64SVEVectorType(sourceBits)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.compact.nxv%di%d(%s %s, %s %s)\n",
		result, vectorType, lanes, sourceBits, predicateType, predicateValue, vectorType, sourceValue)
	return true, false, c.storeZRegElements(destination, sourceBits, "%"+result)
}

// --- arm64_lower_sve_complex_add.go ---
var arm64SVEComplexAddIntrinsics = map[Op]string{
	"ZCADD":   "cadd.x",
	"ZSQCADD": "sqcadd.x",
}

func (c *arm64Ctx) lowerARM64SVEComplexAdd(op Op, ins Instr) (ok bool, terminated bool, err error) {
	intrinsic, ok := arm64SVEComplexAddIntrinsics[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 4 || ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" {
		return true, false, fmt.Errorf("arm64 %s expects $90|$270, Zm.T, Zdn.T, Zdn.T without a suffix: %q", op, ins.Raw)
	}
	rotation := ins.Args[0].Imm
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[1])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	repeatedDestination, repeatedBits, repeatedOK := arm64ParseSVEZElementReg(ins.Args[3])
	if (rotation != 90 && rotation != 270) || !secondOK || !destinationOK || !repeatedOK || secondBits != destinationBits || repeatedBits != destinationBits || repeatedDestination != destination {
		return true, false, fmt.Errorf("arm64 %s requires rotation $90/$270 and matching destructive B/H/S/D operands: %q", op, ins.Raw)
	}
	destinationValue, vectorType, err := c.loadZRegElements(destination, destinationBits)
	if err != nil {
		return true, false, err
	}
	secondValue, _, err := c.loadZRegElements(second, secondBits)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / destinationBits
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s, i32 %d)\n", result, vectorType, intrinsic, lanes, destinationBits, vectorType, destinationValue, vectorType, secondValue, rotation)
	return true, false, c.storeZRegElements(destination, destinationBits, "%"+result)
}

// --- arm64_lower_sve_divide.go ---
var arm64SVEDivideIntrinsics = map[Op]string{
	"ZSDIV":  "sdiv",
	"ZSDIVR": "sdivr",
	"ZUDIV":  "udiv",
	"ZUDIVR": "udivr",
}

func (c *arm64Ctx) lowerARM64SVEDivide(op Op, ins Instr) (ok bool, terminated bool, err error) {
	intrinsic, ok := arm64SVEDivideIntrinsics[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 4 {
		return true, false, fmt.Errorf("arm64 %s expects Zm.S|D, Zdn.S|D, P0..P7/M, Zdn.S|D without a suffix: %q", op, ins.Raw)
	}
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
	first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
	predicate, predicateOK := arm64ParseSVEPredicateMerge(ins.Args[2])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[3])
	if !secondOK || !firstOK || !predicateOK || !destinationOK || (firstBits != 32 && firstBits != 64) || secondBits != firstBits || destinationBits != firstBits || destination != first {
		return true, false, fmt.Errorf("arm64 %s requires matching-width destructive S/D operands and P0..P7/M: %q", op, ins.Raw)
	}
	firstValue, vectorType, err := c.loadZRegElements(first, firstBits)
	if err != nil {
		return true, false, err
	}
	secondValue, _, err := c.loadZRegElements(second, firstBits)
	if err != nil {
		return true, false, err
	}
	predicateValue, predicateType, err := c.loadPRegElements(predicate, firstBits)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / firstBits
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s, %s %s)\n", result, vectorType, intrinsic, lanes, firstBits, predicateType, predicateValue, vectorType, firstValue, vectorType, secondValue)
	return true, false, c.storeZRegElements(destination, firstBits, "%"+result)
}

// --- arm64_lower_sve_dup_general.go ---
type arm64RawSVEDupGeneral struct {
	elementBits int
	source      int
	destination int
}

// decodeARM64RawSVEDupGeneral covers the complete SVE DUP (general) encoding:
// DUP Zd.T, Rn, where T is B/H/S/D and R31 denotes SP (not ZR).
func decodeARM64RawSVEDupGeneral(word uint32) (arm64RawSVEDupGeneral, bool) {
	if word&0xff3ffc00 != 0x05203800 {
		return arm64RawSVEDupGeneral{}, false
	}
	return arm64RawSVEDupGeneral{
		elementBits: 8 << (int(word>>22) & 3),
		source:      int(word>>5) & 31,
		destination: int(word) & 31,
	}, true
}

func (c *arm64Ctx) lowerRawSVEDupGeneral(form arm64RawSVEDupGeneral) error {
	reg := Reg(fmt.Sprintf("R%d", form.source))
	if form.source == 31 {
		reg = SP
	}
	source, err := c.loadReg(reg)
	if err != nil {
		return err
	}
	if form.elementBits != 64 {
		narrowed := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i%d\n", narrowed, source, form.elementBits)
		source = "%" + narrowed
	}
	lanes := 128 / form.elementBits
	vectorType := fmt.Sprintf("<vscale x %d x i%d>", lanes, form.elementBits)
	inserted := c.newTmp()
	splat := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement %s poison, i%d %s, i64 0\n", inserted, vectorType, form.elementBits, source)
	fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s poison, <vscale x %d x i32> zeroinitializer\n", splat, vectorType, inserted, vectorType, lanes)
	bytes := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <vscale x 16 x i8>\n", bytes, vectorType, splat)
	return c.storeZReg(form.destination, "%"+bytes)
}

// --- arm64_lower_sve_dupm.go ---
func (c *arm64Ctx) lowerARM64SVEDupM(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZDUPM" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 || ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" || ins.Args[0].ImmIsFloat {
		return true, false, fmt.Errorf("arm64 ZDUPM expects a resolved logical bitmask immediate and Zd.B|H|S|D without a suffix: %q", ins.Raw)
	}
	destination, elementBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[1])
	immediate := uint64(ins.Args[0].Imm)
	if !destinationOK || !arm64SVELogicalImmediateRepresentable(elementBits, immediate) {
		return true, false, fmt.Errorf("arm64 ZDUPM immediate is not a Go logical bitmask for the destination width: %q", ins.Raw)
	}
	immediate &= arm64SVEMaskForBits(elementBits)
	value := fmt.Sprintf("splat (i%d %d)", elementBits, immediate)
	return true, false, c.storeZRegElements(destination, elementBits, value)
}

// --- arm64_lower_sve_dupq.go ---
func (c *arm64Ctx) lowerARM64SVEDupQ(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZDUPQ" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 {
		return true, false, fmt.Errorf("arm64 ZDUPQ expects Zn.B|H|S|D[index], Zd.B|H|S|D without a suffix: %q", ins.Raw)
	}
	source, elementBits, lane, sourceOK := arm64ParseSVEDupElementReg(ins.Args[0])
	destination, destinationBits, destinationOK := arm64ParseSVEDupDestination(ins.Args[1], false)
	if !sourceOK || !destinationOK || elementBits == 128 || elementBits != destinationBits || lane >= 128/elementBits {
		return true, false, fmt.Errorf("arm64 ZDUPQ requires matching B/H/S/D widths and an index within one 128-bit segment: %q", ins.Raw)
	}
	sourceValue, vectorType, err := c.loadZRegElements(source, elementBits)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / elementBits
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.dupq.lane.nxv%di%d(%s %s, i64 %d)\n", result, vectorType, lanes, elementBits, vectorType, sourceValue, lane)
	return true, false, c.storeZRegElements(destination, elementBits, "%"+result)
}

// --- arm64_lower_sve_dupw.go ---
func (c *arm64Ctx) lowerARM64SVEDupW(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZDUPW" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 {
		return true, false, fmt.Errorf("arm64 ZDUPW expects Rn|RSP, Zd.B|H|S|D without a suffix: %q", ins.Raw)
	}
	source, sourceOK := arm64ParseSVEDupGeneralSource(ins.Args[0])
	destination, elementBits, destinationOK := arm64ParseSVEDupDestination(ins.Args[1], false)
	if !sourceOK || !destinationOK {
		return true, false, fmt.Errorf("arm64 ZDUPW requires R0..R30 or RSP and a B/H/S/D destination: %q", ins.Raw)
	}
	return true, false, c.lowerRawSVEDupGeneral(arm64RawSVEDupGeneral{elementBits: elementBits, source: source, destination: destination})
}

// --- arm64_lower_sve_eor_interleave.go ---
var arm64SVEEORInterleaveIntrinsics = map[Op]string{
	"ZEORBT": "eorbt",
	"ZEORTB": "eortb",
}

func (c *arm64Ctx) lowerARM64SVEEORInterleave(op Op, ins Instr) (ok bool, terminated bool, err error) {
	intrinsic, ok := arm64SVEEORInterleaveIntrinsics[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects Zm.T, Zn.T, Zd.T without a suffix: %q", op, ins.Raw)
	}
	third, thirdBits, thirdOK := arm64ParseSVEZElementReg(ins.Args[0])
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[1])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	if !thirdOK || !secondOK || !destinationOK || thirdBits != secondBits || secondBits != destinationBits {
		return true, false, fmt.Errorf("arm64 %s operands must use one matching B/H/S/D width: %q", op, ins.Raw)
	}
	firstValue, vectorType, err := c.loadZRegElements(destination, destinationBits)
	if err != nil {
		return true, false, err
	}
	secondValue, _, err := c.loadZRegElements(second, destinationBits)
	if err != nil {
		return true, false, err
	}
	thirdValue, _, err := c.loadZRegElements(third, destinationBits)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / destinationBits
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s, %s %s)\n", result, vectorType, intrinsic, lanes, destinationBits, vectorType, firstValue, vectorType, secondValue, vectorType, thirdValue)
	return true, false, c.storeZRegElements(destination, destinationBits, "%"+result)
}

// --- arm64_lower_sve_expand.go ---
func (c *arm64Ctx) lowerARM64SVEExpand(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZEXPAND" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 ZEXPAND expects Zn.B|H|S|D, Pg, Zd.B|H|S|D without a suffix: %q", ins.Raw)
	}
	source, sourceBits, sourceOK := arm64ParseSVEZElementReg(ins.Args[0])
	predicate, predicateOK := arm64ParseSVEPredicateBare(ins.Args[1], 7)
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	if !sourceOK || !predicateOK || !destinationOK || sourceBits != destinationBits {
		return true, false, fmt.Errorf("arm64 ZEXPAND requires matching B/H/S/D vectors and a bare P0..P7 predicate: %q", ins.Raw)
	}
	predicateValue, predicateType, err := c.loadPRegElements(predicate, sourceBits)
	if err != nil {
		return true, false, err
	}
	sourceValue, vectorType, err := c.loadZRegElements(source, sourceBits)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / sourceBits
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.expand.nxv%di%d(%s %s, %s %s)\n", result, vectorType, lanes, sourceBits, predicateType, predicateValue, vectorType, sourceValue)
	return true, false, c.storeZRegElements(destination, destinationBits, "%"+result)
}

// --- arm64_lower_sve_float_complex_add.go ---
func (c *arm64Ctx) lowerARM64SVEFloatComplexAdd(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZFCADD" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 5 || ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" || ins.Args[0].ImmIsFloat {
		return true, false, fmt.Errorf("arm64 ZFCADD expects $90|$270, Zm.H|S|D, Zdn.H|S|D, P0..P7/M, Zdn.H|S|D without a suffix: %q", ins.Raw)
	}
	rotation := ins.Args[0].Imm
	second, secondBits, secondOK := arm64SVEFloatElementReg(ins.Args[1])
	first, firstBits, firstOK := arm64SVEFloatElementReg(ins.Args[2])
	predicate, predicateOK := arm64ParseSVEPredicateMode(ins.Args[3], "M", 7)
	destination, destinationBits, destinationOK := arm64SVEFloatElementReg(ins.Args[4])
	if (rotation != 90 && rotation != 270) || !secondOK || !firstOK || !predicateOK || !destinationOK || secondBits != firstBits || destinationBits != firstBits || destination != first {
		return true, false, fmt.Errorf("arm64 ZFCADD requires rotation $90/$270, matching destructive H/S/D operands, and P0..P7/M: %q", ins.Raw)
	}
	firstValue, vectorType, err := c.loadRawSVEFloatVector(first, firstBits)
	if err != nil {
		return true, false, err
	}
	secondValue, _, err := c.loadRawSVEFloatVector(second, secondBits)
	if err != nil {
		return true, false, err
	}
	predicateValue, predicateType, err := c.loadPRegElements(predicate, firstBits)
	if err != nil {
		return true, false, err
	}
	_, _, lanes, err := arm64SVEFloatType(firstBits)
	if err != nil {
		return true, false, err
	}
	mangle := map[int]string{16: "f16", 32: "f32", 64: "f64"}[firstBits]
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.fcadd.nxv%d%s(%s %s, %s %s, %s %s, i32 %d)\n", result, vectorType, lanes, mangle, predicateType, predicateValue, vectorType, firstValue, vectorType, secondValue, rotation)
	selected := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select %s %s, %s %%%s, %s %s\n", selected, predicateType, predicateValue, vectorType, result, vectorType, firstValue)
	return true, false, c.storeRawSVEFloatVector(destination, firstBits, "%"+selected, vectorType)
}

// --- arm64_lower_sve_float_exponent.go ---
func (c *arm64Ctx) lowerARM64SVEFloatExponent(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZFEXPA" && op != "ZFLOGB" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) {
		return true, false, fmt.Errorf("arm64 %s does not accept a mnemonic suffix: %q", op, ins.Raw)
	}
	if op == "ZFEXPA" {
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("arm64 ZFEXPA expects Zn.H|S|D, Zd.H|S|D: %q", ins.Raw)
		}
		source, sourceBits, sourceOK := arm64ParseSVEZElementReg(ins.Args[0])
		destination, destinationBits, destinationOK := arm64SVEFloatElementReg(ins.Args[1])
		if !sourceOK || !destinationOK || sourceBits == 8 || sourceBits != destinationBits {
			return true, false, fmt.Errorf("arm64 ZFEXPA requires matching H/S/D source and destination widths: %q", ins.Raw)
		}
		sourceValue, integerType, err := c.loadZRegElements(source, sourceBits)
		if err != nil {
			return true, false, err
		}
		_, floatingType, lanes, err := arm64SVEFloatType(sourceBits)
		if err != nil {
			return true, false, err
		}
		mangle := map[int]string{16: "f16", 32: "f32", 64: "f64"}[sourceBits]
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.fexpa.x.nxv%d%s(%s %s)\n", result, floatingType, lanes, mangle, integerType, sourceValue)
		return true, false, c.storeRawSVEFloatVector(destination, destinationBits, "%"+result, floatingType)
	}
	if len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 ZFLOGB expects Zn.H|S|D, Pg/M|Z, Zd.H|S|D: %q", ins.Raw)
	}
	source, sourceBits, sourceOK := arm64SVEFloatElementReg(ins.Args[0])
	mergePredicate, mergeOK := arm64ParseSVEPredicateMode(ins.Args[1], "M", 7)
	zeroPredicate, zeroOK := arm64ParseSVEPredicateMode(ins.Args[1], "Z", 7)
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	if !sourceOK || (!mergeOK && !zeroOK) || !destinationOK || sourceBits != destinationBits {
		return true, false, fmt.Errorf("arm64 ZFLOGB requires matching H/S/D operands and P0..P7/M|Z: %q", ins.Raw)
	}
	predicate := mergePredicate
	if zeroOK {
		predicate = zeroPredicate
	}
	predicateValue, predicateType, err := c.loadPRegElements(predicate, sourceBits)
	if err != nil {
		return true, false, err
	}
	sourceValue, floatingType, err := c.loadRawSVEFloatVector(source, sourceBits)
	if err != nil {
		return true, false, err
	}
	passthrough := "zeroinitializer"
	integerType, lanes, err := arm64SVEVectorType(destinationBits)
	if err != nil {
		return true, false, err
	}
	if mergeOK {
		passthrough, _, err = c.loadZRegElements(destination, destinationBits)
		if err != nil {
			return true, false, err
		}
	}
	mangle := map[int]string{16: "f16", 32: "f32", 64: "f64"}[sourceBits]
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.flogb.nxv%d%s(%s %s, %s %s, %s %s)\n", result, integerType, lanes, mangle, integerType, passthrough, predicateType, predicateValue, floatingType, sourceValue)
	return true, false, c.storeZRegElements(destination, destinationBits, "%"+result)
}

// --- arm64_lower_sve_float_immediate.go ---
func (c *arm64Ctx) lowerARM64SVEFloatImmediate(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZFCPY" && op != "ZFDUP" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) {
		return true, false, fmt.Errorf("arm64 %s does not accept a mnemonic suffix: %q", op, ins.Raw)
	}
	wantArgs := 2
	if op == "ZFCPY" {
		wantArgs = 3
	}
	if len(ins.Args) != wantArgs || !arm64SVEFloatImmediateRepresentable(ins.Args[0]) {
		return true, false, fmt.Errorf("arm64 %s requires an encodable floating immediate and its complete Go 1.27 operand form: %q", op, ins.Raw)
	}
	destinationOperand := ins.Args[wantArgs-1]
	destination, elementBits, destinationOK := arm64SVEFloatElementReg(destinationOperand)
	if !destinationOK {
		return true, false, fmt.Errorf("arm64 %s destination must use H, S, or D elements: %q", op, ins.Raw)
	}
	value := math.Float64frombits(uint64(ins.Args[0].Imm))
	splat, err := c.arm64SVEFloatSplat(value, elementBits)
	if err != nil {
		return true, false, err
	}
	_, vectorType, _, err := arm64SVEFloatType(elementBits)
	if err != nil {
		return true, false, err
	}
	if op == "ZFDUP" {
		return true, false, c.storeRawSVEFloatVector(destination, elementBits, splat, vectorType)
	}
	predicate, predicateOK := arm64ParseSVEPredicateMode(ins.Args[1], "M", 15)
	if !predicateOK {
		return true, false, fmt.Errorf("arm64 ZFCPY requires P0..P15/M: %q", ins.Raw)
	}
	oldDestination, _, err := c.loadRawSVEFloatVector(destination, elementBits)
	if err != nil {
		return true, false, err
	}
	predicateValue, predicateType, err := c.loadPRegElements(predicate, elementBits)
	if err != nil {
		return true, false, err
	}
	selected := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select %s %s, %s %s, %s %s\n", selected, predicateType, predicateValue, vectorType, splat, vectorType, oldDestination)
	return true, false, c.storeRawSVEFloatVector(destination, elementBits, "%"+selected, vectorType)
}

// arm64SVEFloatImmediateRepresentable mirrors Go's chipfloat7 acceptance
// check: one sign bit, a 3-bit exponent, and four fractional bits expanded to
// an exact binary64 value. That is the full 256-value immediate domain shared
// by ZFCPY and ZFDUP.
func arm64SVEFloatImmediateRepresentable(operand Operand) bool {
	if operand.Kind != OpImm || operand.ImmRaw != "" || !operand.ImmIsFloat {
		return false
	}
	bits := math.Float64bits(math.Float64frombits(uint64(operand.Imm)))
	low := uint32(bits)
	high := uint32(bits >> 32)
	if low != 0 || high&0xffff != 0 {
		return false
	}
	exponent := high & 0x7fc00000
	return exponent == 0x40000000 || exponent == 0x3fc00000
}

// --- arm64_lower_sve_float_multiply_extended.go ---
func (c *arm64Ctx) lowerARM64SVEFloatMultiplyExtended(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZFMULX" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 4 {
		return true, false, fmt.Errorf("arm64 ZFMULX expects one complete Go 1.27 predicated form without a suffix: %q", ins.Raw)
	}
	second, secondBits, secondOK := arm64SVEFloatElementReg(ins.Args[0])
	first, firstBits, firstOK := arm64SVEFloatElementReg(ins.Args[1])
	predicate, predicateOK := arm64ParseSVEPredicateMode(ins.Args[2], "M", 7)
	destination, destinationBits, destinationOK := arm64SVEFloatElementReg(ins.Args[3])
	if !secondOK || !firstOK || !predicateOK || !destinationOK || secondBits != firstBits || firstBits != destinationBits || first != destination {
		return true, false, fmt.Errorf("arm64 ZFMULX requires matching destructive H/S/D operands and P0..P7.M: %q", ins.Raw)
	}
	firstValue, vectorType, err := c.loadRawSVEFloatVector(first, firstBits)
	if err != nil {
		return true, false, err
	}
	secondValue, _, err := c.loadRawSVEFloatVector(second, firstBits)
	if err != nil {
		return true, false, err
	}
	predicateValue, predicateType, err := c.loadPRegElements(predicate, firstBits)
	if err != nil {
		return true, false, err
	}
	_, _, lanes, _ := arm64SVEFloatType(firstBits)
	code := map[int]string{16: "f16", 32: "f32", 64: "f64"}[firstBits]
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.fmulx.nxv%d%s(%s %s, %s %s, %s %s)\n",
		result, vectorType, lanes, code, predicateType, predicateValue, vectorType, firstValue, vectorType, secondValue)
	return true, false, c.storeRawSVEFloatVector(destination, firstBits, "%"+result, vectorType)
}

// --- arm64_lower_sve_float_predicated_pairwise.go ---
type arm64SVEFloatPredicatedPairwiseSpec struct {
	intrinsic string
	sve2      bool
	faminmax  bool
}

var arm64SVEFloatPredicatedPairwiseSpecs = map[Op]arm64SVEFloatPredicatedPairwiseSpec{
	"ZFABD":  {intrinsic: "fabd"},
	"ZFADDP": {intrinsic: "faddp", sve2: true},
	"ZFAMAX": {intrinsic: "famax", sve2: true, faminmax: true},
	"ZFAMIN": {intrinsic: "famin", sve2: true, faminmax: true},
}

func (c *arm64Ctx) lowerARM64SVEFloatPredicatedPairwise(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVEFloatPredicatedPairwiseSpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 4 {
		return true, false, fmt.Errorf("arm64 %s expects Zm.H|S|D, Zdn.H|S|D, Pg/M, Zdn.H|S|D without a suffix: %q", op, ins.Raw)
	}
	second, secondBits, secondOK := arm64SVEFloatElementReg(ins.Args[0])
	destination, destinationBits, destinationOK := arm64SVEFloatElementReg(ins.Args[1])
	predicate, predicateOK := arm64ParseSVEPredicateMode(ins.Args[2], "M", 7)
	repeatedDestination, repeatedBits, repeatedOK := arm64SVEFloatElementReg(ins.Args[3])
	if !secondOK || !destinationOK || !predicateOK || !repeatedOK || secondBits != destinationBits || repeatedBits != destinationBits || repeatedDestination != destination {
		return true, false, fmt.Errorf("arm64 %s requires matching destructive H/S/D operands and P0..P7/M: %q", op, ins.Raw)
	}
	destinationValue, vectorType, err := c.loadRawSVEFloatVector(destination, destinationBits)
	if err != nil {
		return true, false, err
	}
	secondValue, _, err := c.loadRawSVEFloatVector(second, secondBits)
	if err != nil {
		return true, false, err
	}
	predicateValue, predicateType, err := c.loadPRegElements(predicate, destinationBits)
	if err != nil {
		return true, false, err
	}
	_, _, lanes, err := arm64SVEFloatType(destinationBits)
	if err != nil {
		return true, false, err
	}
	mangle := map[int]string{16: "f16", 32: "f32", 64: "f64"}[destinationBits]
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%d%s(%s %s, %s %s, %s %s)\n", result, vectorType, spec.intrinsic, lanes, mangle, predicateType, predicateValue, vectorType, destinationValue, vectorType, secondValue)
	return true, false, c.storeRawSVEFloatVector(destination, destinationBits, "%"+result, vectorType)
}

// --- arm64_lower_sve_float_reciprocal_step.go ---
var arm64SVEFloatReciprocalStepIntrinsics = map[Op]string{
	"ZFRECPS":  "frecps.x",
	"ZFRSQRTS": "frsqrts.x",
}

func (c *arm64Ctx) lowerARM64SVEFloatReciprocalStep(op Op, ins Instr) (ok bool, terminated bool, err error) {
	intrinsic, ok := arm64SVEFloatReciprocalStepIntrinsics[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects Zm.H|S|D, Zn.H|S|D, Zd.H|S|D without a suffix: %q", op, ins.Raw)
	}
	second, secondBits, secondOK := arm64SVEFloatElementReg(ins.Args[0])
	first, firstBits, firstOK := arm64SVEFloatElementReg(ins.Args[1])
	destination, destinationBits, destinationOK := arm64SVEFloatElementReg(ins.Args[2])
	if !secondOK || !firstOK || !destinationOK || secondBits != firstBits || firstBits != destinationBits {
		return true, false, fmt.Errorf("arm64 %s requires three matching H/S/D scalable floating-vector operands: %q", op, ins.Raw)
	}
	firstValue, vectorType, err := c.loadRawSVEFloatVector(first, firstBits)
	if err != nil {
		return true, false, err
	}
	secondValue, _, err := c.loadRawSVEFloatVector(second, secondBits)
	if err != nil {
		return true, false, err
	}
	_, _, lanes, err := arm64SVEFloatType(firstBits)
	if err != nil {
		return true, false, err
	}
	mangle := map[int]string{16: "f16", 32: "f32", 64: "f64"}[firstBits]
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%d%s(%s %s, %s %s)\n", result, vectorType, intrinsic, lanes, mangle, vectorType, firstValue, vectorType, secondValue)
	return true, false, c.storeRawSVEFloatVector(destination, destinationBits, "%"+result, vectorType)
}

// --- arm64_lower_sve_float_trig_multiply.go ---
var arm64SVEFloatTrigIntrinsics = map[Op]string{
	"ZFTSMUL": "ftsmul",
	"ZFTSSEL": "ftssel",
}

func (c *arm64Ctx) lowerARM64SVEFloatTrigMultiply(op Op, ins Instr) (ok bool, terminated bool, err error) {
	intrinsic, ok := arm64SVEFloatTrigIntrinsics[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects one complete Go 1.27 vector form without a suffix: %q", op, ins.Raw)
	}
	control, controlBits, controlOK := arm64SVEFloatElementReg(ins.Args[0])
	source, sourceBits, sourceOK := arm64SVEFloatElementReg(ins.Args[1])
	destination, destinationBits, destinationOK := arm64SVEFloatElementReg(ins.Args[2])
	if !controlOK || !sourceOK || !destinationOK || controlBits != sourceBits || sourceBits != destinationBits {
		return true, false, fmt.Errorf("arm64 %s operands must use one H/S/D width: %q", op, ins.Raw)
	}
	sourceValue, floatVectorType, err := c.loadRawSVEFloatVector(source, sourceBits)
	if err != nil {
		return true, false, err
	}
	controlValue, integerVectorType, err := c.loadZRegElements(control, controlBits)
	if err != nil {
		return true, false, err
	}
	_, _, lanes, _ := arm64SVEFloatType(sourceBits)
	code := map[int]string{16: "f16", 32: "f32", 64: "f64"}[sourceBits]
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.x.nxv%d%s(%s %s, %s %s)\n",
		result, floatVectorType, intrinsic, lanes, code, floatVectorType, sourceValue, integerVectorType, controlValue)
	return true, false, c.storeRawSVEFloatVector(destination, sourceBits, "%"+result, floatVectorType)
}

// --- arm64_lower_sve_float_trig_multiply_add.go ---
func (c *arm64Ctx) lowerARM64SVEFloatTrigMultiplyAdd(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZFTMAD" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 4 {
		return true, false, fmt.Errorf("arm64 ZFTMAD expects one complete Go 1.27 vector form without a suffix: %q", ins.Raw)
	}
	if ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" || ins.Args[0].ImmIsFloat || ins.Args[0].Imm < 0 || ins.Args[0].Imm > 7 {
		return true, false, fmt.Errorf("arm64 ZFTMAD immediate must be an unsigned 3-bit integer: %q", ins.Raw)
	}
	multiplier, multiplierBits, multiplierOK := arm64SVEFloatElementReg(ins.Args[1])
	destination, destinationBits, destinationOK := arm64SVEFloatElementReg(ins.Args[2])
	repeated, repeatedBits, repeatedOK := arm64SVEFloatElementReg(ins.Args[3])
	if !multiplierOK || !destinationOK || !repeatedOK || multiplierBits != destinationBits || destinationBits != repeatedBits || destination != repeated {
		return true, false, fmt.Errorf("arm64 ZFTMAD requires matching destructive H/S/D operands: %q", ins.Raw)
	}
	destinationValue, vectorType, err := c.loadRawSVEFloatVector(destination, destinationBits)
	if err != nil {
		return true, false, err
	}
	multiplierValue, _, err := c.loadRawSVEFloatVector(multiplier, multiplierBits)
	if err != nil {
		return true, false, err
	}
	_, _, lanes, _ := arm64SVEFloatType(destinationBits)
	code := map[int]string{16: "f16", 32: "f32", 64: "f64"}[destinationBits]
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.ftmad.x.nxv%d%s(%s %s, %s %s, i32 %d)\n",
		result, vectorType, lanes, code, vectorType, destinationValue, vectorType, multiplierValue, ins.Args[0].Imm)
	return true, false, c.storeRawSVEFloatVector(destination, destinationBits, "%"+result, vectorType)
}

// --- arm64_lower_sve_halving_add_sub.go ---
var arm64SVEHalvingAddSubIntrinsics = map[Op]string{
	"ZSHADD":  "shadd",
	"ZSRHADD": "srhadd",
	"ZUHADD":  "uhadd",
	"ZURHADD": "urhadd",
	"ZSHSUB":  "shsub",
	"ZSHSUBR": "shsubr",
	"ZUHSUB":  "uhsub",
	"ZUHSUBR": "uhsubr",
}

func (c *arm64Ctx) lowerARM64SVEHalvingAddSub(op Op, ins Instr) (ok bool, terminated bool, err error) {
	intrinsic, ok := arm64SVEHalvingAddSubIntrinsics[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 4 {
		return true, false, fmt.Errorf("arm64 %s expects Zm.T, Zdn.T, P0..P7/M, Zdn.T without a suffix: %q", op, ins.Raw)
	}
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
	first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
	predicate, predicateOK := arm64ParseSVEPredicateMerge(ins.Args[2])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[3])
	if !secondOK || !firstOK || !predicateOK || !destinationOK || secondBits != firstBits || firstBits != destinationBits || first != destination {
		return true, false, fmt.Errorf("arm64 %s requires matching-width destructive data operands and P0..P7/M: %q", op, ins.Raw)
	}
	firstValue, vectorType, err := c.loadZRegElements(first, firstBits)
	if err != nil {
		return true, false, err
	}
	secondValue, _, err := c.loadZRegElements(second, firstBits)
	if err != nil {
		return true, false, err
	}
	predicateValue, predicateType, err := c.loadPRegElements(predicate, firstBits)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / firstBits
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s, %s %s)\n", result, vectorType, intrinsic, lanes, firstBits, predicateType, predicateValue, vectorType, firstValue, vectorType, secondValue)
	return true, false, c.storeZRegElements(destination, firstBits, "%"+result)
}

// --- arm64_lower_sve_histogram.go ---
var arm64SVEHistogramOps = map[Op]struct{}{
	"ZHISTCNT": {},
	"ZHISTSEG": {},
}

func (c *arm64Ctx) lowerARM64SVEHistogram(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if _, ok := arm64SVEHistogramOps[op]; !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) {
		return true, false, fmt.Errorf("arm64 %s does not accept a mnemonic suffix: %q", op, ins.Raw)
	}
	if op == "ZHISTSEG" {
		if len(ins.Args) != 3 {
			return true, false, fmt.Errorf("arm64 ZHISTSEG expects Zm.B, Zn.B, Zd.B: %q", ins.Raw)
		}
		second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
		first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
		destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
		if !secondOK || !firstOK || !destinationOK || secondBits != 8 || firstBits != 8 || destinationBits != 8 {
			return true, false, fmt.Errorf("arm64 ZHISTSEG requires three B scalable-vector operands: %q", ins.Raw)
		}
		firstValue, vectorType, err := c.loadZRegElements(first, 8)
		if err != nil {
			return true, false, err
		}
		secondValue, _, err := c.loadZRegElements(second, 8)
		if err != nil {
			return true, false, err
		}
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.histseg.nxv16i8(%s %s, %s %s)\n", result, vectorType, vectorType, firstValue, vectorType, secondValue)
		return true, false, c.storeZRegElements(destination, 8, "%"+result)
	}
	if len(ins.Args) != 4 {
		return true, false, fmt.Errorf("arm64 ZHISTCNT expects Zm.S|D, Zn.S|D, Pg/Z, Zd.S|D: %q", ins.Raw)
	}
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
	first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
	predicate, predicateOK := arm64ParseSVEPredicateMode(ins.Args[2], "Z", 7)
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[3])
	if !secondOK || !firstOK || !predicateOK || !destinationOK || (firstBits != 32 && firstBits != 64) || secondBits != firstBits || destinationBits != firstBits {
		return true, false, fmt.Errorf("arm64 ZHISTCNT requires matching S/D vectors under P0..P7/Z: %q", ins.Raw)
	}
	predicateValue, predicateType, err := c.loadPRegElements(predicate, firstBits)
	if err != nil {
		return true, false, err
	}
	firstValue, vectorType, err := c.loadZRegElements(first, firstBits)
	if err != nil {
		return true, false, err
	}
	secondValue, _, err := c.loadZRegElements(second, secondBits)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / firstBits
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.histcnt.nxv%di%d(%s %s, %s %s, %s %s)\n", result, vectorType, lanes, firstBits, predicateType, predicateValue, vectorType, firstValue, vectorType, secondValue)
	return true, false, c.storeZRegElements(destination, destinationBits, "%"+result)
}

// --- arm64_lower_sve_mixed_saturating_add.go ---
func (c *arm64Ctx) lowerARM64SVEMixedSaturatingAdd(op Op, ins Instr) (ok bool, terminated bool, err error) {
	intrinsic := ""
	switch op {
	case "ZSUQADD":
		intrinsic = "suqadd"
	case "ZUSQADD":
		intrinsic = "usqadd"
	default:
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 4 {
		return true, false, fmt.Errorf("arm64 %s expects Zm.B|H|S|D, Zdn.B|H|S|D, P0..P7/M, Zdn.B|H|S|D without a suffix: %q", op, ins.Raw)
	}
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
	first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
	predicate, predicateOK := arm64ParseSVEPredicateMode(ins.Args[2], "M", 7)
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[3])
	if !secondOK || !firstOK || !predicateOK || !destinationOK || secondBits != firstBits || destinationBits != firstBits || destination != first {
		return true, false, fmt.Errorf("arm64 %s requires matching-width destructive B/H/S/D operands and P0..P7/M: %q", op, ins.Raw)
	}
	firstValue, vectorType, err := c.loadZRegElements(first, firstBits)
	if err != nil {
		return true, false, err
	}
	secondValue, _, err := c.loadZRegElements(second, secondBits)
	if err != nil {
		return true, false, err
	}
	predicateValue, predicateType, err := c.loadPRegElements(predicate, firstBits)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / firstBits
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s, %s %s)\n", result, vectorType, intrinsic, lanes, firstBits, predicateType, predicateValue, vectorType, firstValue, vectorType, secondValue)
	selected := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select %s %s, %s %%%s, %s %s\n", selected, predicateType, predicateValue, vectorType, result, vectorType, firstValue)
	return true, false, c.storeZRegElements(destination, firstBits, "%"+selected)
}

// --- arm64_lower_sve_multiply_add_tail.go ---
var arm64SVEMultiplyAddTailOps = map[Op]string{
	"ZMADPT": "madpt",
	"ZMLAPT": "mlapt",
}

func (c *arm64Ctx) lowerARM64SVEMultiplyAddTail(op Op, ins Instr) (ok bool, terminated bool, err error) {
	mnemonic, ok := arm64SVEMultiplyAddTailOps[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects three D-width vector operands without a suffix: %q", op, ins.Raw)
	}
	firstSource, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[0])
	secondSource, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[1])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	if !firstOK || !secondOK || !destinationOK || firstBits != 64 || secondBits != 64 || destinationBits != 64 {
		return true, false, fmt.Errorf("arm64 %s requires three D-width scalable-vector operands: %q", op, ins.Raw)
	}
	destinationValue, vectorType, err := c.loadZRegElements(destination, 64)
	if err != nil {
		return true, false, err
	}
	secondValue, _, err := c.loadZRegElements(secondSource, 64)
	if err != nil {
		return true, false, err
	}
	firstValue, _, err := c.loadZRegElements(firstSource, 64)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	assembly := mnemonic + " $0.d, $2.d, $3.d"
	fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q(%s %s, %s %s, %s %s)\n", result, vectorType, assembly, "=&w,0,w,w", vectorType, destinationValue, vectorType, secondValue, vectorType, firstValue)
	return true, false, c.storeZRegElements(destination, 64, "%"+result)
}

// --- arm64_lower_sve_non_faulting_memory.go ---
type arm64SVENonFaultingMemorySpec struct {
	memoryBits int
	signed     bool
}

// arm64SVENonFaultingMemorySpecs covers all 16 Go 1.27 LDNF1 encoder forms:
// natural-width and widening unsigned loads plus the widening signed forms.
var arm64SVENonFaultingMemorySpecs = map[Op]arm64SVENonFaultingMemorySpec{
	"ZLDNF1B":  {memoryBits: 8},
	"ZLDNF1H":  {memoryBits: 16},
	"ZLDNF1W":  {memoryBits: 32},
	"ZLDNF1D":  {memoryBits: 64},
	"ZLDNF1SB": {memoryBits: 8, signed: true},
	"ZLDNF1SH": {memoryBits: 16, signed: true},
	"ZLDNF1SW": {memoryBits: 32, signed: true},
}

func (c *arm64Ctx) lowerARM64SVENonFaultingMemory(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVENonFaultingMemorySpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 || ins.Args[0].Kind != OpMem || ins.Args[2].Kind != OpRegList {
		return true, false, fmt.Errorf("arm64 %s expects memory, predicate, vector-list operands: %q", op, ins.Raw)
	}
	predicate, predicateOK := arm64ParseSVEPredicateMode(ins.Args[1], "Z", 7)
	vectors, elementBits, vectorsOK := arm64ParseSVEConsecutiveVectorList(ins.Args[2])
	if !predicateOK || !vectorsOK || len(vectors) != 1 || elementBits < spec.memoryBits || spec.signed && elementBits == spec.memoryBits {
		return true, false, fmt.Errorf("arm64 %s has predicate or destination widths outside its Go 1.27 table: %q", op, ins.Raw)
	}
	address, err := c.arm64SVEVLAddress(ins.Args[0].Mem, -8, 7, int64(16*spec.memoryBits/elementBits))
	if err != nil {
		return true, false, fmt.Errorf("arm64 %s: %w: %q", op, err, ins.Raw)
	}
	predicateValue, predicateType, err := c.loadPRegElements(predicate, elementBits)
	if err != nil {
		return true, false, err
	}
	pointer := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pointer, address)
	lanes := 128 / elementBits
	loadedType := fmt.Sprintf("<vscale x %d x i%d>", lanes, spec.memoryBits)
	loaded := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.ldnf1.nxv%di%d(%s %s, ptr %%%s)\n",
		loaded, loadedType, lanes, spec.memoryBits, predicateType, predicateValue, pointer)
	value := "%" + loaded
	if spec.memoryBits < elementBits {
		vectorType, _, err := arm64SVEVectorType(elementBits)
		if err != nil {
			return true, false, err
		}
		extended := c.newTmp()
		extension := "zext"
		if spec.signed {
			extension = "sext"
		}
		fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", extended, extension, loadedType, value, vectorType)
		value = "%" + extended
	}
	return true, false, c.storeZRegElements(vectors[0], elementBits, value)
}

// --- arm64_lower_sve_optional_crypto.go ---
type arm64SVEOptionalCryptoSpec struct {
	intrinsic   string
	elementBits int
	destructive bool
	feature     string
}

var arm64SVEOptionalCryptoSpecs = map[Op]arm64SVEOptionalCryptoSpec{
	"ZRAX1":    {intrinsic: "rax1", elementBits: 64, feature: "+sve2-sha3"},
	"ZSM4E":    {intrinsic: "sm4e", elementBits: 32, destructive: true, feature: "+sve2-sm4"},
	"ZSM4EKEY": {intrinsic: "sm4ekey", elementBits: 32, feature: "+sve2-sm4"},
}

func (c *arm64Ctx) lowerARM64SVEOptionalCrypto(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVEOptionalCryptoSpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects three vector operands without a suffix: %q", op, ins.Raw)
	}
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
	first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	if !secondOK || !firstOK || !destinationOK || secondBits != spec.elementBits || firstBits != spec.elementBits || destinationBits != spec.elementBits || spec.destructive && first != destination {
		return true, false, fmt.Errorf("arm64 %s requires matching %d-bit vectors%s: %q", op, spec.elementBits, map[bool]string{true: " with repeated source/destination", false: ""}[spec.destructive], ins.Raw)
	}
	firstValue, vectorType, err := c.loadZRegElements(first, spec.elementBits)
	if err != nil {
		return true, false, err
	}
	secondValue, _, err := c.loadZRegElements(second, spec.elementBits)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s(%s %s, %s %s)\n", result, vectorType, spec.intrinsic, vectorType, firstValue, vectorType, secondValue)
	return true, false, c.storeZRegElements(destination, spec.elementBits, "%"+result)
}

// --- arm64_lower_sve_pmul.go ---
func (c *arm64Ctx) lowerARM64SVEPMUL(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZPMUL" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 ZPMUL expects Zm.B, Zn.B, Zd.B without a suffix: %q", ins.Raw)
	}
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
	first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	if !secondOK || !firstOK || !destinationOK || secondBits != 8 || firstBits != 8 || destinationBits != 8 {
		return true, false, fmt.Errorf("arm64 ZPMUL requires B-element vectors: %q", ins.Raw)
	}
	firstValue, vectorType, err := c.loadZRegElements(first, 8)
	if err != nil {
		return true, false, err
	}
	secondValue, _, err := c.loadZRegElements(second, 8)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.pmul.nxv16i8(%s %s, %s %s)\n", result, vectorType, vectorType, firstValue, vectorType, secondValue)
	return true, false, c.storeZRegElements(destination, 8, "%"+result)
}

// --- arm64_lower_sve_pmull.go ---
var arm64SVEPMULLIntrinsics = map[Op]string{
	"ZPMULLB": "pmullb.pair",
	"ZPMULLT": "pmullt.pair",
}

func arm64SVEPMULLNeedsSVE2AES(ins Instr) bool {
	if len(ins.Args) != 3 {
		return false
	}
	_, ok := arm64ParseSVEZQReg(ins.Args[2])
	return ok
}

func (c *arm64Ctx) lowerARM64SVEPMULL(op Op, ins Instr) (ok bool, terminated bool, err error) {
	intrinsic, ok := arm64SVEPMULLIntrinsics[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects Zm.B, Zn.B, Zd.H; Zm.S, Zn.S, Zd.D; or Zm.D, Zn.D, Zd.Q without a suffix: %q", op, ins.Raw)
	}
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
	first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
	if !secondOK || !firstOK || secondBits != firstBits || firstBits != 8 && firstBits != 32 && firstBits != 64 {
		return true, false, fmt.Errorf("arm64 %s requires matching B, S, or D source vectors: %q", op, ins.Raw)
	}
	destinationRepresentationBits := firstBits * 2
	destination := 0
	if firstBits == 64 {
		var destinationOK bool
		destination, destinationOK = arm64ParseSVEZQReg(ins.Args[2])
		if !destinationOK {
			return true, false, fmt.Errorf("arm64 %s D sources require a Q destination: %q", op, ins.Raw)
		}
		destinationRepresentationBits = 64
	} else {
		var destinationBits int
		var destinationOK bool
		destination, destinationBits, destinationOK = arm64ParseSVEZElementReg(ins.Args[2])
		if !destinationOK || destinationBits != destinationRepresentationBits {
			return true, false, fmt.Errorf("arm64 %s must widen B to H or S to D: %q", op, ins.Raw)
		}
	}
	firstValue, sourceType, err := c.loadZRegElements(first, firstBits)
	if err != nil {
		return true, false, err
	}
	secondValue, _, err := c.loadZRegElements(second, firstBits)
	if err != nil {
		return true, false, err
	}
	_, sourceLanes, err := arm64SVEVectorType(firstBits)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s)\n", result, sourceType, intrinsic, sourceLanes, firstBits, sourceType, firstValue, sourceType, secondValue)
	resultValue := "%" + result
	if firstBits != 64 {
		destinationType, _, err := arm64SVEVectorType(destinationRepresentationBits)
		if err != nil {
			return true, false, err
		}
		converted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", converted, sourceType, resultValue, destinationType)
		resultValue = "%" + converted
	}
	return true, false, c.storeZRegElements(destination, destinationRepresentationBits, resultValue)
}

// --- arm64_lower_sve_pmull_pair.go ---
func arm64ParseSVEQPair(operand Operand) (first, second int, ok bool) {
	if operand.Kind != OpRegList || !operand.RegListRange || len(operand.RegList) != 2 {
		return 0, 0, false
	}
	first, firstOK := arm64ParseSVEZQReg(Operand{Kind: OpReg, Reg: operand.RegList[0]})
	second, secondOK := arm64ParseSVEZQReg(Operand{Kind: OpReg, Reg: operand.RegList[1]})
	return first, second, firstOK && secondOK && first%2 == 0 && second == first+1
}

func (c *arm64Ctx) lowerARM64SVEPMULLPair(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZPMULL" && op != "ZPMLAL" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects Zm.D, Zn.D, [Zd.Q-Zd+1.Q] without a suffix: %q", op, ins.Raw)
	}
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
	first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
	firstDestination, secondDestination, destinationOK := arm64ParseSVEQPair(ins.Args[2])
	if !secondOK || !firstOK || secondBits != 64 || firstBits != 64 || !destinationOK {
		return true, false, fmt.Errorf("arm64 %s requires D sources and an even-odd consecutive Q destination pair: %q", op, ins.Raw)
	}
	firstValue, vectorType, err := c.loadZRegElements(first, 64)
	if err != nil {
		return true, false, err
	}
	secondValue, _, err := c.loadZRegElements(second, 64)
	if err != nil {
		return true, false, err
	}
	aggregateType := fmt.Sprintf("{ %s, %s }", vectorType, vectorType)
	result := c.newTmp()
	if op == "ZPMULL" {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.pmull.pair.x2(%s %s, %s %s)\n", result, aggregateType, vectorType, firstValue, vectorType, secondValue)
	} else {
		firstAccumulator, _, err := c.loadZRegElements(firstDestination, 64)
		if err != nil {
			return true, false, err
		}
		secondAccumulator, _, err := c.loadZRegElements(secondDestination, 64)
		if err != nil {
			return true, false, err
		}
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.pmlal.pair.x2(%s %s, %s %s, %s %s, %s %s)\n", result, aggregateType, vectorType, firstAccumulator, vectorType, secondAccumulator, vectorType, firstValue, vectorType, secondValue)
	}
	firstResult := c.newTmp()
	secondResult := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractvalue %s %%%s, 0\n", firstResult, aggregateType, result)
	fmt.Fprintf(c.b, "  %%%s = extractvalue %s %%%s, 1\n", secondResult, aggregateType, result)
	if err := c.storeZRegElements(firstDestination, 64, "%"+firstResult); err != nil {
		return true, false, err
	}
	return true, false, c.storeZRegElements(secondDestination, 64, "%"+secondResult)
}

// --- arm64_lower_sve_predicate_iterate.go ---
type arm64SVEPredicateIterateSpec struct {
	intrinsic string
	byteOnly  bool
}

var arm64SVEPredicateIterateSpecs = map[Op]arm64SVEPredicateIterateSpec{
	"PPFIRST": {intrinsic: "pfirst", byteOnly: true},
	"PPNEXT":  {intrinsic: "pnext"},
}

func (c *arm64Ctx) lowerARM64SVEPredicateIterate(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVEPredicateIterateSpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects Pdn.T, Pg, Pdn.T: %q", op, ins.Raw)
	}
	current, currentBits, currentOK := arm64ParseSVEPredicateElement(ins.Args[0])
	governing, governingOK := arm64ParseSVEPredicateBare(ins.Args[1], 15)
	destination, destinationBits, destinationOK := arm64ParseSVEPredicateElement(ins.Args[2])
	if !currentOK || !governingOK || !destinationOK || current != destination || currentBits != destinationBits || (spec.byteOnly && currentBits != 8) {
		return true, false, fmt.Errorf("arm64 %s operands do not match its Go 1.27 read-modify-write predicate form: %q", op, ins.Raw)
	}
	governingValue, predicateType, err := c.loadPRegElements(governing, currentBits)
	if err != nil {
		return true, false, err
	}
	currentValue, _, err := c.loadPRegElements(current, currentBits)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / currentBits
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di1(%s %s, %s %s)\n", result, predicateType, spec.intrinsic, lanes, predicateType, governingValue, predicateType, currentValue)
	if err := c.storePRegElements(destination, currentBits, "%"+result); err != nil {
		return true, false, err
	}
	c.setSVEPredicateFlags(governingValue, "%"+result, predicateType, lanes)
	return true, false, nil
}

// --- arm64_lower_sve_predicate_position.go ---
var arm64SVEPredicatePositionIntrinsics = map[Op]string{
	"PFIRSTP": "firstp",
	"PLASTP":  "lastp",
}

func (c *arm64Ctx) lowerARM64SVEPredicatePosition(op Op, ins Instr) (ok bool, terminated bool, err error) {
	intrinsic, ok := arm64SVEPredicatePositionIntrinsics[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects Pn.T, Pg, Xd: %q", op, ins.Raw)
	}
	tested, elementBits, testedOK := arm64ParseSVEPredicateElement(ins.Args[0])
	governing, governingOK := arm64ParseSVEPredicateBare(ins.Args[1], 15)
	if !testedOK || !governingOK || ins.Args[2].Kind != OpReg || !isARM64GeneralOrZeroReg(ins.Args[2].Reg) {
		return true, false, fmt.Errorf("arm64 %s operands do not match its Go 1.27 predicate-position form: %q", op, ins.Raw)
	}
	governingValue, predicateType, err := c.loadPRegElements(governing, elementBits)
	if err != nil {
		return true, false, err
	}
	testedValue, _, err := c.loadPRegElements(tested, elementBits)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / elementBits
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call i64 @llvm.aarch64.sve.%s.nxv%di1(%s %s, %s %s)\n", result, intrinsic, lanes, predicateType, governingValue, predicateType, testedValue)
	return true, false, c.storeReg(ins.Args[2].Reg, "%"+result)
}

// --- arm64_lower_sve_revd.go ---
func decodeARM64RawSVERevd(word uint32) (Instr, bool) {
	mode := "M"
	switch word & 0xffffe000 {
	case 0x052e8000:
	case 0x052ea000:
		mode = "Z"
	default:
		return Instr{}, false
	}
	return Instr{Op: "ZREVD", Raw: fmt.Sprintf("WORD $%#08x", word), Args: []Operand{
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.Q", word>>5&31))},
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d.%s", word>>10&7, mode))},
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.Q", word&31))},
	}}, true
}

func arm64ParseSVEZQReg(operand Operand) (int, bool) {
	if operand.Kind != OpReg {
		return 0, false
	}
	name := strings.ToUpper(strings.TrimSpace(string(operand.Reg)))
	if !strings.HasPrefix(name, "Z") || !strings.HasSuffix(name, ".Q") {
		return 0, false
	}
	index, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(name, "Z"), ".Q"))
	return index, err == nil && index >= 0 && index <= 31
}

func arm64SVERevdNeedsSVE2P2(ins Instr) bool {
	return len(ins.Args) == 3 && func() bool {
		_, ok := arm64ParseSVEPredicateMode(ins.Args[1], "Z", 7)
		return ok
	}()
}

func (c *arm64Ctx) lowerARM64SVERevd(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZREVD" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 ZREVD expects Zn.Q, Pg/M|Z, Zd.Q without a suffix: %q", ins.Raw)
	}
	source, sourceOK := arm64ParseSVEZQReg(ins.Args[0])
	destination, destinationOK := arm64ParseSVEZQReg(ins.Args[2])
	predicate, mergeOK := arm64ParseSVEPredicateMode(ins.Args[1], "M", 7)
	zeroing := false
	if !mergeOK {
		predicate, zeroing = arm64ParseSVEPredicateMode(ins.Args[1], "Z", 7)
	}
	if !sourceOK || !destinationOK || !mergeOK && !zeroing {
		return true, false, fmt.Errorf("arm64 ZREVD requires Q vectors and P0..P7/M or P0..P7/Z: %q", ins.Raw)
	}
	sourceValue, vectorType, err := c.loadZRegElements(source, 64)
	if err != nil {
		return true, false, err
	}
	mergeValue := "zeroinitializer"
	if !zeroing {
		mergeValue, _, err = c.loadZRegElements(destination, 64)
		if err != nil {
			return true, false, err
		}
	}
	predicateValue, predicateType, err := c.loadPRegElements(predicate, 64)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.revd.nxv2i64(%s %s, %s %s, %s %s)\n", result, vectorType, vectorType, mergeValue, predicateType, predicateValue, vectorType, sourceValue)
	return true, false, c.storeZRegElements(destination, 64, "%"+result)
}

// --- arm64_lower_sve_saturating_multiply_high.go ---
var arm64SVESaturatingMultiplyHighIntrinsics = map[Op]string{
	"ZSQDMULH":  "sqdmulh",
	"ZSQRDMULH": "sqrdmulh",
}

func (c *arm64Ctx) lowerARM64SVESaturatingMultiplyHigh(op Op, ins Instr) (ok bool, terminated bool, err error) {
	intrinsic, ok := arm64SVESaturatingMultiplyHighIntrinsics[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects one complete Go 1.27 vector form without a suffix: %q", op, ins.Raw)
	}
	first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	if !firstOK || !destinationOK || firstBits != destinationBits {
		return true, false, fmt.Errorf("arm64 %s source and destination widths must match: %q", op, ins.Raw)
	}
	second, secondBits, lane, indexed := arm64ParseSVEZIndexedElementReg(ins.Args[0])
	if !indexed {
		second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
		if !secondOK || secondBits != firstBits {
			return true, false, fmt.Errorf("arm64 %s vector operands must use one B/H/S/D width: %q", op, ins.Raw)
		}
		return true, false, c.lowerARM64SVESaturatingMultiplyHighForm(intrinsic, firstBits, first, second, 0, destination, false)
	}
	if secondBits != firstBits {
		return true, false, fmt.Errorf("arm64 %s indexed operands must use one H/S/D width and an encodable lane: %q", op, ins.Raw)
	}
	return true, false, c.lowerARM64SVESaturatingMultiplyHighForm(intrinsic, firstBits, first, second, lane, destination, true)
}

func (c *arm64Ctx) lowerARM64SVESaturatingMultiplyHighForm(intrinsic string, elementBits, first, second, lane, destination int, indexed bool) error {
	firstValue, vectorType, err := c.loadZRegElements(first, elementBits)
	if err != nil {
		return err
	}
	secondValue, _, err := c.loadZRegElements(second, elementBits)
	if err != nil {
		return err
	}
	_, lanes, err := arm64SVEVectorType(elementBits)
	if err != nil {
		return err
	}
	result := c.newTmp()
	if indexed {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.lane.nxv%di%d(%s %s, %s %s, i32 %d)\n",
			result, vectorType, intrinsic, lanes, elementBits, vectorType, firstValue, vectorType, secondValue, lane)
	} else {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s)\n",
			result, vectorType, intrinsic, lanes, elementBits, vectorType, firstValue, vectorType, secondValue)
	}
	return c.storeZRegElements(destination, elementBits, "%"+result)
}

// --- arm64_lower_sve_saturating_narrow.go ---
type arm64SVESaturatingNarrowSpec struct {
	intrinsic string
	top       bool
}

var arm64SVESaturatingNarrowSpecs = map[Op]arm64SVESaturatingNarrowSpec{
	"ZSQXTNB":  {intrinsic: "sqxtnb"},
	"ZSQXTNT":  {intrinsic: "sqxtnt", top: true},
	"ZSQXTUNB": {intrinsic: "sqxtunb"},
	"ZSQXTUNT": {intrinsic: "sqxtunt", top: true},
	"ZUQXTNB":  {intrinsic: "uqxtnb"},
	"ZUQXTNT":  {intrinsic: "uqxtnt", top: true},
}

func (c *arm64Ctx) lowerARM64SVESaturatingNarrow(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVESaturatingNarrowSpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 {
		return true, false, fmt.Errorf("arm64 %s expects Zn.H|S|D, Zd.B|H|S without a suffix: %q", op, ins.Raw)
	}
	source, sourceBits, sourceOK := arm64ParseSVEZElementReg(ins.Args[0])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[1])
	if !sourceOK || !destinationOK || (sourceBits != 16 && sourceBits != 32 && sourceBits != 64) || destinationBits*2 != sourceBits {
		return true, false, fmt.Errorf("arm64 %s requires an H-to-B, S-to-H, or D-to-S narrowing pair: %q", op, ins.Raw)
	}
	sourceValue, sourceType, err := c.loadZRegElements(source, sourceBits)
	if err != nil {
		return true, false, err
	}
	destinationType, _, err := arm64SVEVectorType(destinationBits)
	if err != nil {
		return true, false, err
	}
	args := fmt.Sprintf("%s %s", sourceType, sourceValue)
	if spec.top {
		merged, _, err := c.loadZRegElements(destination, destinationBits)
		if err != nil {
			return true, false, err
		}
		args = fmt.Sprintf("%s %s, %s", destinationType, merged, args)
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s)\n", result, destinationType, spec.intrinsic, 128/sourceBits, sourceBits, args)
	return true, false, c.storeZRegElements(destination, destinationBits, "%"+result)
}

// --- arm64_lower_sve_saturating_rounding_multiply_accumulate_high.go ---
var arm64SVESaturatingRoundingMultiplyAccumulateHighIntrinsics = map[Op]string{
	"ZSQRDMLAH": "sqrdmlah",
	"ZSQRDMLSH": "sqrdmlsh",
}

func (c *arm64Ctx) lowerARM64SVESaturatingRoundingMultiplyAccumulateHigh(op Op, ins Instr) (ok bool, terminated bool, err error) {
	intrinsic, ok := arm64SVESaturatingRoundingMultiplyAccumulateHighIntrinsics[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects one complete Go 1.27 vector form without a suffix: %q", op, ins.Raw)
	}
	first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	if !firstOK || !destinationOK || firstBits != destinationBits {
		return true, false, fmt.Errorf("arm64 %s source and accumulator widths must match: %q", op, ins.Raw)
	}
	second, secondBits, lane, indexed := arm64ParseSVEZIndexedElementReg(ins.Args[0])
	if !indexed {
		var secondOK bool
		second, secondBits, secondOK = arm64ParseSVEZElementReg(ins.Args[0])
		if !secondOK || secondBits != firstBits {
			return true, false, fmt.Errorf("arm64 %s vector operands must use one B/H/S/D width: %q", op, ins.Raw)
		}
	} else if secondBits != firstBits {
		return true, false, fmt.Errorf("arm64 %s indexed operands must use one H/S/D width and an encodable lane: %q", op, ins.Raw)
	}
	accumulator, vectorType, err := c.loadZRegElements(destination, firstBits)
	if err != nil {
		return true, false, err
	}
	firstValue, _, err := c.loadZRegElements(first, firstBits)
	if err != nil {
		return true, false, err
	}
	secondValue, _, err := c.loadZRegElements(second, firstBits)
	if err != nil {
		return true, false, err
	}
	_, lanes, err := arm64SVEVectorType(firstBits)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	if indexed {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.lane.nxv%di%d(%s %s, %s %s, %s %s, i32 %d)\n",
			result, vectorType, intrinsic, lanes, firstBits, vectorType, accumulator, vectorType, firstValue, vectorType, secondValue, lane)
	} else {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s, %s %s)\n",
			result, vectorType, intrinsic, lanes, firstBits, vectorType, accumulator, vectorType, firstValue, vectorType, secondValue)
	}
	return true, false, c.storeZRegElements(destination, firstBits, "%"+result)
}

// --- arm64_lower_sve_saturating_shift_narrow.go ---
type arm64SVESaturatingShiftNarrowSpec struct {
	intrinsic string
	top       bool
}

var arm64SVESaturatingShiftNarrowSpecs = map[Op]arm64SVESaturatingShiftNarrowSpec{
	"ZSQSHRNB":   {intrinsic: "sqshrnb"},
	"ZSQSHRNT":   {intrinsic: "sqshrnt", top: true},
	"ZSQRSHRNB":  {intrinsic: "sqrshrnb"},
	"ZSQRSHRNT":  {intrinsic: "sqrshrnt", top: true},
	"ZSQSHRUNB":  {intrinsic: "sqshrunb"},
	"ZSQSHRUNT":  {intrinsic: "sqshrunt", top: true},
	"ZSQRSHRUNB": {intrinsic: "sqrshrunb"},
	"ZSQRSHRUNT": {intrinsic: "sqrshrunt", top: true},
	"ZUQSHRNB":   {intrinsic: "uqshrnb"},
	"ZUQSHRNT":   {intrinsic: "uqshrnt", top: true},
	"ZUQRSHRNB":  {intrinsic: "uqrshrnb"},
	"ZUQRSHRNT":  {intrinsic: "uqrshrnt", top: true},
}

func (c *arm64Ctx) lowerARM64SVESaturatingShiftNarrow(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVESaturatingShiftNarrowSpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 || ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" {
		return true, false, fmt.Errorf("arm64 %s expects $shift, Zn.H|S|D, Zd.B|H|S without a suffix: %q", op, ins.Raw)
	}
	shift := ins.Args[0].Imm
	source, sourceBits, sourceOK := arm64ParseSVEZElementReg(ins.Args[1])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	if !sourceOK || !destinationOK || (sourceBits != 16 && sourceBits != 32 && sourceBits != 64) || destinationBits*2 != sourceBits || shift < 1 || shift > int64(destinationBits) {
		return true, false, fmt.Errorf("arm64 %s requires matching H-to-B, S-to-H, or D-to-S operands and shift $1..$destinationBits: %q", op, ins.Raw)
	}
	sourceValue, sourceType, err := c.loadZRegElements(source, sourceBits)
	if err != nil {
		return true, false, err
	}
	destinationType, _, err := arm64SVEVectorType(destinationBits)
	if err != nil {
		return true, false, err
	}
	args := fmt.Sprintf("%s %s, i32 %d", sourceType, sourceValue, shift)
	if spec.top {
		merged, _, err := c.loadZRegElements(destination, destinationBits)
		if err != nil {
			return true, false, err
		}
		args = fmt.Sprintf("%s %s, %s", destinationType, merged, args)
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s)\n", result, destinationType, spec.intrinsic, 128/sourceBits, sourceBits, args)
	return true, false, c.storeZRegElements(destination, destinationBits, "%"+result)
}

// --- arm64_lower_sve_shift_long.go ---
var arm64SVEShiftLongIntrinsics = map[Op]string{
	"ZSSHLLB": "sshllb",
	"ZSSHLLT": "sshllt",
	"ZUSHLLB": "ushllb",
	"ZUSHLLT": "ushllt",
}

func (c *arm64Ctx) lowerARM64SVEShiftLong(op Op, ins Instr) (ok bool, terminated bool, err error) {
	intrinsic, ok := arm64SVEShiftLongIntrinsics[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 || ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" {
		return true, false, fmt.Errorf("arm64 %s expects $shift, Zn.B|H|S, Zd.H|S|D without a suffix: %q", op, ins.Raw)
	}
	shift := ins.Args[0].Imm
	source, sourceBits, sourceOK := arm64ParseSVEZElementReg(ins.Args[1])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	if !sourceOK || !destinationOK || sourceBits == 64 || destinationBits != sourceBits*2 || shift < 0 || shift >= int64(sourceBits) {
		return true, false, fmt.Errorf("arm64 %s requires B-to-H, H-to-S, or S-to-D operands and shift $0..$sourceBits-1: %q", op, ins.Raw)
	}
	sourceValue, sourceType, err := c.loadZRegElements(source, sourceBits)
	if err != nil {
		return true, false, err
	}
	destinationType, destinationLanes, err := arm64SVEVectorType(destinationBits)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, i32 %d)\n", result, destinationType, intrinsic, destinationLanes, destinationBits, sourceType, sourceValue, shift)
	return true, false, c.storeZRegElements(destination, destinationBits, "%"+result)
}

// --- arm64_lower_sve_shift_narrow.go ---
type arm64SVEShiftNarrowSpec struct {
	intrinsic string
	top       bool
}

var arm64SVEShiftNarrowSpecs = map[Op]arm64SVEShiftNarrowSpec{
	"ZSHRNB":  {intrinsic: "shrnb"},
	"ZSHRNT":  {intrinsic: "shrnt", top: true},
	"ZRSHRNB": {intrinsic: "rshrnb"},
	"ZRSHRNT": {intrinsic: "rshrnt", top: true},
}

func (c *arm64Ctx) lowerARM64SVEShiftNarrow(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVEShiftNarrowSpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 || ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" {
		return true, false, fmt.Errorf("arm64 %s expects $shift, Zn.H|S|D, Zd.B|H|S without a suffix: %q", op, ins.Raw)
	}
	shift := ins.Args[0].Imm
	source, sourceBits, sourceOK := arm64ParseSVEZElementReg(ins.Args[1])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	if !sourceOK || !destinationOK || (sourceBits != 16 && sourceBits != 32 && sourceBits != 64) || destinationBits*2 != sourceBits || shift < 1 || shift > int64(destinationBits) {
		return true, false, fmt.Errorf("arm64 %s requires matching H-to-B, S-to-H, or D-to-S operands and shift $1..$destinationBits: %q", op, ins.Raw)
	}
	sourceValue, sourceType, err := c.loadZRegElements(source, sourceBits)
	if err != nil {
		return true, false, err
	}
	destinationType, _, err := arm64SVEVectorType(destinationBits)
	if err != nil {
		return true, false, err
	}
	args := fmt.Sprintf("%s %s, i32 %d", sourceType, sourceValue, shift)
	if spec.top {
		merged, _, err := c.loadZRegElements(destination, destinationBits)
		if err != nil {
			return true, false, err
		}
		args = fmt.Sprintf("%s %s, %s", destinationType, merged, args)
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s)\n", result, destinationType, spec.intrinsic, 128/sourceBits, sourceBits, args)
	return true, false, c.storeZRegElements(destination, destinationBits, "%"+result)
}

// --- arm64_lower_sve_table_extension.go ---
var arm64SVETableExtensionIntrinsics = map[Op]string{
	"ZTBLQ": "tblq",
	"ZTBX":  "tbx",
	"ZTBXQ": "tbxq",
}

func (c *arm64Ctx) lowerARM64SVETableExtension(op Op, ins Instr) (ok bool, terminated bool, err error) {
	intrinsic, ok := arm64SVETableExtensionIntrinsics[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects one complete Go 1.27 table form without a suffix: %q", op, ins.Raw)
	}
	index, indexBits, indexOK := arm64ParseSVEZElementReg(ins.Args[0])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	var table, tableBits int
	var tableOK bool
	if op == "ZTBLQ" {
		if ins.Args[1].Kind != OpRegList || len(ins.Args[1].RegList) != 1 {
			return true, false, fmt.Errorf("arm64 ZTBLQ requires exactly one table register list element: %q", ins.Raw)
		}
		table, tableBits, tableOK = arm64ParseSVEZElementReg(Operand{Kind: OpReg, Reg: ins.Args[1].RegList[0]})
	} else {
		table, tableBits, tableOK = arm64ParseSVEZElementReg(ins.Args[1])
	}
	if !indexOK || !tableOK || !destinationOK || indexBits != tableBits || tableBits != destinationBits {
		return true, false, fmt.Errorf("arm64 %s operands must use one matching B/H/S/D width: %q", op, ins.Raw)
	}
	indexValue, vectorType, err := c.loadZRegElements(index, indexBits)
	if err != nil {
		return true, false, err
	}
	tableValue, _, err := c.loadZRegElements(table, tableBits)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / destinationBits
	result := c.newTmp()
	if op == "ZTBLQ" {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s)\n", result, vectorType, intrinsic, lanes, destinationBits, vectorType, tableValue, vectorType, indexValue)
	} else {
		old, _, err := c.loadZRegElements(destination, destinationBits)
		if err != nil {
			return true, false, err
		}
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s, %s %s)\n", result, vectorType, intrinsic, lanes, destinationBits, vectorType, old, vectorType, tableValue, vectorType, indexValue)
	}
	return true, false, c.storeZRegElements(destination, destinationBits, "%"+result)
}

// --- arm64_lower_sve_ternary_bitwise.go ---
type arm64SVETernaryBitwiseSpec struct {
	intrinsic string
	rawBase   uint32
}

var arm64SVETernaryBitwiseSpecs = map[Op]arm64SVETernaryBitwiseSpec{
	"ZBCAX":  {"bcax", 0x04603800},
	"ZBSL":   {"bsl", 0x04203c00},
	"ZBSL1N": {"bsl1n", 0x04603c00},
	"ZBSL2N": {"bsl2n", 0x04a03c00},
	"ZEOR3":  {"eor3", 0x04203800},
	"ZNBSL":  {"nbsl", 0x04e03c00},
}

var arm64RawSVETernaryBitwiseOps = func() map[uint32]Op {
	ops := make(map[uint32]Op)
	for op, spec := range arm64SVETernaryBitwiseSpecs {
		ops[spec.rawBase] = op
	}
	return ops
}()

func decodeARM64RawSVETernaryBitwise(word uint32) (Instr, bool) {
	op, ok := arm64RawSVETernaryBitwiseOps[word&0xffe0fc00]
	if !ok {
		return Instr{}, false
	}
	vector := func(index uint32) Operand {
		return Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.D", index&31))}
	}
	return Instr{Op: op, Raw: fmt.Sprintf("WORD $%#08x", word), Args: []Operand{
		vector(word >> 5), vector(word >> 16), vector(word), vector(word),
	}}, true
}

func (c *arm64Ctx) lowerARM64SVETernaryBitwise(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVETernaryBitwiseSpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 4 {
		return true, false, fmt.Errorf("arm64 %s expects Zk.D, Zm.D, Zdn.D, Zdn.D without a suffix: %q", op, ins.Raw)
	}
	third, thirdBits, thirdOK := arm64ParseSVEZElementReg(ins.Args[0])
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[1])
	first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[2])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[3])
	if !thirdOK || !secondOK || !firstOK || !destinationOK || thirdBits != 64 || secondBits != 64 || firstBits != 64 || destinationBits != 64 || first != destination {
		return true, false, fmt.Errorf("arm64 %s requires D-width operands and one destructive destination: %q", op, ins.Raw)
	}
	firstValue, vectorType, err := c.loadZRegElements(first, 64)
	if err != nil {
		return true, false, err
	}
	secondValue, _, err := c.loadZRegElements(second, 64)
	if err != nil {
		return true, false, err
	}
	thirdValue, _, err := c.loadZRegElements(third, 64)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv2i64(%s %s, %s %s, %s %s)\n", result, vectorType, spec.intrinsic, vectorType, firstValue, vectorType, secondValue, vectorType, thirdValue)
	return true, false, c.storeZRegElements(destination, 64, "%"+result)
}

// --- arm64_lower_sve_unpack.go ---
var arm64SVEUnpackIntrinsics = map[Op]string{
	"ZSUNPKHI": "sunpkhi",
	"ZSUNPKLO": "sunpklo",
	"ZUUNPKHI": "uunpkhi",
	"ZUUNPKLO": "uunpklo",
}

func (c *arm64Ctx) lowerARM64SVEUnpack(op Op, ins Instr) (ok bool, terminated bool, err error) {
	intrinsic, ok := arm64SVEUnpackIntrinsics[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 {
		return true, false, fmt.Errorf("arm64 %s expects Zn.B|H|S, Zd.H|S|D without a suffix: %q", op, ins.Raw)
	}
	source, sourceBits, sourceOK := arm64ParseSVEZElementReg(ins.Args[0])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[1])
	if !sourceOK || !destinationOK || (sourceBits != 8 && sourceBits != 16 && sourceBits != 32) || destinationBits != sourceBits*2 {
		return true, false, fmt.Errorf("arm64 %s requires a B-to-H, H-to-S, or S-to-D widening pair: %q", op, ins.Raw)
	}
	sourceValue, sourceType, err := c.loadZRegElements(source, sourceBits)
	if err != nil {
		return true, false, err
	}
	destinationType, _, err := arm64SVEVectorType(destinationBits)
	if err != nil {
		return true, false, err
	}
	destinationLanes := 128 / destinationBits
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s)\n", result, destinationType, intrinsic, destinationLanes, destinationBits, sourceType, sourceValue)
	return true, false, c.storeZRegElements(destination, destinationBits, "%"+result)
}

// --- arm64_lower_sve_vector_predicate_incdec.go ---
type arm64SVEVectorPredicateIncDecSpec struct {
	intrinsic  string
	increment  bool
	saturating bool
}

var arm64SVEVectorPredicateIncDecSpecs = map[Op]arm64SVEVectorPredicateIncDecSpec{
	"ZDECP":   {},
	"ZINCP":   {increment: true},
	"ZSQDECP": {intrinsic: "sqdecp", saturating: true},
	"ZSQINCP": {intrinsic: "sqincp", increment: true, saturating: true},
	"ZUQDECP": {intrinsic: "uqdecp", saturating: true},
	"ZUQINCP": {intrinsic: "uqincp", increment: true, saturating: true},
}

func (c *arm64Ctx) lowerARM64SVEVectorPredicateIncDec(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVEVectorPredicateIncDecSpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 {
		return true, false, fmt.Errorf("arm64 %s expects Pm.H/S/D, Zdn.H/S/D without a suffix: %q", op, ins.Raw)
	}
	predicate, predicateBits, predicateOK := arm64ParseSVEPredicateElement(ins.Args[0])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[1])
	if !predicateOK || !destinationOK || predicateBits == 8 || predicateBits != destinationBits {
		return true, false, fmt.Errorf("arm64 %s requires matching H/S/D predicate and vector arrangements: %q", op, ins.Raw)
	}
	predicateValue, predicateType, err := c.loadPRegElements(predicate, predicateBits)
	if err != nil {
		return true, false, err
	}
	value, vectorType, err := c.loadZRegElements(destination, destinationBits)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / destinationBits
	result := c.newTmp()
	if spec.saturating {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s)\n", result, vectorType, spec.intrinsic, lanes, destinationBits, vectorType, value, predicateType, predicateValue)
		return true, false, c.storeZRegElements(destination, destinationBits, "%"+result)
	}
	governing, _, err := c.allTruePRegElements(destinationBits)
	if err != nil {
		return true, false, err
	}
	count := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call i64 @llvm.aarch64.sve.cntp.nxv%di1(%s %s, %s %s)\n", count, lanes, predicateType, governing, predicateType, predicateValue)
	countValue := "%" + count
	if destinationBits != 64 {
		narrowed := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i%d\n", narrowed, countValue, destinationBits)
		countValue = "%" + narrowed
	}
	inserted := c.newTmp()
	splat := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement %s poison, i%d %s, i64 0\n", inserted, vectorType, destinationBits, countValue)
	fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s poison, <vscale x %d x i32> zeroinitializer\n", splat, vectorType, inserted, vectorType, lanes)
	operation := "sub"
	if spec.increment {
		operation = "add"
	}
	fmt.Fprintf(c.b, "  %%%s = %s %s %s, %%%s\n", result, operation, vectorType, value, splat)
	return true, false, c.storeZRegElements(destination, destinationBits, "%"+result)
}

// --- arm64_lower_sve_whole_vector_memory.go ---
var arm64SVEWholeVectorMemoryOps = map[Op]bool{
	"ZLDR": true,
	"ZSTR": false,
}

func (c *arm64Ctx) lowerARM64SVEWholeVectorMemory(op Op, ins Instr) (ok bool, terminated bool, err error) {
	load, ok := arm64SVEWholeVectorMemoryOps[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 {
		return true, false, fmt.Errorf("arm64 %s expects its two-operand Go 1.27 form: %q", op, ins.Raw)
	}
	memoryOperand := 0
	vectorOperand := 1
	if !load {
		vectorOperand, memoryOperand = memoryOperand, vectorOperand
	}
	vector, vectorOK := arm64ParseSVEBareZReg(ins.Args[vectorOperand])
	if !vectorOK || ins.Args[memoryOperand].Kind != OpMem {
		return true, false, fmt.Errorf("arm64 %s requires a MUL VL address and bare Z0..Z31: %q", op, ins.Raw)
	}
	address, err := c.arm64SVEVLAddress(ins.Args[memoryOperand].Mem, -256, 255, 16)
	if err != nil {
		return true, false, fmt.Errorf("arm64 %s: %w: %q", op, err, ins.Raw)
	}
	pointer := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pointer, address)
	if load {
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load <vscale x 16 x i8>, ptr %%%s, align 1\n", value, pointer)
		return true, false, c.storeZReg(vector, "%"+value)
	}
	value, err := c.loadZReg(vector)
	if err != nil {
		return true, false, err
	}
	fmt.Fprintf(c.b, "  store <vscale x 16 x i8> %s, ptr %%%s, align 1\n", value, pointer)
	return true, false, nil
}

func arm64ParseSVEBareZReg(operand Operand) (int, bool) {
	if operand.Kind != OpReg {
		return 0, false
	}
	name := strings.ToUpper(strings.TrimSpace(string(operand.Reg)))
	if strings.Contains(name, ".") || !strings.HasPrefix(name, "Z") {
		return 0, false
	}
	index, err := strconv.Atoi(strings.TrimPrefix(name, "Z"))
	return index, err == nil && index >= 0 && index <= 31
}

// --- arm64_lower_sve_xar.go ---
func decodeARM64RawSVEXAR(word uint32) (Instr, bool) {
	if word&0xff20fc00 != 0x04203400 {
		return Instr{}, false
	}
	encoded := int(word>>16&31 | word>>17&96)
	if encoded < 8 { // tsize=0000 is unallocated.
		return Instr{}, false
	}
	size := bits.Len(uint(encoded)) - 4
	elementBits := 8 << size
	width := "BHSD"[size]
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", word&31, width))}
	return Instr{Op: "ZXAR", Raw: fmt.Sprintf("WORD $%#08x", word), Args: []Operand{
		{Kind: OpImm, Imm: int64(2*elementBits - encoded)},
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", word>>5&31, width))},
		destination, destination,
	}}, true
}

func (c *arm64Ctx) lowerARM64RawSVEXAR(ins Instr) error {
	second, width, _ := arm64ParseSVEZElementReg(ins.Args[1])
	destination, _, _ := arm64ParseSVEZElementReg(ins.Args[2])
	return c.lowerARM64SVEXARForm(destination, second, width, ins.Args[0].Imm)
}

func (c *arm64Ctx) lowerARM64SVEXAR(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZXAR" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 4 || ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" {
		return true, false, fmt.Errorf("arm64 ZXAR expects $shift, Zm.T, Zdn.T, Zdn.T without a suffix: %q", ins.Raw)
	}
	shift := ins.Args[0].Imm
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[1])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	repeatedDestination, repeatedBits, repeatedOK := arm64ParseSVEZElementReg(ins.Args[3])
	if !secondOK || !destinationOK || !repeatedOK || secondBits != destinationBits || repeatedBits != destinationBits || repeatedDestination != destination || shift < 1 || shift >= int64(destinationBits) {
		return true, false, fmt.Errorf("arm64 ZXAR requires matching destructive B/H/S/D operands and shift $1..$elementBits-1: %q", ins.Raw)
	}
	return true, false, c.lowerARM64SVEXARForm(destination, second, destinationBits, shift)
}

func (c *arm64Ctx) lowerARM64SVEXARForm(destination, second, destinationBits int, shift int64) error {
	destinationValue, vectorType, err := c.loadZRegElements(destination, destinationBits)
	if err != nil {
		return err
	}
	secondValue, _, err := c.loadZRegElements(second, destinationBits)
	if err != nil {
		return err
	}
	lanes := 128 / destinationBits
	result := c.newTmp()
	if shift == int64(destinationBits) {
		// Architectural WORD encodings include a full-width rotation. Go's
		// named encoder rejects this spelling; preserve that frontend boundary.
		fmt.Fprintf(c.b, "  %%%s = xor %s %s, %s\n", result, vectorType, destinationValue, secondValue)
	} else {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.xar.nxv%di%d(%s %s, %s %s, i32 %d)\n", result, vectorType, lanes, destinationBits, vectorType, destinationValue, vectorType, secondValue, shift)
	}
	return c.storeZRegElements(destination, destinationBits, "%"+result)
}

// --- arm64_lower_vector_bit_reverse.go ---
func (c *arm64Ctx) lowerARM64VectorBitReverse(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "VRBIT" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != "VRBIT" || len(ins.Args) != 2 ||
		ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("arm64 VRBIT expects Vm.B8/B16, Vd.B8/B16: %q", ins.Raw)
	}
	sourceArrangement, sourceOK := parseARM64VectorArrangement(ins.Args[0].Reg)
	destinationArrangement, destinationOK := parseARM64VectorArrangement(ins.Args[1].Reg)
	if !sourceOK || !destinationOK || sourceArrangement != destinationArrangement ||
		sourceArrangement.elementBits != 8 || sourceArrangement.lanes != 8 && sourceArrangement.lanes != 16 {
		return true, false, fmt.Errorf("arm64 VRBIT requires matching B8 or B16 arrangements: %q", ins.Raw)
	}
	source, err := c.loadARM64VectorInteger(ins.Args[0].Reg, sourceArrangement)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call <%d x i8> @llvm.bitreverse.v%di8(<%d x i8> %s)\n",
		result, sourceArrangement.lanes, sourceArrangement.lanes, sourceArrangement.lanes, source)
	return true, false, c.storeARM64VectorInteger(ins.Args[1].Reg, destinationArrangement, "%"+result)
}

// --- arm64_lower_vector_constant.go ---
// lowerARM64VectorConstant implements the complete Go assembler family for
// materializing 32-, 64-, and 128-bit constants in a vector register:
//
//	VMOVS $lo32, Vd
//	VMOVD $lo64, Vd
//	VMOVQ $lo64, $hi64, Vd
func (c *arm64Ctx) lowerARM64VectorConstant(op Op, ins Instr) (ok bool, terminated bool, err error) {
	var bits int
	switch op {
	case "VMOVS":
		bits = 32
	case "VMOVD":
		bits = 64
	case "VMOVQ":
		bits = 128
	default:
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) {
		return true, false, fmt.Errorf("arm64 %s does not accept an instruction suffix: %q", op, ins.Raw)
	}
	wantArgs := 2
	if bits == 128 {
		wantArgs = 3
	}
	if len(ins.Args) != wantArgs {
		return true, false, fmt.Errorf("arm64 %s expects %d operands: %q", op, wantArgs, ins.Raw)
	}
	for i := 0; i < wantArgs-1; i++ {
		if ins.Args[i].Kind != OpImm {
			return true, false, fmt.Errorf("arm64 %s operand %d must be an immediate: %q", op, i+1, ins.Raw)
		}
	}
	dst := ins.Args[wantArgs-1]
	if dst.Kind != OpReg || strings.Contains(string(dst.Reg), ".") {
		return true, false, fmt.Errorf("arm64 %s destination must be a bare V register: %q", op, ins.Raw)
	}
	if _, valid := arm64ParseVReg(dst.Reg); !valid {
		return true, false, fmt.Errorf("arm64 %s destination must be a bare V register: %q", op, ins.Raw)
	}

	var vector, vectorType string
	switch bits {
	case 32:
		vectorType = "<4 x i32>"
		vector = c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <4 x i32> zeroinitializer, i32 %d, i32 0\n", vector, uint32(ins.Args[0].Imm))
	case 64:
		vectorType = "<2 x i64>"
		vector = c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> zeroinitializer, i64 %d, i32 0\n", vector, uint64(ins.Args[0].Imm))
	case 128:
		vectorType = "<2 x i64>"
		low := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> zeroinitializer, i64 %d, i32 0\n", low, uint64(ins.Args[0].Imm))
		vector = c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> %%%s, i64 %d, i32 1\n", vector, low, uint64(ins.Args[1].Imm))
	}
	bytes := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", bytes, vectorType, vector)
	return true, false, c.storeVReg(dst.Reg, "%"+bytes)
}

// --- arm64_lower_vector_reverse.go ---
func (c *arm64Ctx) lowerARM64VectorReverse(op Op, ins Instr) (ok bool, terminated bool, err error) {
	groupBytes, handled := map[Op]int{
		"VREV16": 2,
		"VREV32": 4,
		"VREV64": 8,
	}[op]
	if !handled {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("arm64 %s expects two same-arrangement vector registers and no suffix: %q", op, ins.Raw)
	}
	sourceArrangement, sourceOK := parseARM64VectorArrangement(ins.Args[0].Reg)
	destinationArrangement, destinationOK := parseARM64VectorArrangement(ins.Args[1].Reg)
	if !sourceOK || !destinationOK || sourceArrangement != destinationArrangement {
		return true, false, fmt.Errorf("arm64 %s expects matching vector arrangements: %q", op, ins.Raw)
	}
	elementBytes := sourceArrangement.elementBits / 8
	if elementBytes == 0 || elementBytes >= groupBytes {
		return true, false, fmt.Errorf("arm64 %s requires elements narrower than its %d-bit reversal groups: %q", op, groupBytes*8, ins.Raw)
	}
	source, err := c.loadARM64VectorInteger(ins.Args[0].Reg, sourceArrangement)
	if err != nil {
		return true, false, err
	}
	vectorType := fmt.Sprintf("<%d x i%d>", sourceArrangement.lanes, sourceArrangement.elementBits)
	groupElements := groupBytes / elementBytes
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector %s %s, %s poison, <%d x i32> <", result, vectorType, source, vectorType, sourceArrangement.lanes)
	for lane := 0; lane < sourceArrangement.lanes; lane++ {
		if lane != 0 {
			c.b.WriteString(", ")
		}
		groupStart := lane / groupElements * groupElements
		reversedLane := groupStart + groupElements - 1 - lane%groupElements
		fmt.Fprintf(c.b, "i32 %d", reversedLane)
	}
	c.b.WriteString(">\n")
	return true, false, c.storeARM64VectorInteger(ins.Args[1].Reg, destinationArrangement, "%"+result)
}
