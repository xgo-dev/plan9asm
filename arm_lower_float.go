package plan9asm

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

func isARMFReg(r Reg) bool {
	s := strings.ToUpper(strings.TrimSpace(string(r)))
	if !strings.HasPrefix(s, "F") {
		return false
	}
	n, err := strconv.Atoi(strings.TrimPrefix(s, "F"))
	return err == nil && n >= 0 && n <= 15
}

func armSingleRegisterNumber(r Reg) (int, bool) {
	s := strings.ToUpper(strings.TrimSpace(string(r)))
	if !strings.HasPrefix(s, "S") {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimPrefix(s, "S"))
	return n, err == nil && n >= 0 && n <= 31
}

func armSingleOperandNumber(op Operand) (int, bool) {
	switch op.Kind {
	case OpReg:
		return armSingleRegisterNumber(op.Reg)
	case OpIdent:
		return armSingleRegisterNumber(Reg(op.Ident))
	default:
		return 0, false
	}
}

func isARMGeneralReg(r Reg) bool {
	s := strings.ToUpper(strings.TrimSpace(string(r)))
	if s == "SP" || s == "PC" {
		return true
	}
	if !strings.HasPrefix(s, "R") {
		return false
	}
	n, err := strconv.Atoi(strings.TrimPrefix(s, "R"))
	return err == nil && n >= 0 && n <= 15
}

func armInstructionSuffixes(ins Instr) []string {
	parts := strings.Split(strings.ToUpper(strings.TrimSpace(string(ins.Op))), ".")
	if len(parts) < 2 {
		return nil
	}
	return parts[1:]
}

func armRequireConditionOnlySuffix(ins Instr) error {
	for _, suffix := range armInstructionSuffixes(ins) {
		if suffix != "" && !armCondCodes[suffix] {
			return fmt.Errorf("arm %s suffix %q is absent from the Go 1.27 optab: %q", ins.Op, suffix, ins.Raw)
		}
	}
	return nil
}

func armMemoryModifiers(ins Instr) (postIndex, writeback, up bool, err error) {
	for _, suffix := range armInstructionSuffixes(ins) {
		switch suffix {
		case "", "AL":
		case "P":
			postIndex = true
		case "W":
			writeback = true
		case "U":
			up = true
		case "PW", "WP":
			postIndex = true
			writeback = true
		default:
			if !armCondCodes[suffix] {
				return false, false, false, fmt.Errorf("arm %s suffix %q is absent from the Go memory optab: %q", ins.Op, suffix, ins.Raw)
			}
		}
	}
	return postIndex, writeback, up, nil
}

func armRawOperands(ins Instr) []string {
	raw := strings.TrimSpace(ins.Raw)
	separator := strings.IndexAny(raw, " \t")
	if separator < 0 {
		return nil
	}
	return splitTopLevelCSV(strings.TrimSpace(raw[separator+1:]))
}

func armFloatImmediateBits(ins Instr, bits int) (string, error) {
	operands := armRawOperands(ins)
	if len(operands) == 0 {
		return "", fmt.Errorf("arm floating move cannot recover its source spelling: %q", ins.Raw)
	}
	source := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(operands[0]), "$"))
	// The Go ARM parser classifies integer constants as C_*CON, none of which
	// occur in MOVF/MOVD's rows. Require a floating token rather than silently
	// accepting forms such as MOVD $1, F0.
	if !strings.ContainsAny(source, ".eEpP") {
		return "", fmt.Errorf("arm MOVF/MOVD immediate must be a Go floating constant: %q", ins.Raw)
	}
	if ins.Args[0].ImmRaw != "" {
		return "", fmt.Errorf("arm unresolved floating immediate %q", ins.Args[0].ImmRaw)
	}
	value := math.Float64frombits(uint64(ins.Args[0].Imm))
	if bits == 32 {
		return strconv.FormatUint(uint64(math.Float32bits(float32(value))), 10), nil
	}
	return strconv.FormatUint(math.Float64bits(value), 10), nil
}

func (c *armCtx) selectFRegWrite(dst Reg, cond, value string) error {
	if cond == "" || strings.EqualFold(cond, "AL") {
		return c.storeFReg(dst, value)
	}
	condition, err := c.condValue(cond)
	if err != nil {
		return err
	}
	old, err := c.loadFReg(dst)
	if err != nil {
		return err
	}
	selected := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, i64 %s, i64 %s\n", selected, condition, value, old)
	return c.storeFReg(dst, "%"+selected)
}

func (c *armCtx) normalizeARMFloatBits(value string, bits int) string {
	if bits == 64 {
		return value
	}
	wide := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", wide, value)
	return "%" + wide
}

func (c *armCtx) loadARMFloatMemoryBits(op Operand, bits int, postIndex, writeback bool) (string, error) {
	switch op.Kind {
	case OpFP:
		return c.loadARMFrameBits(op.FPOffset, bits)
	case OpSym:
		ptr, err := c.ptrFromSB(op.Sym)
		if err != nil {
			return "", err
		}
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load i%d, ptr %s, align 1\n", value, bits, ptr)
		return "%" + value, nil
	case OpMem:
		value, err := c.loadMem(op.Mem, bits, postIndex, false)
		if err != nil {
			return "", err
		}
		if writeback && !postIndex {
			if err := c.updatePostInc(op.Mem.Base, op.Mem.Off); err != nil {
				return "", err
			}
		}
		return value, nil
	default:
		return "", fmt.Errorf("arm floating load has unsupported operand %s", op.String())
	}
}

func (c *armCtx) storeARMFloatMemoryBits(op Operand, bits int, postIndex, writeback bool, value string) error {
	switch op.Kind {
	case OpFP:
		return c.storeARMFrameBits(op.FPOffset, bits, value)
	case OpSym:
		ptr, err := c.ptrFromSB(op.Sym)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store i%d %s, ptr %s, align 1\n", bits, value, ptr)
		return nil
	case OpMem:
		if err := c.storeMem(op.Mem, bits, postIndex, value); err != nil {
			return err
		}
		if writeback && !postIndex {
			return c.updatePostInc(op.Mem.Base, op.Mem.Off)
		}
		return nil
	default:
		return fmt.Errorf("arm floating store has unsupported operand %s", op.String())
	}
}

func isARMFloatMemory(op Operand) bool {
	return op.Kind == OpFP || op.Kind == OpMem || (op.Kind == OpSym && !strings.HasPrefix(strings.TrimSpace(op.Sym), "$"))
}

func (c *armCtx) lowerARMFloatMove(op, cond string, ins Instr) (ok bool, terminated bool, err error) {
	bits := 32
	if op == "MOVD" {
		bits = 64
	}
	if len(ins.Args) != 2 {
		return true, false, fmt.Errorf("arm %s expects exactly 2 operands: %q", op, ins.Raw)
	}
	postIndex, writeback, up, err := armMemoryModifiers(ins)
	if err != nil {
		return true, false, err
	}
	src, dst := ins.Args[0], ins.Args[1]
	srcF := src.Kind == OpReg && isARMFReg(src.Reg)
	dstF := dst.Kind == OpReg && isARMFReg(dst.Reg)
	srcMemory := isARMFloatMemory(src)
	dstMemory := isARMFloatMemory(dst)
	valid := (srcF && (dstF || dstMemory)) || (srcMemory && dstF) || (src.Kind == OpImm && dstF)
	if !valid {
		return true, false, fmt.Errorf("arm %s operands are absent from the Go 1.27 optab: %q", op, ins.Raw)
	}
	if (postIndex || writeback || up) && !srcMemory && !dstMemory {
		return true, false, fmt.Errorf("arm %s addressing suffix requires a memory operand: %q", op, ins.Raw)
	}
	memory := src
	if dstMemory {
		memory = dst
	}
	if up && memory.Kind == OpMem && memory.Mem.Off < 0 {
		return true, false, fmt.Errorf("arm %s .U cannot be used with a negative offset: %q", op, ins.Raw)
	}
	if cond != "" && !strings.EqualFold(cond, "AL") {
		err := c.emitConditionalEffect(cond, func() error {
			_, _, innerErr := c.lowerARMFloatMove(op, "", ins)
			return innerErr
		})
		return true, false, err
	}

	var value string
	switch {
	case src.Kind == OpImm:
		value, err = armFloatImmediateBits(ins, bits)
	case srcF:
		value, err = c.loadFReg(src.Reg)
		if err == nil && bits == 32 {
			narrow := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", narrow, value)
			value = "%" + narrow
		}
	case srcMemory:
		value, err = c.loadARMFloatMemoryBits(src, bits, postIndex, writeback)
	}
	if err != nil {
		return true, false, err
	}
	if dstF {
		return true, false, c.selectFRegWrite(dst.Reg, "", c.normalizeARMFloatBits(value, bits))
	}
	return true, false, c.storeARMFloatMemoryBits(dst, bits, postIndex, writeback, value)
}

func (c *armCtx) loadARMFloatRegValue(reg Reg, bits int) (string, error) {
	value, err := c.loadFReg(reg)
	if err != nil {
		return "", err
	}
	integerType := "i64"
	floatType := "double"
	if bits == 32 {
		narrow := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", narrow, value)
		value = "%" + narrow
		integerType = "i32"
		floatType = "float"
	}
	converted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", converted, integerType, value, floatType)
	return "%" + converted, nil
}

func (c *armCtx) storeARMFloatRegValue(reg Reg, cond string, bits int, value string) error {
	floatType := "double"
	integerType := "i64"
	if bits == 32 {
		floatType = "float"
		integerType = "i32"
	}
	encoded := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", encoded, floatType, value, integerType)
	bitsValue := "%" + encoded
	if bits == 32 {
		bitsValue = c.normalizeARMFloatBits(bitsValue, bits)
	}
	return c.selectFRegWrite(reg, cond, bitsValue)
}

func (c *armCtx) setARMFloatCompareFlags(lhs, rhs, floatType, cond string) error {
	if cond != "" && !strings.EqualFold(cond, "AL") {
		return c.emitConditionalEffect(cond, func() error {
			return c.setARMFloatCompareFlags(lhs, rhs, floatType, "")
		})
	}
	comparisons := []struct {
		predicate string
		slot      string
	}{
		{"olt", c.flagsNSlot},
		{"oeq", c.flagsZSlot},
		// ARM VFP compare sets C for greater, equal, and unordered.
		{"uge", c.flagsCSlot},
		{"uno", c.flagsVSlot},
	}
	for _, comparison := range comparisons {
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fcmp %s %s %s, %s\n", value, comparison.predicate, floatType, lhs, rhs)
		c.storeFlag(comparison.slot, "%"+value)
	}
	c.flagsWritten = true
	return nil
}

func (c *armCtx) lowerARMFloatCompare(op, cond string, ins Instr) (ok bool, terminated bool, err error) {
	switch op {
	case "CMPF", "CMPD":
	default:
		return false, false, nil
	}
	if err := armRequireConditionOnlySuffix(ins); err != nil {
		return true, false, err
	}
	if len(ins.Args) < 1 || len(ins.Args) > 2 {
		return true, false, fmt.Errorf("arm %s expects Fsrc or Fsrc1,Fsrc2: %q", op, ins.Raw)
	}
	for _, arg := range ins.Args {
		if arg.Kind != OpReg || !isARMFReg(arg.Reg) {
			return true, false, fmt.Errorf("arm %s accepts only floating registers: %q", op, ins.Raw)
		}
	}
	bits := 32
	floatType := "float"
	if op == "CMPD" {
		bits = 64
		floatType = "double"
	}
	// obj/arm encodes p.From as Vm and p.Reg as Vd. With one operand Vd is
	// compared against zero; with two, Plan 9 order is Vm,Vd.
	rhs := "0.000000e+00"
	lhsIndex := 0
	if len(ins.Args) == 2 {
		lhsIndex = 1
		var loadErr error
		rhs, loadErr = c.loadARMFloatRegValue(ins.Args[0].Reg, bits)
		if loadErr != nil {
			return true, false, loadErr
		}
	}
	lhs, err := c.loadARMFloatRegValue(ins.Args[lhsIndex].Reg, bits)
	if err != nil {
		return true, false, err
	}
	return true, false, c.setARMFloatCompareFlags(lhs, rhs, floatType, cond)
}

func armWordFloatConversionUnsigned(ins Instr) (bool, error) {
	unsigned := false
	for _, suffix := range armInstructionSuffixes(ins) {
		switch {
		case suffix == "", suffix == "AL", armCondCodes[suffix]:
		case suffix == "U":
			unsigned = true
		default:
			return false, fmt.Errorf("arm %s suffix %q is absent from the Go 1.27 conversion optab: %q", ins.Op, suffix, ins.Raw)
		}
	}
	return unsigned, nil
}

func (c *armCtx) lowerARMWordFloatConversion(op, cond string, ins Instr) (ok bool, terminated bool, err error) {
	switch op {
	case "MOVWF", "MOVWD", "MOVFW", "MOVDW":
	default:
		return false, false, nil
	}
	unsigned, err := armWordFloatConversionUnsigned(ins)
	if err != nil {
		return true, false, err
	}
	if len(ins.Args) != 2 {
		return true, false, fmt.Errorf("arm %s expects exactly 2 operands: %q", op, ins.Raw)
	}
	wordToFloat := strings.HasPrefix(op, "MOVW")
	floatBits := 32
	if strings.Contains(op, "D") {
		floatBits = 64
	}
	src, dst := ins.Args[0], ins.Args[1]
	srcF := src.Kind == OpReg && isARMFReg(src.Reg)
	dstF := dst.Kind == OpReg && isARMFReg(dst.Reg)
	srcSNumber, srcS := armSingleOperandNumber(src)
	dstSNumber, dstS := armSingleOperandNumber(dst)
	// S-register spellings are produced by the architectural decoder for raw
	// VCVT encodings. They are not part of the source-level Go optab, whose
	// floating register class is F0..F15.
	rawSingleRegisters := strings.Contains(ins.Raw, "decoded from WORD") && floatBits == 32
	if !rawSingleRegisters {
		srcS = false
		dstS = false
	}
	srcR := src.Kind == OpReg && isARMGeneralReg(src.Reg) && !isARMFReg(src.Reg)
	dstR := dst.Kind == OpReg && isARMGeneralReg(dst.Reg) && !isARMFReg(dst.Reg)
	if wordToFloat {
		if (!srcF && !srcS && !srcR) || (!dstF && !dstS) {
			return true, false, fmt.Errorf("arm %s expects R/F word source and F destination: %q", op, ins.Raw)
		}
	} else if (!srcF && !srcS) || (!dstF && !dstS && !dstR) {
		return true, false, fmt.Errorf("arm %s expects F source and R/F word destination: %q", op, ins.Raw)
	}
	if cond != "" && !strings.EqualFold(cond, "AL") {
		err := c.emitConditionalEffect(cond, func() error {
			_, _, innerErr := c.lowerARMWordFloatConversion(op, "", ins)
			return innerErr
		})
		return true, false, err
	}

	floatType := "float"
	if floatBits == 64 {
		floatType = "double"
	}
	if wordToFloat {
		var integer string
		switch {
		case srcR:
			integer, err = c.loadReg(src.Reg)
		case srcS:
			integer, err = c.loadARMRawSingleBits(srcSNumber)
		default:
			var wide string
			wide, err = c.loadFReg(src.Reg)
			if err == nil {
				narrow := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", narrow, wide)
				integer = "%" + narrow
			}
		}
		if err != nil {
			return true, false, err
		}
		converted := c.newTmp()
		conversion := "sitofp"
		if unsigned {
			conversion = "uitofp"
		}
		fmt.Fprintf(c.b, "  %%%s = %s i32 %s to %s\n", converted, conversion, integer, floatType)
		if dstS {
			bits := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast float %%%s to i32\n", bits, converted)
			return true, false, c.storeARMRawSingleBits(dstSNumber, "%"+bits, "")
		}
		return true, false, c.storeARMFloatRegValue(dst.Reg, "", floatBits, "%"+converted)
	}

	var floating string
	if srcS {
		floating, err = c.loadARMRawVFPRegValue(srcSNumber, 32)
	} else {
		floating, err = c.loadARMFloatRegValue(src.Reg, floatBits)
	}
	if err != nil {
		return true, false, err
	}
	converted := c.newTmp()
	conversion := "fptosi"
	if unsigned {
		conversion = "fptoui"
	}
	fmt.Fprintf(c.b, "  %%%s = %s %s %s to i32\n", converted, conversion, floatType, floating)
	integer := "%" + converted
	if dstR {
		return true, false, c.storeReg(dst.Reg, integer)
	}
	if dstS {
		return true, false, c.storeARMRawSingleBits(dstSNumber, integer, "")
	}
	return true, false, c.selectFRegWrite(dst.Reg, "", c.normalizeARMFloatBits(integer, 32))
}

func armScalarFloatArithmeticKind(op string) (kind string, bits int, accumulating bool, ok bool) {
	bits = 32
	if strings.HasSuffix(op, "D") {
		bits = 64
	}
	switch op {
	case "ADDF", "ADDD":
		return "add", bits, false, true
	case "SUBF", "SUBD":
		return "sub", bits, false, true
	case "MULF", "MULD":
		return "mul", bits, false, true
	case "NMULF", "NMULD":
		return "nmul", bits, false, true
	case "DIVF", "DIVD":
		return "div", bits, false, true
	case "MULAF", "MULAD", "FMULAF", "FMULAD":
		return "madd", bits, true, true
	case "MULSF", "MULSD", "FMULSF", "FMULSD":
		return "msub", bits, true, true
	case "NMULAF", "NMULAD", "FNMULAF", "FNMULAD":
		return "nmadd", bits, true, true
	case "NMULSF", "NMULSD", "FNMULSF", "FNMULSD":
		return "nmsub", bits, true, true
	default:
		return "", 0, false, false
	}
}

func (c *armCtx) lowerARMScalarFloatArithmetic(op, cond string, ins Instr) (ok bool, terminated bool, err error) {
	kind, bits, accumulating, handled := armScalarFloatArithmeticKind(op)
	if !handled {
		return false, false, nil
	}
	if err := armRequireConditionOnlySuffix(ins); err != nil {
		return true, false, err
	}
	wantMin := 2
	if accumulating {
		wantMin = 3
	}
	if len(ins.Args) < wantMin || len(ins.Args) > 3 {
		if accumulating {
			return true, false, fmt.Errorf("arm %s expects Fsrc1, Fsrc2, Faccumulator: %q", op, ins.Raw)
		}
		return true, false, fmt.Errorf("arm %s expects Fsrc,Fdst or Fsrc1,Fsrc2,Fdst: %q", op, ins.Raw)
	}
	for _, arg := range ins.Args {
		if arg.Kind != OpReg || !isARMFReg(arg.Reg) {
			return true, false, fmt.Errorf("arm %s accepts only floating registers: %q", op, ins.Raw)
		}
	}
	if cond != "" && !strings.EqualFold(cond, "AL") {
		err := c.emitConditionalEffect(cond, func() error {
			_, _, innerErr := c.lowerARMScalarFloatArithmetic(op, "", ins)
			return innerErr
		})
		return true, false, err
	}

	// obj/arm encodes p.From as Vm and p.Reg (or p.To for two-operand
	// instructions) as Vn. Plan 9 order is therefore Vm,Vn,Vd and subtraction
	// and division must compute Vn op Vm.
	rhs, err := c.loadARMFloatRegValue(ins.Args[0].Reg, bits)
	if err != nil {
		return true, false, err
	}
	lhsIndex := 1
	dstIndex := len(ins.Args) - 1
	lhs, err := c.loadARMFloatRegValue(ins.Args[lhsIndex].Reg, bits)
	if err != nil {
		return true, false, err
	}
	floatType := "float"
	if bits == 64 {
		floatType = "double"
	}
	emitBinary := func(operation, left, right string) string {
		name := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s %s %s, %s\n", name, operation, floatType, left, right)
		return "%" + name
	}
	emitNeg := func(value string) string {
		name := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fneg %s %s\n", name, floatType, value)
		return "%" + name
	}

	var result string
	switch kind {
	case "add":
		result = emitBinary("fadd", lhs, rhs)
	case "sub":
		result = emitBinary("fsub", lhs, rhs)
	case "mul":
		result = emitBinary("fmul", lhs, rhs)
	case "nmul":
		result = emitNeg(emitBinary("fmul", lhs, rhs))
	case "div":
		result = emitBinary("fdiv", lhs, rhs)
	default:
		product := emitBinary("fmul", lhs, rhs)
		accumulator, loadErr := c.loadARMFloatRegValue(ins.Args[dstIndex].Reg, bits)
		if loadErr != nil {
			return true, false, loadErr
		}
		switch kind {
		case "madd":
			result = emitBinary("fadd", accumulator, product)
		case "msub":
			result = emitBinary("fsub", accumulator, product)
		case "nmadd":
			result = emitNeg(emitBinary("fadd", accumulator, product))
		case "nmsub":
			result = emitBinary("fsub", product, accumulator)
		}
	}
	return true, false, c.storeARMFloatRegValue(ins.Args[dstIndex].Reg, "", bits, result)
}

func (c *armCtx) lowerFloat(op, cond string, ins Instr) (ok bool, terminated bool, err error) {
	if ok, terminated, err := c.lowerARMFloatCompare(op, cond, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARMWordFloatConversion(op, cond, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARMScalarFloatArithmetic(op, cond, ins); ok {
		return ok, terminated, err
	}
	switch op {
	case "NEGF", "NEGD", "ABSF", "ABSD", "SQRTF", "SQRTD", "MOVFD", "MOVDF":
	default:
		return false, false, nil
	}
	if err := armRequireConditionOnlySuffix(ins); err != nil {
		return true, false, err
	}
	if len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || !isARMFReg(ins.Args[0].Reg) || ins.Args[1].Kind != OpReg || !isARMFReg(ins.Args[1].Reg) {
		return true, false, fmt.Errorf("arm %s expects Fsrc, Fdst: %q", op, ins.Raw)
	}
	if cond != "" && !strings.EqualFold(cond, "AL") {
		err := c.emitConditionalEffect(cond, func() error {
			_, _, innerErr := c.lowerFloat(op, "", ins)
			return innerErr
		})
		return true, false, err
	}

	sourceBits, destinationBits := 32, 32
	if strings.HasSuffix(op, "D") {
		sourceBits, destinationBits = 64, 64
	}
	if op == "MOVFD" {
		sourceBits, destinationBits = 32, 64
	} else if op == "MOVDF" {
		sourceBits, destinationBits = 64, 32
	}
	source, err := c.loadARMFloatRegValue(ins.Args[0].Reg, sourceBits)
	if err != nil {
		return true, false, err
	}
	result := source
	resultName := c.newTmp()
	floatType := "float"
	if sourceBits == 64 {
		floatType = "double"
	}
	switch {
	case strings.HasPrefix(op, "NEG"):
		fmt.Fprintf(c.b, "  %%%s = fneg %s %s\n", resultName, floatType, source)
		result = "%" + resultName
	case strings.HasPrefix(op, "ABS"):
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.fabs.f%d(%s %s)\n", resultName, floatType, sourceBits, floatType, source)
		result = "%" + resultName
	case strings.HasPrefix(op, "SQRT"):
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.sqrt.f%d(%s %s)\n", resultName, floatType, sourceBits, floatType, source)
		result = "%" + resultName
	case op == "MOVFD":
		fmt.Fprintf(c.b, "  %%%s = fpext float %s to double\n", resultName, source)
		result = "%" + resultName
	case op == "MOVDF":
		fmt.Fprintf(c.b, "  %%%s = fptrunc double %s to float\n", resultName, source)
		result = "%" + resultName
	}
	return true, false, c.storeARMFloatRegValue(ins.Args[1].Reg, "", destinationBits, result)
}
