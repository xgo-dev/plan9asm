package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
)

// --- amd64_lower_accumulator_sign_extend.go ---
// lowerAccumulatorSignExtend implements the complete Go 1.27 ynone family
// sharing opcodes 98/99: CBW/CWDE/CDQE extend into AX/EAX/RAX, while
// CWD/CDQ/CQO produce the sign half in DX/EDX/RDX. None of them modify flags.
func (c *amd64Ctx) lowerAccumulatorSignExtend(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, known, err := x86AccumulatorSignExtendProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	sourceType := amd64IntegerTypeForBits(int(spec.sourceBytes * 8))
	targetType := amd64IntegerTypeForBits(int(spec.destinationBytes * 8))
	value, err := c.evalIntSized(Operand{Kind: OpReg, Reg: AX}, sourceType)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	if spec.destination == AX {
		fmt.Fprintf(c.b, "  %%%s = sext %s %s to %s\n", result, sourceType, value, targetType)
	} else {
		bits, _ := amd64IntegerTypeBits(sourceType)
		fmt.Fprintf(c.b, "  %%%s = ashr %s %s, %d\n", result, sourceType, value, bits-1)
	}
	return true, false, c.storeRegSized(spec.destination, targetType, "%"+result)
}

// --- amd64_lower_adc_sbb.go ---
func (c *amd64Ctx) emitScalarADCSBB(spec x86LockScalarRMWSpec, typ LLVMType, destinationValue, sourceValue string,
	store func(string) error) error {
	add, bits := spec.stem == "ADC", spec.bits
	wideType := LLVMType(fmt.Sprintf("i%d", bits*2))
	widen := func(value string) string {
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext %s %s to %s\n", wide, typ, value, wideType)
		return "%" + wide
	}
	wideDestination := widen(destinationValue)
	wideSource := widen(sourceValue)
	carry := c.loadFlag(c.flagsCFSlot)
	wideCarryName := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext i1 %s to %s\n", wideCarryName, carry, wideType)
	wideCarry := "%" + wideCarryName

	partial := c.newTmp()
	wideResult := c.newTmp()
	var carryOut string
	if add {
		fmt.Fprintf(c.b, "  %%%s = add %s %s, %s\n", partial, wideType, wideDestination, wideSource)
		fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %s\n", wideResult, wideType, partial, wideCarry)
		carryOut = c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp ugt %s %%%s, %s\n", carryOut, wideType, wideResult, amd64UnsignedMaximum(bits))
	} else {
		fmt.Fprintf(c.b, "  %%%s = add %s %s, %s\n", partial, wideType, wideSource, wideCarry)
		fmt.Fprintf(c.b, "  %%%s = sub %s %s, %%%s\n", wideResult, wideType, wideDestination, partial)
		carryOut = c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp ult %s %s, %%%s\n", carryOut, wideType, wideDestination, partial)
	}

	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to %s\n", result, wideType, wideResult, typ)
	resultValue := "%" + result
	if err := store(resultValue); err != nil {
		return err
	}
	c.setScalarAddSubCarryFlags(typ, add, destinationValue, sourceValue, resultValue, "%"+carryOut)
	return nil
}

func amd64UnsignedMaximum(bits int) string {
	switch bits {
	case 8:
		return "255"
	case 16:
		return "65535"
	case 32:
		return "4294967295"
	case 64:
		return "18446744073709551615"
	default:
		panic(fmt.Sprintf("unsupported x86 integer width %d", bits))
	}
}

// --- amd64_lower_addsub_float.go ---
// lowerAlternatingFloatingAddSubtract implements the complete Go 1.27 yxm
// and _yvaddsubpd families. Even lanes subtract the Plan 9 first source from
// the destination/base source; odd lanes add it.
func (c *amd64Ctx) lowerAlternatingFloatingAddSubtract(op Op, ins Instr) (ok bool, terminated bool, err error) {
	local := ins
	local.Op = op
	form, known, err := x86AlternatingFloatProperties(local, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	if form.legacy && form.memory >= 0 && ins.Args[form.first].Kind != OpFP {
		return true, false, c.emitLegacyAlternatingRoundMemory(local, form, nil)
	}
	first, err := c.loadAlternatingRoundFloat(ins.Args[form.first], form.byteWidth, form.bits, !form.legacy)
	if err != nil {
		return true, false, err
	}
	second, err := c.loadHorizontalFloatingOperand(ins.Args[form.second], form.byteWidth, form.bits)
	if err != nil {
		return true, false, err
	}
	result := c.emitAlternatingFloatingAddSubtract(form.byteWidth, form.bits, first, second)
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <%d x i8>\n", out, amd64FMA3LLVMType(form.byteWidth*8/form.bits, form.bits), result, form.byteWidth)
	if form.legacy {
		return true, false, c.storeX(ins.Args[form.destination].Reg, "%"+out)
	}
	return true, false, c.storePackedMoveOperand(ins.Args[form.destination], form.byteWidth, "%"+out)
}

func (c *amd64Ctx) emitAlternatingFloatingAddSubtract(byteWidth, laneBits int, first, second string) string {
	lanes := byteWidth * 8 / laneBits
	typeName := amd64FMA3LLVMType(lanes, laneBits)
	elementType := amd64FMA3LLVMType(1, laneBits)
	result := "poison"
	for lane := 0; lane < lanes; lane++ {
		left := c.newTmp()
		right := c.newTmp()
		value := c.newTmp()
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", left, typeName, second, lane)
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", right, typeName, first, lane)
		operation := "fsub"
		if lane%2 == 1 {
			operation = "fadd"
		}
		fmt.Fprintf(c.b, "  %%%s = %s %s %%%s, %%%s\n", value, operation, elementType, left, right)
		fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, %s %%%s, i32 %d\n", inserted, typeName, result, elementType, value, lane)
		result = "%" + inserted
	}
	return result
}

// --- amd64_lower_adx.go ---
type amd64ADXCarry uint8

const (
	amd64ADXCarryCF amd64ADXCarry = iota
	amd64ADXCarryOF
)

type amd64ADXSpec struct {
	bits   int
	prefix byte
	carry  amd64ADXCarry
}

// Go 1.27 asm6.go uses yml_rl for every ADX form. One spec binds the
// register/memory grammar, encoded mandatory prefix, width and carry chain.
var amd64ADXSpecs = map[Op]amd64ADXSpec{
	"ADCXL": {bits: 32, prefix: 0x66, carry: amd64ADXCarryCF},
	"ADCXQ": {bits: 64, prefix: 0x66, carry: amd64ADXCarryCF},
	"ADOXL": {bits: 32, prefix: 0xf3, carry: amd64ADXCarryOF},
	"ADOXQ": {bits: 64, prefix: 0xf3, carry: amd64ADXCarryOF},
}

// lowerADX implements ADCXL/Q and ADOXL/Q. All four opcodes use Go 1.27's
// yml_rl row: register/memory source and register destination. ADCX consumes
// and updates CF; ADOX independently consumes and updates OF.
func (c *amd64Ctx) lowerADX(op Op, ins Instr) (ok bool, terminated bool, err error) {
	form, known, err := x86ADXProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	bits, flagSlot := form.spec.bits, c.flagsCFSlot
	if form.spec.carry == amd64ADXCarryOF {
		flagSlot = c.flagsOFSlot
	}
	source, destination := form.source, form.destination
	typ := amd64IntegerTypeForBits(bits)
	sourceValue, err := c.evalSizedNativeGPSource(source, typ, ins.x86AddressBits)
	if err != nil {
		return true, false, err
	}
	destinationValue, err := c.evalIntSized(destination, typ)
	if err != nil {
		return true, false, err
	}
	carryIn := c.loadFlag(flagSlot)
	carryValue := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext i1 %s to %s\n", carryValue, carryIn, typ)
	sum := c.newTmp()
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add %s %s, %s\n", sum, typ, destinationValue, sourceValue)
	fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %%%s\n", result, typ, sum, carryValue)
	carryFromOperands := c.newTmp()
	carryFromInput := c.newTmp()
	carryOut := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ult %s %%%s, %s\n", carryFromOperands, typ, sum, destinationValue)
	fmt.Fprintf(c.b, "  %%%s = icmp ult %s %%%s, %%%s\n", carryFromInput, typ, result, sum)
	fmt.Fprintf(c.b, "  %%%s = or i1 %%%s, %%%s\n", carryOut, carryFromOperands, carryFromInput)
	if err := c.storeRegSized(destination.Reg, typ, "%"+result); err != nil {
		return true, false, err
	}
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", carryOut, flagSlot)
	return true, false, nil
}

// --- amd64_lower_align_elements.go ---
// Preserve the original family registry for source-op extraction.
var amd64VectorAlignSpecs = map[Op]int{
	"VALIGND": 32,
	"VALIGNQ": 64,
}

func (c *amd64Ctx) lowerVectorAlign(op Op, ins Instr) (bool, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	if _, known := amd64VectorAlignSpecs[Op(base)]; !known {
		return false, false, nil
	}
	return c.lowerPackedAlignFamily(op, ins)
}

// --- amd64_lower_align_right.go ---
// Keep both original dispatcher entries on the complete shared grammar.
func (c *amd64Ctx) lowerPackedAlignRight(op Op, ins Instr) (bool, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	if base != "PALIGNR" && base != "VPALIGNR" {
		return false, false, nil
	}
	return c.lowerPackedAlignFamily(op, ins)
}

func amd64UnsignedImmediate(operand Operand, bits int) bool {
	if operand.Kind != OpImm || operand.ImmIsFloat || operand.ImmRaw != "" || bits <= 0 || bits >= 63 {
		return false
	}
	return operand.Imm >= 0 && operand.Imm < int64(uint64(1)<<bits)
}

// --- amd64_lower_andn.go ---
func (c *amd64Ctx) lowerANDN(op Op, ins Instr) (bool, bool, error) {
	form, known, err := x86TernaryGPProperties(op, ins, c.goarch)
	if !known || form.spec.operation != x86TernaryANDN {
		return false, false, nil
	}
	if err != nil {
		return true, false, err
	}
	typ := amd64IntegerTypeForBits(form.spec.bits)
	first, err := c.evalSizedNativeGPSource(form.first, typ, ins.x86AddressBits)
	if err != nil {
		return true, false, err
	}
	second, err := c.evalIntSized(form.second, typ)
	if err != nil {
		return true, false, err
	}
	inverted, result := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor %s %s, -1\n", inverted, typ, second)
	fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %s\n", result, typ, inverted, first)
	if typ == I64 {
		c.setZSFlagsFromI64("%" + result)
	} else {
		c.setZSFlagsFromI32("%" + result)
	}
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsCFSlot)
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
	return true, false, c.storeRegSized(form.destination.Reg, typ, "%"+result)
}

// --- amd64_lower_approximate_math.go ---
type amd64ApproximateMathMode uint8

const (
	amd64ApproximateExp2 amd64ApproximateMathMode = iota
	amd64ApproximateReciprocal28
	amd64ApproximateReciprocalSqrt28
)

type amd64ApproximateMathSpec struct {
	laneBits int
	scalar   bool
	mode     amd64ApproximateMathMode
}

// amd64ApproximateMathSpecs models the complete AVX512ER family exposed by
// Go 1.27's _yvexp2pd and _yvgetexpsd tables. The type axes describe the
// mathematical operation, lane type, and packed/scalar operand shape; the
// parser below derives every legal mask, zero, broadcast, and SAE form.
var amd64ApproximateMathSpecs = map[Op]amd64ApproximateMathSpec{
	"VEXP2PS":    {laneBits: 32, mode: amd64ApproximateExp2},
	"VEXP2PD":    {laneBits: 64, mode: amd64ApproximateExp2},
	"VRCP28PS":   {laneBits: 32, mode: amd64ApproximateReciprocal28},
	"VRCP28PD":   {laneBits: 64, mode: amd64ApproximateReciprocal28},
	"VRCP28SS":   {laneBits: 32, scalar: true, mode: amd64ApproximateReciprocal28},
	"VRCP28SD":   {laneBits: 64, scalar: true, mode: amd64ApproximateReciprocal28},
	"VRSQRT28PS": {laneBits: 32, mode: amd64ApproximateReciprocalSqrt28},
	"VRSQRT28PD": {laneBits: 64, mode: amd64ApproximateReciprocalSqrt28},
	"VRSQRT28SS": {laneBits: 32, scalar: true, mode: amd64ApproximateReciprocalSqrt28},
	"VRSQRT28SD": {laneBits: 64, scalar: true, mode: amd64ApproximateReciprocalSqrt28},
}

// All ten EVEX approximation members share the existing typed native helper.
// The original instruction owns SAE/MXCSR, masking and the actual memory access;
// source data is never eagerly loaded before a masked native instruction.
func (c *amd64Ctx) lowerApproximateMath(op Op, ins Instr) (bool, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	if _, known := amd64ApproximateMathSpecs[Op(base)]; !known {
		return false, false, nil
	}
	return c.lowerNativeFloatingHelper(op, ins)
}

func (c *amd64Ctx) approximateMathMask32(mask string) string {
	truncated := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", truncated, mask)
	return "%" + truncated
}

// --- amd64_lower_arithmetic_shift.go ---
// The complete uniform arithmetic family shares yps/_yvpslld operand shapes
// with logical shifts. VPSRAQ has only the unsigned-immediate EVEX rows.
// These descriptors grant no register input, native backing or caller role.
var amd64PackedArithmeticShiftSpecs = map[Op]amd64PackedLogicalShiftSpec{
	"PSRAW":  {laneBits: 16},
	"PSRAL":  {laneBits: 32},
	"VPSRAW": {laneBits: 16, vector: true},
	"VPSRAD": {laneBits: 32, vector: true},
	"VPSRAQ": {laneBits: 64, vector: true},
}

func (c *amd64Ctx) lowerPackedArithmeticRightShift(op Op, ins Instr) (bool, bool, error) {
	return c.lowerX86PackedShift(op, ins)
}

func (c *amd64Ctx) emitPackedArithmeticRightShift(lanes, laneBits int, data, count64 string) string {
	valid, safe := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ult i64 %s, %d\n", valid, count64, laneBits)
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 %s, i64 %d\n", safe, valid, count64, laneBits-1)
	count := "%" + safe
	if laneBits < 64 {
		narrow := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i%d\n", narrow, count, laneBits)
		count = "%" + narrow
	}
	counts := amd64SplatInteger(c, lanes, laneBits, count)
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = ashr <%d x i%d> %s, %s\n", result, lanes, laneBits, data, counts)
	return "%" + result
}

// --- amd64_lower_atomic.go ---
func (c *amd64Ctx) lowerAtomic(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if known, terminated, err := c.lowerLockScalarRMW(op, ins); known {
		return known, terminated, err
	}
	if spec, recognized := amd64ExchangeSpecs[Op(normalizeInstructionOpcode(op))]; recognized {
		return c.lowerExchange(op, spec, ins)
	}
	if _, _, recognized := amd64CompareExchangeProperties(normalizeInstructionOpcode(op)); recognized {
		return c.lowerCompareExchange(op, ins)
	}
	switch op {
	case "LOCK":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("%w: LOCK operands cannot substitute for a complete following atomic instruction: %q", ErrProbeNeedsContext, ins.Raw)
		}
		// Only the whole-source consumer can bind this prefix to an adjacent
		// complete native operation. An isolated helper has no such body.
		return true, false, fmt.Errorf("%w: standalone LOCK has no source-adjacent complete atomic operation", ErrProbeNeedsContext)
	}
	return false, false, nil
}

func (c *amd64Ctx) amd64AtomicPtrFromMem(mem MemRef) (string, error) {
	ptr, ptrType, err := c.ptrFromMem(mem)
	if err != nil {
		return "", err
	}
	if ptrType != "ptr" {
		return "", fmt.Errorf("amd64 atomic operation does not support segment-relative memory")
	}
	return ptr, nil
}

func (c *amd64Ctx) amd64AtomicTruncFromI64(v64 string, ty LLVMType) (string, error) {
	switch ty {
	case I64:
		return v64, nil
	case I32, I16, I8, I1:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", t, v64, ty)
		return "%" + t, nil
	default:
		return "", fmt.Errorf("amd64: unsupported trunc target %s", ty)
	}
}

func (c *amd64Ctx) amd64AtomicExtendToI64(v string, ty LLVMType) (string, error) {
	switch ty {
	case I64:
		return v, nil
	case I32, I16, I8, I1:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext %s %s to i64\n", t, ty, v)
		return "%" + t, nil
	default:
		return "", fmt.Errorf("amd64: unsupported extend source %s", ty)
	}
}

// --- amd64_lower_average.go ---
func (c *amd64Ctx) lowerPackedUnsignedAverage(op Op, ins Instr) (bool, bool, error) {
	return c.lowerPackedPhysical(op, ins, x86PackedAverage)
}

func (c *amd64Ctx) lowerPackedAverageForm(op Op, ins Instr, form x86PackedPhysicalForm) (bool, bool, error) {
	ins.Op = op
	if err := x86LegacyMMXReadEmitterContext(ins, c.goarch); err != nil {
		return true, false, err
	}
	first, second, destination := form.source, ins.Args[form.second], ins.Args[form.destination]
	if form.legacy && !form.mmx && form.memory >= 0 {
		// A virtual FP/SP/BP view is not the source's native aligned m128.
		// Only the existing exact fixed-local certificate supplies that backing.
		virtual := first.Kind == OpFP
		if first.Kind == OpMem {
			virtual = !c.nativeMemoryOperand(ins, form.first) && !c.fixedLocalMemoryCertified(ins, form.memory)
		}
		if virtual {
			return true, false, fmt.Errorf("%w: legacy packed average m128 needs original native storage, not virtual FP/SP/BP alignment", ErrProbeNeedsContext)
		}
	}
	if form.memory >= 0 && first.Kind == OpFP {
		if err := c.validateX86PackedShiftFPSpan(first.FPOffset, form.memoryBytes); err != nil {
			return true, false, err
		}
	}
	bits := form.spec.outputBits
	lanes := form.byteWidth * 8 / bits
	if form.mmx {
		var a string
		var err error
		if first.Kind == OpReg {
			a, err = c.loadReg(first.Reg)
		} else {
			// Exact m64 bytes, including independent logical FP fields. Native
			// reads stay observable without inventing an x87/tag-state bridge.
			a, err = c.loadPackedUnpackMMXSource(first, 8)
		}
		if err != nil {
			return true, false, err
		}
		b, err := c.loadReg(second.Reg)
		if err != nil {
			return true, false, err
		}
		value := c.emitPackedUnsignedAverage(lanes, bits, c.bitcastI64ToIntegerLanes(lanes, bits, a), c.bitcastI64ToIntegerLanes(lanes, bits, b))
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to i64\n", out, lanes, bits, value)
		return true, false, c.storeReg(destination.Reg, "%"+out)
	}
	mnemonic := "pavgb"
	if bits == 16 {
		mnemonic = "pavgw"
	}
	return true, false, c.emitPackedBinaryE4(ins, form.x86PackedBinaryForm, form.spec.memoryBits,
		mnemonic, c.emitPackedUnsignedAverage)
}

func (c *amd64Ctx) emitPackedUnsignedAverage(lanes, laneBits int, first, second string) string {
	narrowType := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
	wideBits := laneBits * 2
	wideType := fmt.Sprintf("<%d x i%d>", lanes, wideBits)
	firstWide := c.newTmp()
	secondWide := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext %s %s to %s\n", firstWide, narrowType, first, wideType)
	fmt.Fprintf(c.b, "  %%%s = zext %s %s to %s\n", secondWide, narrowType, second, wideType)
	sum := c.newTmp()
	rounded := c.newTmp()
	average := c.newTmp()
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %%%s\n", sum, wideType, firstWide, secondWide)
	fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %s\n", rounded, wideType, sum, llvmSplatSignedInteger(lanes, wideBits, 1))
	fmt.Fprintf(c.b, "  %%%s = lshr %s %%%s, %s\n", average, wideType, rounded, llvmSplatSignedInteger(lanes, wideBits, 1))
	fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to %s\n", result, wideType, average, narrowType)
	return "%" + result
}

// --- amd64_lower_blend_mask.go ---
type amd64MaskBlendSpec struct {
	laneBits  int
	broadcast bool
}

// amd64MaskBlendSpecs is the complete shared _yvblendmpd grammar for the
// floating-point and integer mask-blend families.
var amd64MaskBlendSpecs = map[Op]amd64MaskBlendSpec{
	"VBLENDMPS": {laneBits: 32, broadcast: true},
	"VBLENDMPD": {laneBits: 64, broadcast: true},
	"VPBLENDMB": {laneBits: 8},
	"VPBLENDMW": {laneBits: 16},
	"VPBLENDMD": {laneBits: 32, broadcast: true},
	"VPBLENDMQ": {laneBits: 64, broadcast: true},
}

// lowerMaskBlend implements Go 1.27's complete _yvblendmpd operand table for
// VBLENDM{PS,PD} and VPBLENDM{B,W,D,Q}. A set K bit selects the first Plan 9
// (Intel r/m) source; an unset bit selects the second source, or zero for .Z.
func (c *amd64Ctx) lowerMaskBlend(op Op, ins Instr) (bool, bool, error) {
	form, known, err := x86MaskBlendProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	if err := c.validateConflictFunnelMemory(ins, form.x86PackedBinaryForm); err != nil {
		return true, false, err
	}
	mask := ""
	if form.mask >= 0 {
		mask, err = c.loadK(ins.Args[form.mask].Reg)
		if err != nil {
			return true, false, err
		}
	}
	// E4 suppresses only inactive memory elements. The shared volatile reader
	// retains active faults even when all result bytes are discarded after O2.
	first, err := c.loadX86PackedShiftLanes(ins.Args[form.first], form.byteWidth, form.spec.laneBits, form.broadcast, mask)
	if err != nil {
		return true, false, err
	}
	result := first
	lanes := form.byteWidth * 8 / form.spec.laneBits
	if form.mask >= 0 {
		second := "zeroinitializer"
		if !form.zeroing {
			second, err = c.loadPackedCompareLanes(ins.Args[form.second], form.byteWidth, form.spec.laneBits, false)
			if err != nil {
				return true, false, err
			}
		}
		result = amd64ApplyIntegerLaneMask(c, lanes, form.spec.laneBits, first, second, mask, form.zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, form.spec.laneBits, result, form.byteWidth)
	return true, false, c.storePackedMoveOperand(ins.Args[form.destination], form.byteWidth, "%"+out)
}

// --- amd64_lower_blend_variable.go ---
type amd64VariableBlendSpec struct {
	laneBits int
	vector   bool
	opcode   int
}

// Go's yblendvpd and _yvblendvpd differ only in implicit/explicit mask,
// destructive/non-destructive destination and the available vector widths.
// The VEX raw decoder consumes the same opcode table as named lowering.
var amd64VariableBlendSpecs = map[Op]amd64VariableBlendSpec{
	"BLENDVPS":  {laneBits: 32, opcode: 0x14},
	"BLENDVPD":  {laneBits: 64, opcode: 0x15},
	"PBLENDVB":  {laneBits: 8, opcode: 0x10},
	"VBLENDVPS": {laneBits: 32, vector: true, opcode: 0x4a},
	"VBLENDVPD": {laneBits: 64, vector: true, opcode: 0x4b},
	"VPBLENDVB": {laneBits: 8, vector: true, opcode: 0x4c},
}

// lowerVariableBlend implements Go 1.27's complete yblendvpd and _yvblendvpd
// families. Each opcode tests the high bit of its mask lane: false selects the
// base/destination lane and true selects the register-or-memory source lane.
func (c *amd64Ctx) lowerVariableBlend(op Op, ins Instr) (ok bool, terminated bool, err error) {
	form, recognized, err := x86BlendMinposProperties(op, ins, c.goarch)
	if !recognized || form.minimum {
		return false, false, nil
	}
	if err != nil {
		return true, false, err
	}
	laneBits, byteWidth := form.laneBits, form.byteWidth
	maskArg, source := ins.Args[form.mask], ins.Args[form.source]
	base, destination := ins.Args[form.base], ins.Args[form.destination]
	if form.legacy && form.memory {
		return true, false, c.lowerLegacyBlendMinposMemory(ins, form)
	}
	maskBytes, err := c.loadPackedCompareBytes(maskArg, byteWidth)
	if err != nil {
		return true, false, err
	}
	sourceBytes, err := c.loadX86PackedShiftBytes(source, byteWidth, true)
	if err != nil {
		return true, false, err
	}
	baseBytes, err := c.loadPackedCompareBytes(base, byteWidth)
	if err != nil {
		return true, false, err
	}
	lanes := byteWidth * 8 / laneBits
	maskLanes := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, laneBits, maskBytes)
	sourceLanes := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, laneBits, sourceBytes)
	baseLanes := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, laneBits, baseBytes)
	selectedMask := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt <%d x i%d> %s, zeroinitializer\n", selectedMask, lanes, laneBits, maskLanes)
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, <%d x i%d> %s, <%d x i%d> %s\n", result, lanes, selectedMask, lanes, laneBits, sourceLanes, lanes, laneBits, baseLanes)
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %%%s to <%d x i8>\n", out, lanes, laneBits, result, byteWidth)
	if !form.legacy {
		return true, false, c.storePackedMoveOperand(destination, byteWidth, "%"+out)
	}
	return true, false, c.storeLegacyXViews(destination.Reg, "%"+out)
}

// --- amd64_lower_bls.go ---
// lowerLowestSetBitManipulation implements Go 1.27's complete _yblsil table:
// BLSI, BLSMSK, and BLSR at L/Q widths, with a Yml register-or-memory source
// and a Yrl destination register.
func (c *amd64Ctx) lowerLowestSetBitManipulation(op Op, ins Instr) (ok bool, terminated bool, err error) {
	form, known, err := x86BLSProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	typ := amd64IntegerTypeForBits(form.spec.bits)
	value, err := c.evalBLSSource(ins, form, typ)
	if err != nil {
		return true, false, err
	}
	minusOne := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sub %s %s, 1\n", minusOne, typ, value)
	result := c.newTmp()
	carry := ""
	switch form.spec.kind {
	case x86BLSIsolate:
		negative := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub %s 0, %s\n", negative, typ, value)
		fmt.Fprintf(c.b, "  %%%s = and %s %s, %%%s\n", result, typ, value, negative)
		carry = c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp ne %s %s, 0\n", carry, typ, value)
	case x86BLSMask:
		fmt.Fprintf(c.b, "  %%%s = xor %s %s, %%%s\n", result, typ, value, minusOne)
		carry = c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, 0\n", carry, typ, value)
	case x86BLSReset:
		fmt.Fprintf(c.b, "  %%%s = and %s %s, %%%s\n", result, typ, value, minusOne)
		carry = c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, 0\n", carry, typ, value)
	}

	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", carry, c.flagsCFSlot)
	if form.spec.kind == x86BLSMask {
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsZSlot)
	} else {
		zero := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq %s %%%s, 0\n", zero, typ, result)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zero, c.flagsZSlot)
	}
	sign := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt %s %%%s, 0\n", sign, typ, result)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", sign, c.flagsSltSlot)
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
	return true, false, c.storeRegSized(form.destination.Reg, typ, "%"+result)
}

// --- amd64_lower_bmi2_shift.go ---
type amd64BMI2ShiftSpec struct {
	bits      int
	prefix    int
	kind      string
	immediate bool
}

var amd64BMI2ShiftSpecs = map[Op]amd64BMI2ShiftSpec{
	"SARXL": {bits: 32, prefix: 2, kind: "ashr"},
	"SARXQ": {bits: 64, prefix: 2, kind: "ashr"},
	"SHLXL": {bits: 32, prefix: 1, kind: "shl"},
	"SHLXQ": {bits: 64, prefix: 1, kind: "shl"},
	"SHRXL": {bits: 32, prefix: 3, kind: "lshr"},
	"SHRXQ": {bits: 64, prefix: 3, kind: "lshr"},
	"RORXL": {bits: 32, prefix: 3, kind: "rotate", immediate: true},
	"RORXQ": {bits: 64, prefix: 3, kind: "rotate", immediate: true},
}

// All eight L/Q shifts and rotates consume the shared complete _ybextrl or
// _yrorxl grammar, exact source width and count mask. None changes FLAGS.
func (c *amd64Ctx) lowerBMI2ShiftRotate(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, supported := amd64BMI2ShiftSpecs[op]
	if !supported {
		return false, false, nil
	}
	form, _, err := x86ScalarShiftProperties(op, ins, c.goarch)
	if err != nil {
		return true, false, err
	}
	typ := amd64IntegerTypeForBits(form.bits)
	countValue, err := c.evalIntSized(form.count, typ)
	if err != nil {
		return true, false, err
	}
	sourceValue, _, err := c.loadScalarShiftOperand(ins, 1, typ)
	if err != nil {
		return true, false, err
	}
	maskedCount := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and %s %s, %d\n", maskedCount, typ, countValue, form.bits-1)
	result := c.newTmp()
	if spec.immediate {
		// Both shifts stay in range at count zero; LLVM must never see poison.
		negative, reverse := c.newTmp(), c.newTmp()
		low, high := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub %s 0, %%%s\n", negative, typ, maskedCount)
		fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %d\n", reverse, typ, negative, form.bits-1)
		fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %%%s\n", low, typ, sourceValue, maskedCount)
		fmt.Fprintf(c.b, "  %%%s = shl %s %s, %%%s\n", high, typ, sourceValue, reverse)
		fmt.Fprintf(c.b, "  %%%s = or %s %%%s, %%%s\n", result, typ, low, high)
	} else {
		fmt.Fprintf(c.b, "  %%%s = %s %s %s, %%%s\n", result, spec.kind, typ, sourceValue, maskedCount)
	}
	if err := c.storeRegSized(form.destination.Reg, typ, "%"+result); err != nil {
		return true, false, err
	}
	return true, false, nil
}

// --- amd64_lower_broadcast_float.go ---
// lowerScalarFloatBroadcast implements all Go 1.27 _yvbroadcastss and
// _yvbroadcastsd operand forms, including EVEX mask merge and zeroing.
func (c *amd64Ctx) lowerScalarFloatBroadcast(op Op, ins Instr) (ok bool, terminated bool, err error) {
	f, known, err := x86BroadcastProperties(op, ins, c.goarch)
	if !known || f.kind != x86BroadcastFloat {
		return false, false, nil
	}
	if err != nil {
		return true, false, err
	}
	laneBits, byteWidth := f.laneBits, f.byteWidth
	source, dst := ins.Args[0], ins.Args[f.destination]
	masked, zeroing := f.mask >= 0, f.zeroing
	var mask string
	if masked {
		mask, err = c.loadK(ins.Args[f.mask].Reg)
		if err != nil {
			return true, false, err
		}
	}

	var scalar string
	if source.Kind == OpReg {
		scalar, err = c.loadXLowInteger(source.Reg, laneBits)
	} else if source.Kind == OpImm {
		scalar, err = c.evalIntSized(source, amd64IntegerTypeForBits(laneBits))
	} else {
		if masked {
			// Broadcasting reads the scalar only if any destination lane is
			// active. High K bits outside this vector's lane count do not
			// enable the load; checking only mask bit zero is also incorrect.
			lanes := byteWidth * 8 / laneBits
			relevant, active := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i64 %s, %d\n", relevant, mask, uint64(1)<<uint(lanes)-1)
			fmt.Fprintf(c.b, "  %%%s = icmp ne i64 %%%s, 0\n", active, relevant)
			scalar, err = c.loadX86ScalarIf(laneBits, "%"+active, func() (string, error) {
				return c.loadPackedBroadcastScalar(source, laneBits, false)
			})
		} else {
			scalar, err = c.loadPackedBroadcastScalar(source, laneBits, false)
		}
	}
	if err != nil {
		return true, false, err
	}

	lanes := byteWidth * 8 / laneBits
	result := amd64SplatInteger(c, lanes, laneBits, scalar)
	if masked {
		oldBytes, err := c.loadPackedCompareBytes(dst, byteWidth)
		if err != nil {
			return true, false, err
		}
		old := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, laneBits, oldBytes)
		result = amd64ApplyIntegerLaneMask(c, lanes, laneBits, result, old, mask, zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, laneBits, result, byteWidth)
	return true, false, c.storePackedMoveOperand(dst, byteWidth, "%"+out)
}

// --- amd64_lower_broadcast_mask.go ---
type amd64MaskBroadcastSpec struct {
	sourceBits int
	laneBits   int
}

// amd64MaskBroadcastSpecs is the complete Go 1.27 _yvpbroadcastmb2q grammar.
// The low byte/word of a K register is zero-extended and broadcast into every
// qword/dword lane of an EVEX X, Y, or Z destination.
var amd64MaskBroadcastSpecs = map[Op]amd64MaskBroadcastSpec{
	"VPBROADCASTMB2Q": {sourceBits: 8, laneBits: 64},
	"VPBROADCASTMW2D": {sourceBits: 16, laneBits: 32},
}

func (c *amd64Ctx) lowerMaskRegisterBroadcast(op Op, ins Instr) (ok bool, terminated bool, err error) {
	f, known, err := x86BroadcastProperties(op, ins, c.goarch)
	if !known || f.kind != x86BroadcastMask {
		return false, false, nil
	}
	if err != nil {
		return true, false, err
	}
	spec := amd64MaskBroadcastSpecs[Op(strings.ToUpper(string(op)))]
	byteWidth := f.byteWidth
	mask, err := c.loadK(ins.Args[0].Reg)
	if err != nil {
		return true, false, err
	}
	narrow := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i%d\n", narrow, mask, spec.sourceBits)
	scalar := "%" + narrow
	if spec.sourceBits != spec.laneBits {
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i%d %s to i%d\n", wide, spec.sourceBits, scalar, spec.laneBits)
		scalar = "%" + wide
	}
	lanes := byteWidth * 8 / spec.laneBits
	result := amd64SplatInteger(c, lanes, spec.laneBits, scalar)
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, spec.laneBits, result, byteWidth)
	return true, false, c.storePackedMoveOperand(ins.Args[1], byteWidth, "%"+out)
}

// --- amd64_lower_byte_shift.go ---
// lowerPackedByteShift implements Go 1.27's PSLLO/PSRLO aliases and
// PSLLDQ/PSRLDQ vector family. Every operation shifts bytes independently
// within each 128-bit lane and fills vacated bytes with zero.
func (c *amd64Ctx) lowerPackedByteShift(op Op, ins Instr) (bool, bool, error) {
	return c.lowerX86PackedShift(op, ins)
}

func amd64SignedImmediate(operand Operand, bits int) bool {
	if operand.Kind != OpImm || operand.ImmIsFloat || operand.ImmRaw != "" || bits <= 0 || bits >= 63 {
		return false
	}
	limit := int64(1) << (bits - 1)
	return operand.Imm >= -limit && operand.Imm < limit
}

func amd64VectorByteShiftImmediate(operand Operand) bool {
	return operand.Kind == OpImm && !operand.ImmIsFloat && operand.ImmRaw == "" && operand.Imm >= -128 && operand.Imm <= 255
}

func amd64PackedByteShiftRequiresEVEX(source, destination Operand, byteWidth int) bool {
	if byteWidth == 64 || isAMD64MemoryOperand(source) {
		return true
	}
	for _, operand := range []Operand{source, destination} {
		index, ok := amd64VectorRegisterIndex(operand.Reg, byteWidth)
		if !ok || index >= 16 {
			return true
		}
	}
	return false
}

func (c *amd64Ctx) emitPackedByteShift(byteWidth int, source string, count uint8, left bool) string {
	if count >= 16 {
		return "zeroinitializer"
	}
	result := "zeroinitializer"
	for laneBase := 0; laneBase < byteWidth; laneBase += 16 {
		for destinationByte := 0; destinationByte < 16; destinationByte++ {
			sourceByte := destinationByte + int(count)
			if left {
				sourceByte = destinationByte - int(count)
			}
			if sourceByte < 0 || sourceByte >= 16 {
				continue
			}
			extracted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i8> %s, i32 %d\n", extracted, byteWidth, source, laneBase+sourceByte)
			inserted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i8> %s, i8 %%%s, i32 %d\n", inserted, byteWidth, result, extracted, laneBase+destinationByte)
			result = "%" + inserted
		}
	}
	return result
}

// --- amd64_lower_bzhi.go ---
// lowerBZHI implements Go 1.27's complete _ybextrl operand row for BZHIL/Q:
// register index, register/memory source, and register destination.
func (c *amd64Ctx) lowerBZHI(op Op, ins Instr) (ok bool, terminated bool, err error) {
	form, known, err := x86ScalarBitFieldFamilyProperties(op, ins, c.goarch, x86BitFieldZeroHigh)
	if !known || err != nil {
		return known, false, err
	}

	bits := form.bits
	typ := amd64IntegerTypeForBits(bits)
	indexValue, err := c.evalIntSized(form.control, typ)
	if err != nil {
		return true, false, err
	}
	sourceValue, err := c.evalScalarBitFieldSource(ins, form, typ)
	if err != nil {
		return true, false, err
	}
	indexLowByte := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and %s %s, 255\n", indexLowByte, typ, indexValue)
	indexInRange := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ult %s %%%s, %d\n", indexInRange, typ, indexLowByte, bits)
	safeIndex := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %d\n", safeIndex, typ, indexLowByte, bits-1)
	one := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shl %s 1, %%%s\n", one, typ, safeIndex)
	partialMask := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add %s %%%s, -1\n", partialMask, typ, one)
	mask := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s %%%s, %s -1\n", mask, indexInRange, typ, partialMask, typ)
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and %s %s, %%%s\n", result, typ, sourceValue, mask)
	if err := c.storeRegSized(form.destination.Reg, typ, "%"+result); err != nil {
		return true, false, err
	}
	carry := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, true\n", carry, indexInRange)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", carry, c.flagsCFSlot)
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
	zero := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq %s %%%s, 0\n", zero, typ, result)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zero, c.flagsZSlot)
	sign := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt %s %%%s, 0\n", sign, typ, result)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", sign, c.flagsSltSlot)
	return true, false, nil
}

// --- amd64_lower_cache_line.go ---
var x86CacheLineWritebackOps = map[string]struct{}{
	"CLFLUSH":    {},
	"CLFLUSHOPT": {},
	"CLWB":       {},
}

// All three Go yclflush rows consume a memory address without reading or
// writing its scalar value.
func x86CacheLineWritebackProperties(op Op, ins Instr, arch string) (string, bool, error) {
	rawOp := strings.ToUpper(string(op))
	baseOp, _, suffix := strings.Cut(rawOp, ".")
	if _, ok := x86CacheLineWritebackOps[baseOp]; !ok {
		return "", false, nil
	}
	if suffix {
		return "", true, fmt.Errorf("%s %s does not accept instruction suffixes: %q", arch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 1 || !isAMD64MemoryOperand(ins.Args[0]) {
		return "", true, fmt.Errorf("%s %s expects one Go Ym memory operand: %q", arch, baseOp, ins.Raw)
	}
	return baseOp, true, nil
}

func x86TypedCacheLineWritebackByteEffect(ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	_, known, err := x86CacheLineWritebackProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	return x86TypedByteEffect{operands: []x86TypedByteOperand{
		{index: 0, operand: ins.Args[0], width: 1, read: true, addressOnly: true},
	}}, true, nil
}

func x86LoweredCacheLineWritebackStep(ins Instr, state *x86ResultState, owned []bool, arch, triple string) (bool, bool) {
	_, known, err := x86CacheLineWritebackProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	if !x86ScalarFloatIntegerNativeTarget(arch, triple) || !x86ResultNamedPredicateInstruction(ins) {
		return false, true
	}
	address := ins.Args[0]
	if address.Kind == OpFP {
		offset := address.FPOffset
		return offset >= 0 && offset < int64(len(owned)) && owned[offset], true
	}
	if _, local := state.localOffset(address, 1); local {
		return true, true
	}
	if _, symbol := x86StaticSBReadAddress(address, arch); symbol {
		return true, true
	}
	return x86ResultIncomingPointerAddressIdentity(address, state, arch) ||
		x86ResultNativeNumericAddress(address, state, arch), true
}

// Retain the architectural cache operation and its ordering and persistence
// semantics through inline assembly.
func (c *amd64Ctx) lowerCacheLineWriteback(op Op, ins Instr) (ok bool, terminated bool, err error) {
	baseOp, known, err := x86CacheLineWritebackProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}

	ptr, ptrType, err := c.x86DescriptorMemoryPointer(ins.Args[0])
	if err != nil {
		return true, false, err
	}
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(%s elementtype(i8) %s)\n",
		strings.ToLower(baseOp)+" $0", "*m,~{memory},~{dirflag},~{fpsr},~{flags}", ptrType, ptr)
	return true, false, nil
}

// --- amd64_lower_convert.go ---
func amd64ParseMReg(r Reg) (idx int, ok bool) {
	s := strings.ToUpper(strings.TrimSpace(string(r)))
	if !strings.HasPrefix(s, "M") {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimPrefix(s, "M"))
	if err != nil || n < 0 || n > 7 {
		return 0, false
	}
	return n, true
}

// Legacy named entries use the complete shared typed/native family.
func (c *amd64Ctx) lowerPackedFloatToDword(op Op, ins Instr) (bool, bool, error) {
	return c.lowerPackedNumericConversion(op, ins)
}

func (c *amd64Ctx) lowerPackedSingleToDouble(op Op, ins Instr) (bool, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	if base != "CVTPS2PD" && base != "VCVTPS2PD" {
		return false, false, nil
	}
	return c.lowerPackedPrecisionConvert(op, ins)
}

// --- amd64_lower_convert_fp16_scalar.go ---
func (c *amd64Ctx) lowerRawScalarHalfConversion(ins Instr, f x86FP16ConversionForm) (bool, bool, error) {
	spec, properties := f.spec, f.controls
	source, upper, destination := ins.Args[0], ins.Args[f.upper], ins.Args[f.destination]
	mask := ""
	var err error
	if f.mask >= 0 {
		mask, err = c.loadK(ins.Args[f.mask].Reg)
		if err != nil {
			return true, false, err
		}
	}
	value, err := c.loadFMA3Scalar(source, spec.inputBits, mask)
	if err != nil {
		return true, false, err
	}
	inputType := amd64FMA3LLVMType(1, spec.inputBits)
	vector, bits := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <1 x %s> poison, %s %s, i32 0\n", vector, inputType, inputType, value)
	fmt.Fprintf(c.b, "  %%%s = bitcast <1 x %s> %%%s to <1 x i%d>\n", bits, inputType, vector, spec.inputBits)
	result := c.emitHalfConversion(1, spec, "%"+bits, properties.rounding)
	low := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractelement <1 x i%d> %s, i32 0\n", low, spec.outputBits, result)
	upperBytes, err := c.loadX(upper.Reg)
	if err != nil {
		return true, false, err
	}
	base := c.bitcastVectorBytesToIntegerLanes(16, 128/spec.outputBits, spec.outputBits, upperBytes)
	return true, false, c.storeScalarMoveRegister(destination.Reg, spec.outputBits, "%"+low, base, mask, properties.zeroing)
}

// --- amd64_lower_convert_integer_float.go ---
// lowerLegacyIntegerToFloat implements Go 1.27's complete legacy integer to
// floating-point conversion group: yxcvlf/yxcvqf scalar conversions and the
// two yxcvm2 packed conversions.
func (c *amd64Ctx) lowerLegacyIntegerToFloat(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if _, known, _ := x86SignedPackedFloatProperties(ins, c.goarch); known {
		return c.lowerSignedPackedIntegerFloat(op, ins)
	}
	rawOp := strings.ToUpper(string(op))
	if strings.Contains(rawOp, ".") {
		base := strings.SplitN(rawOp, ".", 2)[0]
		switch base {
		case "CVTSL2SS", "CVTSL2SD", "CVTSQ2SS", "CVTSQ2SD", "CVTPL2PS", "CVTPL2PD":
			return true, false, fmt.Errorf("amd64 %s does not accept instruction suffixes: %q", base, ins.Raw)
		}
	}
	switch rawOp {
	case "CVTSL2SS", "CVTSL2SD", "CVTSQ2SS", "CVTSQ2SD":
		return c.lowerLegacyScalarIntegerToFloat(rawOp, ins)
	case "CVTPL2PS", "CVTPL2PD":
		return c.lowerLegacyPackedIntegerToFloat(rawOp, ins)
	default:
		return false, false, nil
	}
}

func (c *amd64Ctx) lowerLegacyScalarIntegerToFloat(op string, ins Instr) (bool, bool, error) {
	return c.lowerSignedIntegerScalarFloat(Op(op), ins)
}

func (c *amd64Ctx) lowerLegacyPackedIntegerToFloat(op string, ins Instr) (bool, bool, error) {
	return c.lowerSignedPackedIntegerFloat(Op(op), ins)
}

// --- amd64_lower_convert_narrow.go ---
func (c *amd64Ctx) lowerPackedDoubleToSingle(op Op, ins Instr) (bool, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	if base != "CVTPD2PS" && base != "VCVTPD2PSX" && base != "VCVTPD2PSY" && base != "VCVTPD2PS" {
		return false, false, nil
	}
	return c.lowerPackedPrecisionConvert(op, ins)
}

// --- amd64_lower_crc32.go ---
func (c *amd64Ctx) lowerCrc32(op Op, ins Instr) (ok bool, terminated bool, err error) {
	form, known, err := x86CRC32Properties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	if form.source.Kind == OpReg && (form.source.Reg == SP || form.source.Reg == BP) &&
		form.source.Reg != ins.Args[0].Reg {
		return true, false, fmt.Errorf("%w: Go CRC32 REX byte view needs its original physical SP/BP input", ErrProbeNeedsContext)
	}
	sourceType := amd64IntegerTypeForBits(form.bits)
	intrinsic := fmt.Sprintf("llvm.x86.sse42.crc32.32.%d", form.bits)
	resultType := I32
	if form.bits == 64 {
		resultType = I64
		intrinsic = "llvm.x86.sse42.crc32.64.64"
	}
	sourceValue, err := c.evalCRC32Source(ins, form, sourceType)
	if err != nil {
		return true, false, err
	}
	crcValue, err := c.evalIntSized(form.destination, I32)
	if err != nil {
		return true, false, err
	}
	if resultType == I64 {
		extended := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", extended, crcValue)
		crcValue = "%" + extended // Unknown old high32 never enter the intrinsic.
	}
	call := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @%s(%s %s, %s %s)\n", call, resultType, intrinsic, resultType, crcValue, sourceType, sourceValue)
	return true, false, c.storeRegSized(form.destination.Reg, resultType, "%"+call)
}

func (c *amd64Ctx) evalCRC32Source(ins Instr, form x86CRC32Form, typ LLVMType) (string, error) {
	if form.source.Kind == OpFP && x86ResultNamedPredicateInstruction(ins) {
		if value, handled, err := c.loadIntegerFPBytesMode(form.source.FPOffset, typ, true); handled || err != nil {
			return value, err
		}
	}
	if isAMD64MemoryOperand(form.source) && form.source.Kind != OpFP &&
		(c.nativeMemoryOperand(ins, 0) ||
			x86CallerMemoryCertified(ins, 0) || c.fixedLocalMemoryCertified(ins, 0)) {
		if ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride {
			return "", fmt.Errorf("%w: CRC32 needs its original native address size", ErrProbeNeedsContext)
		}
		pointer, pointerType, _, err := c.packedVectorMemoryPointer(form.source)
		if err != nil {
			return "", err
		}
		value := c.newTmp()
		// Even a zero accumulator or dead result retains the complete native
		// source read. No backing, extent or alignment follows from continuing.
		fmt.Fprintf(c.b, "  %%%s = load volatile %s, %s %s, align 1\n", value, typ, pointerType, pointer)
		return "%" + value, nil
	}
	return c.evalIntSized(form.source, typ)
}

// --- amd64_lower_dot_float.go ---
type amd64PackedFloatingDotForm uint8

const (
	// amd64PackedFloatingDotLegacy is Go's yxshuf table: imm8, X/m128, X.
	amd64PackedFloatingDotLegacy amd64PackedFloatingDotForm = iota
	// amd64PackedFloatingDotVEX128 is Go's _yvdppd table: imm8, X/m128,
	// X, X. The Go 386 frontend cannot represent the four operands.
	amd64PackedFloatingDotVEX128
	// amd64PackedFloatingDotVEX128Or256 is Go's _yvblendpd table, adding
	// the corresponding Y/m256, Y, Y row.
	amd64PackedFloatingDotVEX128Or256
)

type amd64PackedFloatingDotSpec struct {
	form     amd64PackedFloatingDotForm
	laneBits int
}

// amd64PackedFloatingDotSpecs is the complete Go 1.27 grammar for the SSE4.1
// and AVX floating dot-product family. The form class captures operand count,
// legal vector widths, and the 386 frontend restriction; laneBits selects the
// hardware intrinsic and immediate-bit interpretation.
var amd64PackedFloatingDotSpecs = map[Op]amd64PackedFloatingDotSpec{
	"DPPD":  {form: amd64PackedFloatingDotLegacy, laneBits: 64},
	"DPPS":  {form: amd64PackedFloatingDotLegacy, laneBits: 32},
	"VDPPD": {form: amd64PackedFloatingDotVEX128, laneBits: 64},
	"VDPPS": {form: amd64PackedFloatingDotVEX128Or256, laneBits: 32},
}

func (c *amd64Ctx) lowerPackedFloatingDot(op Op, ins Instr) (ok bool, terminated bool, err error) {
	return c.lowerNativePackedReduction(op, ins)
}

// --- amd64_lower_enqueue.go ---
var x86EnqueueOps = map[string]byte{
	"ENQCMD":  0xf2,
	"ENQCMDS": 0xf3,
}

// Keep the 64-byte device enqueue operation in hardware. An ordinary memory
// copy cannot implement PASID handling, atomic submission, or retry status.
func (c *amd64Ctx) lowerEnqueue(op Op, ins Instr) (bool, bool, error) {
	form, known, err := x86EnqueueProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	source := form.source
	assemblySource := "$1"
	if source.Kind == OpMem && source.Mem.Segment != "" {
		switch source.Mem.Segment {
		case FS, GS:
			// LLVM inline-asm memory operands do not preserve the pointer's
			// segment address space. Spell the prefix explicitly and pass
			// its offset, not an ordinary unsegmented effective address.
			assemblySource = "%" + strings.ToLower(string(source.Mem.Segment)) + ":$1"
			source.Mem.Segment = ""
		default:
			return true, false, fmt.Errorf("unsupported enqueue source segment %s", source.Mem.Segment)
		}
	}
	ptr, ptrType, err := c.x86DescriptorMemoryPointer(source)
	if err != nil {
		return true, false, err
	}
	wordType := amd64IntegerTypeForBits(form.wordBits)
	destination, err := c.evalIntSized(form.destination, wordType)
	if err != nil {
		return true, false, err
	}
	if bits := form.addressBits; bits != form.wordBits {
		// Truncate the effective offset before hardware applies any explicit
		// source-segment override.
		address := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ptrtoint %s %s to i%d\n", address, ptrType, ptr, bits)
		wrapped := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = inttoptr i%d %%%s to %s\n", wrapped, bits, address, ptrType)
		ptr = "%" + wrapped
		low, extended := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc %s %s to i%d\n", low, wordType, destination, bits)
		fmt.Fprintf(c.b, "  %%%s = zext i%d %%%s to %s\n", extended, bits, low, wordType)
		destination = "%" + extended
	}

	status := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call i8 asm sideeffect %q, %q(%s elementtype([64 x i8]) %s, %s %s)\n",
		status, form.native+" "+assemblySource+", $2; sete $0",
		"=q,*m,r,~{memory},~{dirflag},~{fpsr},~{flags}", ptrType, ptr, wordType, destination)
	c.storeSegmentQueryZF("%" + status)
	c.clearX86StatusFlags(x86StatusAll &^ x86StatusZF)
	return true, false, nil
}

// --- amd64_lower_extract.go ---
// lowerVectorLaneExtract implements all Go 1.27 forms in _yvextractf128,
// _yvextractf32x4, and _yvextractf32x8 for their F/I lane-extract mnemonics.
func (c *amd64Ctx) lowerVectorLaneExtract(op Op, ins Instr) (ok bool, terminated bool, err error) {
	return c.lowerInsertExtractFamily(op, ins)
}

func (c *amd64Ctx) storeVectorBytesOperand(dst Operand, byteWidth int, value string) error {
	return c.storeVectorBytesOperandWithMetadata(dst, byteWidth, value, "")
}

func (c *amd64Ctx) storeVectorBytesOperandWithMetadata(dst Operand, byteWidth int, value, metadata string) error {
	if dst.Kind == OpReg {
		if metadata != "" {
			return fmt.Errorf("vector register destination cannot carry store metadata: %s", dst.String())
		}
		if !amd64VectorRegisterHasWidth(dst, byteWidth) {
			return fmt.Errorf("expected %d-byte vector register, got %s", byteWidth, dst.String())
		}
		return c.storeVectorBytes(dst.Reg, byteWidth, value)
	}
	switch dst.Kind {
	case OpMem:
		addr, err := c.addrFromMem(dst.Mem)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store <%d x i8> %s, ptr %s, align 1%s\n", byteWidth, value, c.ptrFromAddrI64(addr), metadata)
		return nil
	case OpSym:
		p, err := c.ptrFromSB(dst.Sym)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store <%d x i8> %s, ptr %s, align 1%s\n", byteWidth, value, p, metadata)
		return nil
	case OpFP:
		return c.storeFPVectorBytes(dst.FPOffset, byteWidth, value, metadata)
	default:
		return fmt.Errorf("expected vector register or memory destination, got %s", dst.String())
	}
}

// --- amd64_lower_fixed_system.go ---
type amd64FixedSystemEffect uint8

const (
	amd64FixedSystemContinue amd64FixedSystemEffect = iota
	amd64FixedSystemTrap
	amd64FixedSystemControlTransfer
)

type amd64FixedSystemSpec struct {
	encoding string
	effect   amd64FixedSystemEffect
	rawOnly  bool
}

// amd64FixedSystemSpecs is the complete Go 1.27 operand-free system/state
// family that has no modeled GP-register data flow, plus raw-only ENDBR32.
// Exact bytes keep Go's
// accepted 386 compatibility rows (notably ENDBR64 and SWAPGS) object-level
// compatible even when LLVM's mnemonic matcher applies architectural mode
// restrictions. Effects remain typed so traps and non-returning RSM cannot
// accidentally acquire ordinary fallthrough.
var amd64FixedSystemSpecs = map[Op]amd64FixedSystemSpec{
	"CLAC":    {encoding: ".byte 0x0f, 0x01, 0xca"},
	"CLI":     {encoding: ".byte 0xfa"},
	"CLTS":    {encoding: ".byte 0x0f, 0x06"},
	"ENDBR32": {encoding: ".byte 0xf3, 0x0f, 0x1e, 0xfb", rawOnly: true},
	"ENDBR64": {encoding: ".byte 0xf3, 0x0f, 0x1e, 0xfa"},
	"ICEBP":   {encoding: ".byte 0xf1", effect: amd64FixedSystemTrap},
	"INVD":    {encoding: ".byte 0x0f, 0x08"},
	"RSM":     {encoding: ".byte 0x0f, 0xaa", effect: amd64FixedSystemControlTransfer},
	"STAC":    {encoding: ".byte 0x0f, 0x01, 0xcb"},
	"STI":     {encoding: ".byte 0xfb"},
	"SWAPGS":  {encoding: ".byte 0x0f, 0x01, 0xf8"},
	"UD1":     {encoding: ".byte 0x0f, 0xb9, 0x00", effect: amd64FixedSystemTrap},
	"WBINVD":  {encoding: ".byte 0x0f, 0x09"},
}

func (c *amd64Ctx) lowerFixedSystem(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	spec, recognized := amd64FixedSystemSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	if spec.rawOnly && !ins.x86Encoded {
		return true, false, fmt.Errorf("%s %s has no Go assembler mnemonic; use its raw encoding: %q", c.goarch, baseOp, ins.Raw)
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("%s %s does not accept instruction suffixes: %q", c.goarch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 0 {
		return true, false, fmt.Errorf("%s %s takes no operands: %q", c.goarch, baseOp, ins.Raw)
	}
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q()\n",
		spec.encoding, "~{memory},~{dirflag},~{fpsr},~{flags}")
	if spec.effect == amd64FixedSystemContinue {
		return true, false, nil
	}
	c.b.WriteString("  unreachable\n")
	return true, true, nil
}

// --- amd64_lower_float_min_max.go ---
func (c *amd64Ctx) lowerFloatMinMax(op Op, ins Instr) (bool, bool, error) {
	return c.lowerFloatArithmetic(op, ins, x86FloatMinimumMaximum)
}

func (c *amd64Ctx) lowerFloatMinMaxForm(ins Instr, f x86FloatMinMaxForm) (bool, bool, error) {
	if (ins.x86Encoded || ins.x86SourceRaw != nil) && !x86RawFloatMinMaxEncodingSource(ins, c.goarch) {
		return true, false, fmt.Errorf("%w: MIN/MAX original physical source identity changed", ErrProbeNeedsContext)
	}
	if x86ScalarFloatIntegerNativeTarget(c.goarch, c.targetTriple) {
		if f.legacy && !f.scalar && f.memory >= 0 {
			return true, false, c.lowerLegacyPackedFloatingMemory(ins, f.x86FloatBinaryForm)
		}
		lanes := f.byteWidth * 8 / f.bits
		logicalFPBits := 0
		if f.scalar {
			lanes = 1
			logicalFPBits = f.bits
		}
		evex := x86FloatMinMaxNativeEVEX(ins, f)
		return true, false, c.emitNativeFloatingOperands(ins, x86NativeFloatingOperands{
			byteWidth: f.byteWidth, lanes: lanes, memoryBytes: f.memoryBytes,
			second: f.second, destination: f.destination, mask: f.mask,
			controls: amd64FMA3Suffix{broadcast: f.broadcast, zeroing: f.zeroing},
			sae:      f.sae, legacy: f.legacy, logicalFPBits: logicalFPBits,
			lowBank: !evex, forceEVEX: evex && f.byteWidth < 64 && f.mask < 0 && !f.sae && !f.broadcast,
		})
	}
	// Portable numerical values do not certify x86 MXCSR or native exceptions.
	return c.lowerFloatBinaryOperands(ins, f.x86FloatBinaryForm,
		func(lanes int, left, right, _ string) string {
			typ := amd64FMA3LLVMType(lanes, f.bits)
			predicate := "ogt"
			if f.spec.mode == amd64BinaryFloatingMin {
				predicate = "olt"
			}
			condition, value := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = fcmp %s %s %s, %s\n", condition, predicate, typ, left, right)
			predicateType := "i1"
			if lanes > 1 {
				predicateType = fmt.Sprintf("<%d x i1>", lanes)
			}
			// Native MIN/MAX chooses the first explicit Go source for equal
			// values and unordered pairs. Keep its original NaN/zero bits.
			fmt.Fprintf(c.b, "  %%%s = select %s %%%s, %s %s, %s %s\n", value, predicateType, condition, typ, left, typ, right)
			return "%" + value
		})
}

// --- amd64_lower_horizontal_float.go ---
type amd64HorizontalFloatingSpec struct {
	laneBits int
	subtract bool
	vector   bool
}

// amd64HorizontalFloatingSpecs is the complete Go 1.27 horizontal
// floating-point add/subtract family. Legacy forms use yxm; V-prefixed forms
// use _yvaddsubpd and are deliberately limited to VEX X/Y registers.
var amd64HorizontalFloatingSpecs = map[Op]amd64HorizontalFloatingSpec{
	"HADDPS":  {laneBits: 32},
	"HADDPD":  {laneBits: 64},
	"HSUBPS":  {laneBits: 32, subtract: true},
	"HSUBPD":  {laneBits: 64, subtract: true},
	"VHADDPS": {laneBits: 32, vector: true},
	"VHADDPD": {laneBits: 64, vector: true},
	"VHSUBPS": {laneBits: 32, subtract: true, vector: true},
	"VHSUBPD": {laneBits: 64, subtract: true, vector: true},
}

func (c *amd64Ctx) lowerHorizontalFloating(op Op, ins Instr) (ok bool, terminated bool, err error) {
	return c.lowerNativePackedReduction(op, ins)
}

func (c *amd64Ctx) loadHorizontalFloatingOperand(operand Operand, byteWidth, laneBits int) (string, error) {
	bytesValue, err := c.loadPackedCompareBytes(operand, byteWidth)
	if err != nil {
		return "", err
	}
	lanes := byteWidth * 8 / laneBits
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to %s\n", result, byteWidth, bytesValue, amd64FMA3LLVMType(lanes, laneBits))
	return "%" + result, nil
}

// --- amd64_lower_implicit_mask_move.go ---
type amd64ImplicitMaskMoveSpec struct {
	byteWidth int
	vector    bool
}

// Go's frontend exposes the legacy SSE spelling both as MASKMOVOU and via
// the Intel-name alias MASKMOVDQU. MASKMOVQ is the corresponding MMX form;
// VMASKMOVDQU is the VEX spelling. All use the first operand as a byte mask,
// the second as data, and DI as the implicit memory destination.
var amd64ImplicitMaskMoveSpecs = map[Op]amd64ImplicitMaskMoveSpec{
	"MASKMOVQ":    {byteWidth: 8},
	"MASKMOVOU":   {byteWidth: 16},
	"MASKMOVDQU":  {byteWidth: 16},
	"VMASKMOVDQU": {byteWidth: 16, vector: true},
}

func (c *amd64Ctx) lowerImplicitMaskMove(op Op, ins Instr) (bool, bool, error) {
	spec, known, err := x86ImplicitMaskMoveProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	if spec.byteWidth == 8 || !x86ScalarFloatIntegerNativeTarget(c.goarch, c.targetTriple) ||
		!x86ResultNamedPredicateInstruction(ins) && !x86RawImplicitVectorMaskMoveSource(ins, c.goarch) {
		return true, false, fmt.Errorf("%w: implicit mask store needs its original native source/target and MMX owner", ErrProbeNeedsContext)
	}
	mask, err := c.loadX(ins.Args[0].Reg)
	if err != nil {
		return true, false, err
	}
	data, err := c.loadX(ins.Args[1].Reg)
	if err != nil {
		return true, false, err
	}
	addressInteger, err := c.loadReg(DI)
	if err != nil {
		return true, false, err
	}
	address := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", address, addressInteger)
	mnemonic := "maskmovdqu"
	if spec.vector {
		mnemonic = "vmaskmovdqu"
	}
	// Preserve WC/non-temporal behavior and implementation-dependent
	// zero-mask address faults, not a removable masked store or a fabricated
	// unconditional read of the destination.
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(<16 x i8> %s, <16 x i8> %s, ptr %%%s)\n",
		mnemonic+" $1, $0", "x,x,{di},~{memory}", data, mask, address)
	return true, false, nil
}

// --- amd64_lower_insert.go ---
// lowerPackedVectorInsert implements every Go 1.27 form in _yvinsertf128,
// _yvinsertf32x4, and _yvinsertf32x8. The floating and integer spellings have
// identical bit-level insert behavior; their lane type only changes EVEX mask
// granularity.
func (c *amd64Ctx) lowerPackedVectorInsert(op Op, ins Instr) (ok bool, terminated bool, err error) {
	return c.lowerInsertExtractFamily(op, ins)
}

// --- amd64_lower_insert_integer.go ---
type amd64PackedIntegerInsertSpec struct {
	laneBits int
	legacy   bool
}

var amd64PackedIntegerInsertSpecs = map[string]amd64PackedIntegerInsertSpec{
	"PINSRB":  {laneBits: 8, legacy: true},
	"PINSRW":  {laneBits: 16, legacy: true},
	"PINSRD":  {laneBits: 32, legacy: true},
	"PINSRQ":  {laneBits: 64, legacy: true},
	"VPINSRB": {laneBits: 8},
	"VPINSRW": {laneBits: 16},
	"VPINSRD": {laneBits: 32},
	"VPINSRQ": {laneBits: 64},
}

func (c *amd64Ctx) lowerPackedIntegerInsert(op Op, ins Instr) (ok bool, terminated bool, err error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	if _, known := amd64PackedIntegerInsertSpecs[base]; !known {
		return false, false, nil
	}
	ins, f, _, err := c.bindScalarLaneForm(op, ins)
	if err != nil {
		return true, false, err
	}
	source := ins.Args[f.source]
	if source.Kind == OpReg {
		source.Reg = f.transferReg
	}
	// Exact native m8/m16/m32/m64 reads remain volatile; FP uses the
	// independent complete-byte-span helper, not the first scalar slot.
	var scalar string
	if source.Kind == OpFP {
		scalar, err = c.loadScalarLaneFPBits(source.FPOffset, f.bits)
	} else {
		scalar, err = c.loadGPSIMDTransferSource(source, f.bits)
	}
	if err != nil {
		return true, false, err
	}
	baseBytes, err := c.loadX(ins.Args[f.base].Reg)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / f.bits
	baseLanes, inserted, out := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <%d x i%d>\n", baseLanes, baseBytes, lanes, f.bits)
	fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> %%%s, i%d %s, i32 %d\n", inserted, lanes, f.bits, baseLanes, f.bits, scalar, f.offset/(f.bits/8))
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %%%s to <16 x i8>\n", out, lanes, f.bits, inserted)
	if f.legacy {
		return true, false, c.storeX(ins.Args[f.destination].Reg, "%"+out)
	}
	return true, false, c.storePackedMoveOperand(ins.Args[f.destination], 16, "%"+out)
}

func amd64IsExtendedGPRegister(reg Reg) bool {
	switch strings.ToUpper(string(reg)) {
	case "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15":
		return true
	default:
		return false
	}
}

// --- amd64_lower_integer_dot.go ---
func (c *amd64Ctx) lowerIntegerPackedDotProduct(op Op, ins Instr) (bool, bool, error) {
	form, known, err := x86PackedDotProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	if err := c.validateConflictFunnelMemory(ins, form.x86PackedBinaryForm); err != nil {
		return true, false, err
	}
	var mask string
	if form.mask >= 0 {
		mask, err = c.loadK(ins.Args[form.mask].Reg)
		if err != nil {
			return true, false, err
		}
	}
	// E4 reads one exact volatile dword per enabled output lane; broadcast
	// reads m32 iff an output lane is enabled. VEX retains its full tuple.
	first, err := c.loadX86PackedShiftLanes(ins.Args[form.first], form.byteWidth, 32, form.broadcast, mask)
	if err != nil {
		return true, false, err
	}
	lanes, inputBits := form.byteWidth/4, form.spec.inputBits
	inputLanes := form.byteWidth * 8 / inputBits
	firstBits := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i32> %s to <%d x i%d>\n", firstBits, lanes, first, inputLanes, inputBits)
	second, err := c.loadPackedCompareBytes(ins.Args[form.second], form.byteWidth)
	if err != nil {
		return true, false, err
	}
	destination := ins.Args[form.destination]
	oldBytes, err := c.loadPackedCompareBytes(destination, form.byteWidth)
	if err != nil {
		return true, false, err
	}
	other := c.bitcastVectorBytesToIntegerLanes(form.byteWidth, inputLanes, inputBits, second)
	old := c.bitcastVectorBytesToIntegerLanes(form.byteWidth, lanes, 32, oldBytes)
	computed := c.emitPackedDotProduct(form.spec, lanes, "%"+firstBits, other, old)
	if form.mask >= 0 {
		computed = amd64ApplyI32LaneMask(c, lanes, computed, old, mask, form.zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i32> %s to <%d x i8>\n", out, lanes, computed, form.byteWidth)
	return true, false, c.storePackedMoveOperand(destination, form.byteWidth, "%"+out)
}

// --- amd64_lower_lddqu.go ---
type amd64UnalignedLoadSpec struct {
	maxBytes int
	vector   bool
}

// amd64UnalignedLoadSpecs is the complete Go 1.27 ylddqu/_yvlddqu grammar.
// Both instructions are load-only; legacy LDDQU is X-width, while VLDDQU
// adds the VEX Y-width row.
var amd64UnalignedLoadSpecs = map[Op]amd64UnalignedLoadSpec{
	"LDDQU":  {maxBytes: 16},
	"VLDDQU": {maxBytes: 32, vector: true},
}

func (c *amd64Ctx) lowerUnalignedVectorLoad(op Op, ins Instr) (ok bool, terminated bool, err error) {
	form, known, err := x86UnalignedLoadProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	if !x86ScalarFloatIntegerNativeTarget(c.goarch, c.targetTriple) || ins.Args[0].Kind == OpFP {
		return true, false, fmt.Errorf("%w: LDDQU needs its original x86 native access, not logical FP storage", ErrProbeNeedsContext)
	}
	// Share only the native vector transport. No alignment assumption is
	// introduced: the actual opcode retains its wider/repeated reads and #AC.
	move := amd64PackedVectorMoveForm{byteWidth: form.byteWidth, memory: 0, destination: 1, mask: -1}
	return true, false, c.lowerNativeAlignedVectorMemory(ins, move, !form.spec.vector)
}

// --- amd64_lower_leave.go ---
type amd64LeaveSpec struct {
	bits int
}

// amd64LeaveSpecs is the complete Go 1.27 LEAVE grammar. W is shared,
// L is 386-only, and Q is amd64-only. The lowering models the architectural
// sequence SP = BP; POP BP against the translated register/address state.
var amd64LeaveSpecs = map[Op]amd64LeaveSpec{
	"LEAVEW": {bits: 16},
	"LEAVEL": {bits: 32},
	"LEAVEQ": {bits: 64},
}

func (c *amd64Ctx) lowerLeave(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	spec, recognized := amd64LeaveSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("%s %s does not accept instruction suffixes: %q", c.goarch, baseOp, ins.Raw)
	}
	if c.goarch == "386" && spec.bits == 64 {
		return true, false, fmt.Errorf("386 %s is absent from Go 1.27's 32-bit encoding table: %q", baseOp, ins.Raw)
	}
	if c.goarch != "386" && spec.bits == 32 {
		return true, false, fmt.Errorf("amd64 %s is absent from Go 1.27's 64-bit encoding table: %q", baseOp, ins.Raw)
	}
	if len(ins.Args) != 0 {
		return true, false, fmt.Errorf("%s %s takes no operands: %q", c.goarch, baseOp, ins.Raw)
	}

	base, err := c.loadReg(BP)
	if err != nil {
		return true, false, err
	}
	address := base
	if c.goarch == "386" {
		low := c.truncI64(base, I32)
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", wide, low)
		address = "%" + wide
	}
	pointer := c.ptrFromAddrI64(address)
	typ := amd64StackLLVMType(spec.bits)
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load %s, ptr %s, align 1\n", value, typ, pointer)
	if err := c.storeRegSized(BP, typ, "%"+value); err != nil {
		return true, false, err
	}
	if c.goarch == "386" {
		address32 := c.truncI64(address, I32)
		next32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i32 %s, %d\n", next32, address32, spec.bits/8)
		next64 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", next64, next32)
		return true, false, c.storeRegUnchecked(SP, "%"+next64)
	}
	next := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add i64 %s, %d\n", next, address, spec.bits/8)
	return true, false, c.storeRegUnchecked(SP, "%"+next)
}

// --- amd64_lower_legacy_float_memory.go ---
func x86LegacyPackedFloatingNativeMemoryBits(ins Instr, goarch string) int {
	parsed, known, err := x86FloatArithmeticProperties(ins, goarch, "")
	form := parsed.x86FloatBinaryForm
	if !known || err != nil || !form.legacy || form.scalar || form.memory < 0 || ins.Args[form.memory].Kind == OpFP {
		return 0
	}
	return form.bits
}

// Legacy packed SSE arithmetic consumes one complete native m128 operand.
// An align-1 LLVM load followed by floating arithmetic can select a different
// load/instruction sequence, losing the original alignment and fault contract.
// Execute the exact validated opcode, including its source-order NaNs, MXCSR
// exceptions/rounding/DAZ/FTZ, and observable read even when the result is dead.
func (c *amd64Ctx) lowerLegacyPackedFloatingMemory(ins Instr, form x86FloatBinaryForm) error {
	source := ins.Args[form.first]
	if source.Kind == OpFP {
		// ABI0 virtual fields are independently allocated. Even a logical
		// contiguous field span is not original native stack alignment.
		return fmt.Errorf("%w: %s m128 needs contiguous original FP storage and native alignment context, not virtual ABI0 fields", ErrProbeNeedsContext, ins.Op)
	}
	if ins.x86AddressBits != 0 {
		return fmt.Errorf("%w: %s m128 lacks its original native address-size binding", ErrProbeNeedsContext, ins.Op)
	}
	if source.Kind == OpMem && !x86CallerMemoryCertified(ins, form.first) {
		if !c.nativeMemoryOperand(ins, form.first) {
			return fmt.Errorf("%w: %s m128 needs original native stack backing, not virtual SP/BP", ErrProbeNeedsContext, ins.Op)
		}
	}
	pointer, pointerType, _, err := c.packedVectorMemoryPointer(source)
	if err != nil {
		return err
	}
	left, err := c.loadX(ins.Args[form.second].Reg)
	if err != nil {
		return err
	}
	segment := ""
	if pointerType == "ptr addrspace(256)" {
		segment = "%gs:"
	} else if pointerType == "ptr addrspace(257)" {
		segment = "%fs:"
	}
	carrierType := amd64FMA3LLVMType(128/form.bits, form.bits)
	carrier, result, bytes := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to %s\n", carrier, left, carrierType)
	assembly := strings.ToLower(string(ins.Op)) + " " + segment + "($2), $0"
	// The tied private XMM value is read before its output is written. No
	// original GP, flags, upper SIMD bytes, or additional pointer permission
	// is created. Segment-aware pointers retain the original FS/GS prefix.
	// SSE1 admits a <4 x float> XMM carrier on physical i386; a byte-vector
	// constraint there requires SSE2 and fails LLVM legalization. These are
	// only bitcasts, not extra arithmetic or an x87 transport ABI.
	fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q(%s %%%s, %s %s)\n", result, carrierType, assembly, "=x,0,r,~{memory},~{fpsr}", carrierType, carrier, pointerType, pointer)
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", bytes, carrierType, result)
	return c.storeLegacyPackedLogical(ins.Args[form.destination], "%"+bytes)
}

// --- amd64_lower_low_multiply.go ---
func (c *amd64Ctx) lowerPackedLowMultiply(op Op, ins Instr) (bool, bool, error) {
	form, known, err := x86PackedLowMultiplyProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	first := ins.Args[form.first]
	if form.legacy && form.memory >= 0 {
		virtual := first.Kind == OpFP
		if first.Kind == OpMem && !x86CallerMemoryCertified(ins, form.memory) && !c.fixedLocalMemoryCertified(ins, form.memory) {
			virtual = !c.nativeMemoryOperand(ins, form.first)
		}
		if virtual {
			return true, false, fmt.Errorf("%w: legacy packed low multiply m128 needs original native storage, not virtual FP/SP/BP", ErrProbeNeedsContext)
		}
	}
	if form.memory >= 0 && first.Kind == OpFP {
		if err := c.validateX86PackedShiftFPSpan(first.FPOffset, form.memoryBytes); err != nil {
			return true, false, err
		}
	}
	bits := form.spec.laneBits
	err = c.emitPackedBinaryE4(ins, form.x86PackedBinaryForm, bits, "pmulld",
		func(lanes, bits int, first, second string) string {
			product := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = mul <%d x i%d> %s, %s\n", product, lanes, bits, second, first)
			return "%" + product
		})
	return true, false, err
}

func isAMD64MemoryOperand(op Operand) bool {
	switch op.Kind {
	case OpFP, OpMem:
		return true
	case OpSym:
		// Go TYPE_ADDR is an address, not a TYPE_MEM read.
		return !strings.HasPrefix(strings.TrimSpace(op.Sym), "$")
	default:
		return false
	}
}

// --- amd64_lower_maddword.go ---
// Both Go packed multiply-add families share the same ordered operand,
// memory and write-generation contract.
func (c *amd64Ctx) lowerPackedWordMultiplyAdd(op Op, ins Instr) (bool, bool, error) {
	return c.lowerPackedPhysical(op, ins, x86PackedMultiplyAdd)
}

func (c *amd64Ctx) emitPackedWordMultiplyAdd(wordLanes int, first, second string) string {
	wordType := fmt.Sprintf("<%d x i16>", wordLanes)
	wideType := fmt.Sprintf("<%d x i32>", wordLanes)
	firstWide := c.newTmp()
	secondWide := c.newTmp()
	products := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sext %s %s to %s\n", firstWide, wordType, first, wideType)
	fmt.Fprintf(c.b, "  %%%s = sext %s %s to %s\n", secondWide, wordType, second, wideType)
	fmt.Fprintf(c.b, "  %%%s = mul %s %%%s, %%%s\n", products, wideType, firstWide, secondWide)
	resultLanes := wordLanes / 2
	result := "zeroinitializer"
	for lane := 0; lane < resultLanes; lane++ {
		low := c.newTmp()
		high := c.newTmp()
		sum := c.newTmp()
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %%%s, i32 %d\n", low, wideType, products, lane*2)
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %%%s, i32 %d\n", high, wideType, products, lane*2+1)
		fmt.Fprintf(c.b, "  %%%s = add i32 %%%s, %%%s\n", sum, low, high)
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i32> %s, i32 %%%s, i32 %d\n", inserted, resultLanes, result, sum, lane)
		result = "%" + inserted
	}
	return result
}

func (c *amd64Ctx) emitPackedUnsignedSignedByteMultiplyAdd(byteLanes int, signedBytes, unsignedBytes string) string {
	byteType := fmt.Sprintf("<%d x i8>", byteLanes)
	wideType := fmt.Sprintf("<%d x i32>", byteLanes)
	signedWide := c.newTmp()
	unsignedWide := c.newTmp()
	products := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sext %s %s to %s\n", signedWide, byteType, signedBytes, wideType)
	fmt.Fprintf(c.b, "  %%%s = zext %s %s to %s\n", unsignedWide, byteType, unsignedBytes, wideType)
	fmt.Fprintf(c.b, "  %%%s = mul %s %%%s, %%%s\n", products, wideType, signedWide, unsignedWide)
	resultLanes := byteLanes / 2
	result := "zeroinitializer"
	for lane := 0; lane < resultLanes; lane++ {
		low := c.newTmp()
		high := c.newTmp()
		sum := c.newTmp()
		below := c.newTmp()
		lowerClamped := c.newTmp()
		above := c.newTmp()
		clamped := c.newTmp()
		narrow := c.newTmp()
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %%%s, i32 %d\n", low, wideType, products, lane*2)
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %%%s, i32 %d\n", high, wideType, products, lane*2+1)
		fmt.Fprintf(c.b, "  %%%s = add i32 %%%s, %%%s\n", sum, low, high)
		fmt.Fprintf(c.b, "  %%%s = icmp slt i32 %%%s, -32768\n", below, sum)
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i32 -32768, i32 %%%s\n", lowerClamped, below, sum)
		fmt.Fprintf(c.b, "  %%%s = icmp sgt i32 %%%s, 32767\n", above, lowerClamped)
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i32 32767, i32 %%%s\n", clamped, above, lowerClamped)
		fmt.Fprintf(c.b, "  %%%s = trunc i32 %%%s to i16\n", narrow, clamped)
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i16> %s, i16 %%%s, i32 %d\n", inserted, resultLanes, result, narrow, lane)
		result = "%" + inserted
	}
	return result
}

// --- amd64_lower_mask_arithmetic.go ---
type amd64MaskArithmeticSpec struct {
	bits  int
	shift string
}

// amd64MaskArithmeticSpecs covers Go 1.27's complete KADD and KSHIFT
// families. KADD wraps at the named mask width; KSHIFT produces zero when the
// unsigned byte count is greater than or equal to that width.
var amd64MaskArithmeticSpecs = map[Op]amd64MaskArithmeticSpec{
	"KADDB": {bits: 8}, "KADDW": {bits: 16}, "KADDD": {bits: 32}, "KADDQ": {bits: 64},
	"KSHIFTLB": {bits: 8, shift: "shl"}, "KSHIFTLW": {bits: 16, shift: "shl"},
	"KSHIFTLD": {bits: 32, shift: "shl"}, "KSHIFTLQ": {bits: 64, shift: "shl"},
	"KSHIFTRB": {bits: 8, shift: "lshr"}, "KSHIFTRW": {bits: 16, shift: "lshr"},
	"KSHIFTRD": {bits: 32, shift: "lshr"}, "KSHIFTRQ": {bits: 64, shift: "lshr"},
}

func (c *amd64Ctx) lowerMaskArithmetic(op Op, ins Instr) error {
	form, known, err := x86MaskValueProperties(op, ins, c.goarch)
	if err != nil {
		return err
	}
	if !known || form.unpack {
		return fmt.Errorf("%s unknown mask-arithmetic opcode %q", c.goarch, op)
	}
	spec := form.spec
	if spec.shift == "" {
		first, err := c.loadK(ins.Args[0].Reg)
		if err != nil {
			return err
		}
		second, err := c.loadK(ins.Args[1].Reg)
		if err != nil {
			return err
		}
		first = c.maskMoveI64(first, spec.bits)
		second = c.maskMoveI64(second, spec.bits)
		added := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i64 %s, %s\n", added, first, second)
		return c.storeK(ins.Args[2].Reg, c.maskMoveI64("%"+added, spec.bits))
	}

	source, err := c.loadK(ins.Args[1].Reg)
	if err != nil {
		return err
	}
	source = c.maskMoveI64(source, spec.bits)
	result := "0"
	count := int(uint8(ins.Args[0].Imm))
	if count < spec.bits {
		shifted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s i64 %s, %d\n", shifted, spec.shift, source, count)
		result = c.maskMoveI64("%"+shifted, spec.bits)
	}
	return c.storeK(ins.Args[2].Reg, result)
}

// --- amd64_lower_mask_to_vector.go ---
func (c *amd64Ctx) lowerMaskVectorMove(op Op, ins Instr) (bool, bool, error) {
	if ins.Op == "" {
		ins.Op = op
	}
	form, recognized, err := x86MaskVectorProperties(ins, c.goarch)
	if err != nil || !recognized {
		return recognized, false, err
	}
	if !strings.EqualFold(string(ins.Op), string(op)) {
		return true, false, fmt.Errorf("mask/vector dispatch/source opcode mismatch: %s/%s", op, ins.Op)
	}
	vectorOperand, maskOperand := ins.Args[form.vector], ins.Args[form.mask]
	lanes := form.byteWidth * 8 / form.spec.laneBits
	vectorType := fmt.Sprintf("<%d x i%d>", lanes, form.spec.laneBits)
	if !form.spec.maskToVector {
		bytes, err := c.loadPackedCompareBytes(vectorOperand, form.byteWidth)
		if err != nil {
			return true, false, err
		}
		vector := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to %s\n", vector, form.byteWidth, bytes, vectorType)
		signBits := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp slt %s %%%s, zeroinitializer\n", signBits, vectorType, vector)
		packedType := fmt.Sprintf("i%d", lanes)
		packed := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i1> %%%s to %s\n", packed, lanes, signBits, packedType)
		result := "%" + packed
		if lanes < 64 {
			wide := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext %s %s to i64\n", wide, packedType, result)
			result = "%" + wide
		}
		return true, false, c.storeK(maskOperand.Reg, result)
	}

	mask, err := c.loadK(maskOperand.Reg)
	if err != nil {
		return true, false, err
	}
	vector := "zeroinitializer"
	for lane := 0; lane < lanes; lane++ {
		shifted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr i64 %s, %d\n", shifted, mask, lane)
		bit := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i1\n", bit, shifted)
		element := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d -1, i%d 0\n", element, bit, form.spec.laneBits, form.spec.laneBits)
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, i%d %%%s, i32 %d\n", inserted, vectorType, vector, form.spec.laneBits, element, lane)
		vector = "%" + inserted
	}
	bytes := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <%d x i8>\n", bytes, vectorType, vector, form.byteWidth)
	// All widths are EVEX writes. Legacy storeX would preserve wider aliases
	// and contradict the caller's complete defined-byte effect.
	return true, false, c.storePackedMoveOperand(vectorOperand, form.byteWidth, "%"+bytes)
}

// --- amd64_lower_mask_unpack.go ---
// amd64MaskUnpackBits covers Go 1.27's complete KUNPCK family. The Plan 9
// first source is the encoded r/m operand and becomes the low half; the second
// source is VEX.vvvv and becomes the high half of the destination mask.
var amd64MaskUnpackBits = map[Op]int{
	"KUNPCKBW": 8,
	"KUNPCKWD": 16,
	"KUNPCKDQ": 32,
}

func (c *amd64Ctx) lowerMaskUnpack(op Op, ins Instr) error {
	form, known, err := x86MaskValueProperties(op, ins, c.goarch)
	if err != nil {
		return err
	}
	if !known || !form.unpack {
		return fmt.Errorf("%s unknown mask-unpack opcode %q", c.goarch, op)
	}
	bits := form.spec.bits

	low, err := c.loadK(ins.Args[0].Reg)
	if err != nil {
		return err
	}
	high, err := c.loadK(ins.Args[1].Reg)
	if err != nil {
		return err
	}
	low = c.maskMoveI64(low, bits)
	high = c.maskMoveI64(high, bits)
	shifted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shl i64 %s, %d\n", shifted, high, bits)
	combined := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = or i64 %%%s, %s\n", combined, shifted, low)
	result := "%" + combined
	if bits < 32 {
		result = c.maskMoveI64(result, bits*2)
	}
	return c.storeK(ins.Args[2].Reg, result)
}

// --- amd64_lower_minmax.go ---
type amd64PackedIntegerMinMaxSpec struct {
	laneBits  int
	signed    bool
	minimum   bool
	broadcast bool
	mapNumber int
	opcode    int
}

// The twelve legacy and sixteen VEX/EVEX members share typed operand and
// numerical rules. Legacy retains its RMW/upper aliases and original m128
// opcode; only VEX/EVEX D/Q has scalar-memory broadcast.
func (c *amd64Ctx) lowerPackedIntegerMinMax(op Op, ins Instr) (ok bool, terminated bool, err error) {
	form, known, err := x86IntegerMinMaxProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	if err := c.validateConflictFunnelMemory(ins, form.x86PackedBinaryForm); err != nil {
		return true, false, err
	}
	first := ins.Args[form.first]
	if form.legacy && form.memory >= 0 &&
		(first.Kind == OpFP || first.Kind == OpMem && !c.nativeMemoryOperand(ins, form.first) ||
			!x86ScalarFloatIntegerNativeTarget(c.goarch, c.targetTriple)) {
		return true, false, fmt.Errorf("%w: legacy integer min/max m128 needs its original native storage/target", ErrProbeNeedsContext)
	}
	spec := form.spec
	predicate := "ult"
	if spec.signed {
		predicate = "slt"
	}
	if !spec.minimum {
		predicate = strings.Replace(predicate, "lt", "gt", 1)
	}
	legacyMnemonic := ""
	if form.legacy && form.memory >= 0 {
		legacyMnemonic = strings.ToLower(string(op))
	}
	err = c.emitPackedBinaryE4(ins, form.x86PackedBinaryForm, spec.laneBits, legacyMnemonic,
		func(lanes, bits int, first, second string) string {
			compared, computed := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp %s <%d x i%d> %s, %s\n", compared, predicate, lanes, bits, second, first)
			fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, <%d x i%d> %s, <%d x i%d> %s\n", computed, lanes, compared, lanes, bits, second, lanes, bits, first)
			return "%" + computed
		})
	return true, false, err
}

var amd64PackedIntegerMinMaxSpecs = map[string]amd64PackedIntegerMinMaxSpec{
	"VPMINSB": {laneBits: 8, signed: true, minimum: true, mapNumber: 2, opcode: 0x38},
	"VPMINUB": {laneBits: 8, minimum: true, mapNumber: 1, opcode: 0xda},
	"VPMAXSB": {laneBits: 8, signed: true, mapNumber: 2, opcode: 0x3c},
	"VPMAXUB": {laneBits: 8, mapNumber: 1, opcode: 0xde},
	"VPMINSW": {laneBits: 16, signed: true, minimum: true, mapNumber: 1, opcode: 0xea},
	"VPMINUW": {laneBits: 16, minimum: true, mapNumber: 2, opcode: 0x3a},
	"VPMAXSW": {laneBits: 16, signed: true, mapNumber: 1, opcode: 0xee},
	"VPMAXUW": {laneBits: 16, mapNumber: 2, opcode: 0x3e},

	"VPMINSD": {laneBits: 32, signed: true, minimum: true, broadcast: true, mapNumber: 2, opcode: 0x39},
	"VPMINUD": {laneBits: 32, minimum: true, broadcast: true, mapNumber: 2, opcode: 0x3b},
	"VPMAXSD": {laneBits: 32, signed: true, broadcast: true, mapNumber: 2, opcode: 0x3d},
	"VPMAXUD": {laneBits: 32, broadcast: true, mapNumber: 2, opcode: 0x3f},
	"VPMINSQ": {laneBits: 64, signed: true, minimum: true, broadcast: true, mapNumber: 2, opcode: 0x39},
	"VPMINUQ": {laneBits: 64, minimum: true, broadcast: true, mapNumber: 2, opcode: 0x3b},
	"VPMAXSQ": {laneBits: 64, signed: true, broadcast: true, mapNumber: 2, opcode: 0x3d},
	"VPMAXUQ": {laneBits: 64, broadcast: true, mapNumber: 2, opcode: 0x3f},
}

// --- amd64_lower_mov_extension.go ---
func (c *amd64Ctx) lowerScalarExtensionMove(op Op, ins Instr) error {
	form, recognized, err := x86ScalarExtensionProperties(op, ins, c.goarch)
	if err != nil {
		return err
	}
	if !recognized {
		return fmt.Errorf("unrecognized scalar extension opcode %s: %q", op, ins.Raw)
	}
	spec := form.spec
	sourceType := amd64IntegerTypeForBits(spec.sourceBits)
	destinationType := amd64IntegerTypeForBits(spec.destinationBits)
	var value string
	native := c.nativeMemoryOperand(ins, 0) ||
		x86CallerMemoryCertified(ins, 0) || c.fixedLocalMemoryCertified(ins, 0)
	if native {
		if ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride {
			return fmt.Errorf("%w: scalar extension needs its original native address size", ErrProbeNeedsContext)
		}
		pointer, pointerType, _, pointerErr := c.packedVectorMemoryPointer(form.source)
		if pointerErr != nil {
			return pointerErr
		}
		loaded := c.newTmp()
		// Even a dead extension must read (and possibly fault on) its exact
		// source width. No validity or alignment assumption follows.
		fmt.Fprintf(c.b, "  %%%s = load volatile %s, %s %s, align 1\n", loaded, sourceType, pointerType, pointer)
		value = "%" + loaded
	} else {
		value, err = c.evalIntSized(form.source, sourceType)
	}
	if err != nil {
		return err
	}
	if spec.sourceBits < spec.destinationBits {
		extended := c.newTmp()
		extension := "zext"
		if spec.signed {
			extension = "sext"
		}
		fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", extended, extension, sourceType, value, destinationType)
		value = "%" + extended
	}
	return c.storeRegSized(form.result, destinationType, value)
}

// Only the paired volatile emitter can supply these conditional numerical
// result bytes. This creates no reusable pointee, bounds or caller proof.
func x86LoweredScalarExtensionRead(ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) (bool, bool) {
	form, known, err := x86ScalarExtensionProperties(ins.Op, ins, arch)
	if !known || err != nil || form.source.Kind != OpMem || form.source.Mem.Sym != "" ||
		!x86OrdinaryNativeMemoryOperand(form.source, arch) || ins.x86NumericalRead != nil {
		return false, false
	}
	if ins.x86Encoded || ins.x86SourceRaw != nil || ins.x86RawNearReturn != nil ||
		ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride || ins.x86SegmentPrefix != 0 ||
		!x86ResultReadWithNativeGPContinuation(ins, form.source, int64(form.spec.sourceBits/8), state, owned, arch) {
		return false, true
	}
	return x86ResultStore(Operand{Kind: OpReg, Reg: form.result}, int64(form.spec.destinationBits/8),
		state, owned, resultOffset, arch), true
}

// --- amd64_lower_movbe.go ---
// lowerMOVBE implements both rows of Go 1.27's ymovbe table: memory to
// general register and general register to memory, for W/L/Q widths.
func (c *amd64Ctx) lowerMOVBE(op Op, ins Instr) (ok bool, terminated bool, err error) {
	form, known, err := x86MOVBEProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	typ := amd64IntegerTypeForBits(form.bits)
	value, err := c.evalSizedNativeGPSource(form.source, typ, ins.x86AddressBits)
	if err != nil {
		return true, false, err
	}
	swapped := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.bswap.%s(%s %s)\n", swapped, typ, typ, typ, value)
	if !form.store {
		return true, false, c.storeRegSized(form.destination.Reg, typ, "%"+swapped)
	}
	return true, false, c.storeMOVBEMemory(form.destination, typ, "%"+swapped)
}

func (c *amd64Ctx) storeMOVBEMemory(destination Operand, typ LLVMType, value string) error {
	switch destination.Kind {
	case OpMem:
		pointer, pointerType, _, err := c.packedVectorMemoryPointer(destination)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store volatile %s %s, %s %s, align 1\n", typ, value, pointerType, pointer)
		return nil
	case OpFP:
		return c.storeFPResult(destination.FPOffset, typ, value)
	case OpSym:
		pointer, err := c.ptrFromSB(destination.Sym)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store volatile %s %s, ptr %s, align 1\n", typ, value, pointer)
		return nil
	default:
		return fmt.Errorf("MOVBE destination is not memory: %s", destination.String())
	}
}

// --- amd64_lower_msr.go ---
// lowerMSRAccess implements the complete RDMSR/WRMSR instruction family.
// Go 1.27 uses the operand-free ynone optab entry for both instructions on
// amd64 and 386; the architectural operands are ECX and EDX:EAX.
func (c *amd64Ctx) lowerMSRAccess(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	switch baseOp {
	case "RDMSR", "WRMSR":
		// handled below
	default:
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("%s %s does not accept instruction suffixes: %q", c.goarch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 0 {
		return true, false, fmt.Errorf("%s %s takes no operands: %q", c.goarch, baseOp, ins.Raw)
	}

	cx, err := c.loadReg(CX)
	if err != nil {
		return true, false, err
	}
	cx32 := c.truncI64(cx, I32)
	if baseOp == "RDMSR" {
		call := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call { i32, i32 } asm sideeffect \"rdmsr\", \"={ax},={dx},{cx},~{dirflag},~{fpsr},~{flags}\"(i32 %s)\n", call, cx32)
		for index, reg := range []Reg{AX, DX} {
			part := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractvalue { i32, i32 } %%%s, %d\n", part, call, index)
			if err := c.storeRegSized(reg, I32, "%"+part); err != nil {
				return true, false, err
			}
		}
		return true, false, nil
	}

	ax, err := c.loadReg(AX)
	if err != nil {
		return true, false, err
	}
	dx, err := c.loadReg(DX)
	if err != nil {
		return true, false, err
	}
	ax32 := c.truncI64(ax, I32)
	dx32 := c.truncI64(dx, I32)
	fmt.Fprintf(c.b, "  call void asm sideeffect \"wrmsr\", \"{ax},{dx},{cx},~{dirflag},~{fpsr},~{flags}\"(i32 %s, i32 %s, i32 %s)\n", ax32, dx32, cx32)
	return true, false, nil
}

// --- amd64_lower_neg.go ---
// Both complete unary families use Go's yscond(Ymb) grammar, including
// byte-register spellings of wide operations. Only NEG changes flags.
type x86UnaryYmbSpec struct {
	bits   int
	negate bool
}

var x86UnaryYmbSpecs = map[Op]x86UnaryYmbSpec{
	"NEGB": {bits: 8, negate: true},
	"NEGW": {bits: 16, negate: true},
	"NEGL": {bits: 32, negate: true},
	"NEGQ": {bits: 64, negate: true},
	"NOTB": {bits: 8},
	"NOTW": {bits: 16},
	"NOTL": {bits: 32},
	"NOTQ": {bits: 64},
}

func (c *amd64Ctx) lowerScalarUnaryYmb(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, recognized := x86UnaryYmbSpecs[op]
	if !recognized {
		return false, false, nil
	}
	bits := spec.bits
	if c.goarch == "386" && bits == 64 {
		return true, false, fmt.Errorf("386 %s is illegal in 32-bit mode: %q", op, ins.Raw)
	}
	if len(ins.Args) != 1 {
		return true, false, fmt.Errorf("%s %s expects one register/memory operand: %q", c.goarch, op, ins.Raw)
	}
	destination := ins.Args[0]
	if destination.Kind == OpReg {
		if !isGoYmbRegisterForArch(destination.Reg, c.goarch) {
			return true, false, fmt.Errorf("%s %s register is outside Go 1.27's Ymb class: %q", c.goarch, op, ins.Raw)
		}
		destination.Reg = amd64YmbEffectiveRegister(destination.Reg, bits)
	} else if !isAMD64MemoryOperand(destination) {
		return true, false, fmt.Errorf("%s %s operand is outside Go 1.27's Ymb class: %q", c.goarch, op, ins.Raw)
	}

	typ := amd64IntegerTypeForBits(bits)
	value, store, err := c.loadScalarRMWDestination(op, ins, destination, typ)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	if !spec.negate {
		fmt.Fprintf(c.b, "  %%%s = xor %s %s, -1\n", result, typ, value)
		return true, false, store("%" + result)
	}
	fmt.Fprintf(c.b, "  %%%s = sub %s 0, %s\n", result, typ, value)
	if err := store("%" + result); err != nil {
		return true, false, err
	}
	// NEG has the same arithmetic flags as subtraction from zero: CF is set
	// exactly for nonzero inputs and OF is set only for the signed minimum.
	c.setScalarAddSubFlags(typ, false, "0", value, "%"+result)
	return true, false, nil
}

// --- amd64_lower_non_temporal_move.go ---
// A non-temporal hint does not make the instruction's native access optional.
// Reuse the aligned packed-move emitter, including original faults, exact
// width, segment address spaces and encoding-aware register writeback.
func (c *amd64Ctx) lowerNonTemporalVectorMove(op Op, ins Instr) (bool, bool, error) {
	form, known, err := x86NonTemporalVectorProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	if !x86ScalarFloatIntegerNativeTarget(c.goarch, c.targetTriple) {
		return true, false, fmt.Errorf("%w: non-temporal vector access needs its actual x86 target", ErrProbeNeedsContext)
	}
	if form.trap {
		return c.lowerSyscall("UD2", Instr{Op: "UD2"})
	}
	if ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride ||
		(ins.x86Encoded || ins.x86SourceRaw != nil) && ins.x86NumericalRead == nil && ins.x86SDKLiteral == nil {
		return true, false, fmt.Errorf("%w: non-temporal vector access needs its actual x86 target/encoding", ErrProbeNeedsContext)
	}
	if !c.nativeMemoryOperand(ins, form.move.memory) &&
		!x86CallerMemoryCertified(ins, form.move.memory) && !c.fixedLocalMemoryCertified(ins, form.move.memory) {
		return true, false, fmt.Errorf("%w: non-temporal vector access needs native backing, not logical FP/AUTO bytes", ErrProbeNeedsContext)
	}
	if err := x86Mode32VectorRegisterContext(ins, c.goarch); err != nil {
		return true, false, err
	}
	native := ins
	native.Op = Op(form.spec.native) // Local spelling adapter; never mutate original source identity.
	return true, false, c.lowerNativeAlignedVectorMemory(native, form.move, !form.spec.vector)
}

// --- amd64_lower_packed_binary_e4.go ---
// emitPackedBinaryE4 shares the lane pipeline after the family's grammar and
// storage checks. Legacy memory keeps its original SSE opcode and alignment
// faults. VEX/EVEX uses E4 reads: even dead outputs retain active volatile
// accesses, while inactive lanes are suppressed. The operation callback owns
// only register arithmetic; this helper supplies no source or memory authority.
func (c *amd64Ctx) emitPackedBinaryE4(ins Instr, form x86PackedBinaryForm, bits int,
	legacyMnemonic string, operation func(lanes, bits int, first, second string) string) error {
	lanes := form.byteWidth * 8 / bits
	second, err := c.loadPackedCompareLanes(ins.Args[form.second], form.byteWidth, bits, false)
	if err != nil {
		return err
	}
	var mask, value string
	if form.mask >= 0 {
		mask, err = c.loadK(ins.Args[form.mask].Reg)
		if err != nil {
			return err
		}
	}
	first := ins.Args[form.first]
	if form.legacy && form.memory >= 0 {
		value, err = c.emitPackedBinaryNativeMemory(first, bits, second, legacyMnemonic)
	} else {
		var input string
		input, err = c.loadX86PackedShiftLanes(first, form.byteWidth, bits, form.broadcast, mask)
		if err == nil {
			value = operation(lanes, bits, input, second)
		}
	}
	if err != nil {
		return err
	}
	destination := ins.Args[form.destination]
	if form.mask >= 0 {
		old := "zeroinitializer"
		if !form.zeroing {
			old, err = c.loadPackedCompareLanes(destination, form.byteWidth, bits, false)
			if err != nil {
				return err
			}
		}
		value = amd64ApplyIntegerLaneMask(c, lanes, bits, value, old, mask, form.zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, bits, value, form.byteWidth)
	if form.legacy {
		return c.storeLegacyPackedLogical(destination, "%"+out)
	}
	return c.storePackedMoveOperand(destination, form.byteWidth, "%"+out)
}

// --- amd64_lower_packed_precision.go ---
func (c *amd64Ctx) lowerPackedPrecisionConvert(op Op, ins Instr) (bool, bool, error) {
	form, known, err := x86PackedPrecisionProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	ins.Op = op
	if !x86ScalarFloatIntegerNativeTarget(c.goarch, c.targetTriple) {
		return true, false, fmt.Errorf("%w: %s needs its matching native x86 MXCSR target", ErrProbeNeedsContext, op)
	}
	if c.fpScalarSource.x86SourceStack != nil {
		return true, false, fmt.Errorf("%w: %s retains its separate source/frame owner", ErrProbeNeedsContext, op)
	}
	source := ins.Args[0]
	if source.Kind == OpFP {
		if err := c.validateX86PackedShiftFPSpan(source.FPOffset, form.memoryBytes); err != nil {
			return true, false, err
		}
		for at := source.FPOffset; at < source.FPOffset+int64(form.memoryBytes); at++ {
			if slot, _, _ := c.fpVectorSlot(at); slot.Type == Ptr {
				return true, false, fmt.Errorf("%w: %s cannot use opaque pointer bits as floating input", ErrProbeNeedsContext, op)
			}
		}
	} else if form.memory >= 0 && !c.nativeMemoryOperand(ins, form.memory) && !c.fixedLocalMemoryCertified(ins, form.memory) {
		return true, false, fmt.Errorf("%w: %s needs its original native source address", ErrProbeNeedsContext, op)
	}
	base, _, _ := strings.Cut(strings.ToLower(string(op)), ".")
	mnemonic := base
	if base == "vcvtpd2psx" || base == "vcvtpd2psy" {
		mnemonic = "vcvtpd2ps"
		if form.memory >= 0 && source.Kind != OpFP && !form.properties.broadcast {
			// AT&T memory syntax needs the source VL, not the narrower
			// destination carrier, to distinguish X/m128 from Y/m256.
			mnemonic = base
		}
	}
	return true, false, c.emitNativePackedConversion(ins, x86NativePackedConversion{
		byteWidth: form.shape.destinationBytes, sourceBytes: form.shape.sourceBytes,
		memoryBytes: form.memoryBytes, outputBits: form.spec.destinationBits, logicalFPBits: form.spec.sourceBits,
		lanes: form.shape.lanes, destination: form.destination, mask: form.mask,
		legacy: form.spec.legacy, evex: form.evex, broadcast: form.properties.broadcast,
		zeroing: form.properties.zeroing, sae: form.properties.sae, rounding: form.properties.rounding, mnemonic: mnemonic,
	})
}

// Independent scalar FP fields supply only their checked little-endian value
// bytes. Fill unused register-container bytes with private zeros, or replicate
// one declared scalar for a broadcast; never invent a physical FP address.
func (c *amd64Ctx) loadPackedConversionFPValue(source Operand, sourceBytes, memoryBytes, bits int, broadcast bool) (string, error) {
	bytes, err := c.loadFPVectorBytes(source.FPOffset, memoryBytes)
	if err != nil {
		return "", err
	}
	if broadcast {
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to i%d\n", value, memoryBytes, bytes, bits)
		lanes := sourceBytes * 8 / bits
		splat := amd64SplatInteger(c, lanes, bits, "%"+value)
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x float>\n", out, lanes, bits, splat, sourceBytes/4)
		return "%" + out, nil
	}
	if memoryBytes != sourceBytes {
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i8> %s, <%d x i8> zeroinitializer, <%d x i32> %s\n",
			out, memoryBytes, bytes, memoryBytes, sourceBytes, llvmI32RangeMask(0, sourceBytes))
		bytes = "%" + out
	}
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to <%d x float>\n", value, sourceBytes, bytes, sourceBytes/4)
	return "%" + value, nil
}

// --- amd64_lower_packed_testmask.go ---
type amd64PackedTestMaskSpec struct {
	laneBits int
	testZero bool
}

var amd64PackedTestMaskSpecs = map[string]amd64PackedTestMaskSpec{
	"VPTESTMB":  {laneBits: 8},
	"VPTESTMW":  {laneBits: 16},
	"VPTESTMD":  {laneBits: 32},
	"VPTESTMQ":  {laneBits: 64},
	"VPTESTNMB": {laneBits: 8, testZero: true},
	"VPTESTNMW": {laneBits: 16, testZero: true},
	"VPTESTNMD": {laneBits: 32, testZero: true},
	"VPTESTNMQ": {laneBits: 64, testZero: true},
}

// lowerPackedTestMask implements the complete Go 1.27 _yvpshufbitqmb
// operand table shared by VPTESTM{B,W,D,Q} and VPTESTNM{B,W,D,Q}.
// VPTESTM sets each K bit when the corresponding source-lane intersection is
// nonzero; VPTESTNM sets it when that intersection is zero.
func (c *amd64Ctx) lowerPackedTestMask(op Op, ins Instr) (ok bool, terminated bool, err error) {
	form, known, err := x86PackedTestMaskProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	spec, byteWidth := form.spec, form.byteWidth
	first, second := form.source, ins.Args[form.second]
	destination := ins.Args[form.destination]
	writeMask := ""
	if form.mask >= 0 {
		writeMask, err = c.loadK(ins.Args[form.mask].Reg)
		if err != nil {
			return true, false, err
		}
	}
	firstValue, err := c.loadX86PackedShiftLanes(first, byteWidth, spec.laneBits, form.broadcast, writeMask)
	if err != nil {
		return true, false, err
	}
	secondValue, err := c.loadPackedCompareLanes(second, byteWidth, spec.laneBits, false)
	if err != nil {
		return true, false, err
	}
	lanes := byteWidth * 8 / spec.laneBits
	vectorType := fmt.Sprintf("<%d x i%d>", lanes, spec.laneBits)
	intersection := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and %s %s, %s\n", intersection, vectorType, firstValue, secondValue)
	predicate := "ne"
	if spec.testZero {
		predicate = "eq"
	}
	tested := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp %s %s %%%s, zeroinitializer\n", tested, predicate, vectorType, intersection)
	return true, false, c.storeVectorPredicates(destination.Reg, "%"+tested, lanes, writeMask)
}

// --- amd64_lower_parallel_bits.go ---
// Both BMI2 families share the complete three-word grammar with ANDN.
// Their operation and preserved FLAGS remain separate.
func (c *amd64Ctx) lowerParallelBitDepositExtract(op Op, ins Instr) (bool, bool, error) {
	form, known, err := x86TernaryGPProperties(op, ins, c.goarch)
	if !known || form.spec.operation == x86TernaryANDN {
		return false, false, nil
	}
	if err != nil {
		return true, false, err
	}
	bits := form.spec.bits
	typ := amd64IntegerTypeForBits(bits)
	mask, err := c.evalSizedNativeGPSource(form.first, typ, ins.x86AddressBits)
	if err != nil {
		return true, false, err
	}
	source, err := c.evalIntSized(form.second, typ)
	if err != nil {
		return true, false, err
	}
	result := c.emitParallelBitOperation(form.spec.operation == x86TernaryPDEP, bits, mask, source)
	return true, false, c.storeRegSized(form.destination.Reg, typ, result)
}

// emitParallelBitOperation emits target-independent LLVM so translated code
// retains PDEP/PEXT semantics even when the LLVM execution host lacks BMI2.
// cursor is at most bit before each iteration, so every variable shift stays
// strictly below the integer width and cannot produce LLVM poison.
func (c *amd64Ctx) emitParallelBitOperation(deposit bool, bits int, mask, source string) string {
	typ := fmt.Sprintf("i%d", bits)
	result := "0"
	cursor := "0"
	for bit := 0; bit < bits; bit++ {
		shiftedMask := c.newTmp()
		maskBit := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %d\n", shiftedMask, typ, mask, bit)
		fmt.Fprintf(c.b, "  %%%s = and %s %%%s, 1\n", maskBit, typ, shiftedMask)

		sourceShift := cursor
		destinationShift := fmt.Sprintf("%d", bit)
		if !deposit {
			sourceShift = fmt.Sprintf("%d", bit)
			destinationShift = cursor
		}
		shiftedSource := c.newTmp()
		sourceBit := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %s\n", shiftedSource, typ, source, sourceShift)
		fmt.Fprintf(c.b, "  %%%s = and %s %%%s, 1\n", sourceBit, typ, shiftedSource)
		placed := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shl %s %%%s, %s\n", placed, typ, sourceBit, destinationShift)
		enabledMask := c.newTmp()
		enabled := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub %s 0, %%%s\n", enabledMask, typ, maskBit)
		fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %%%s\n", enabled, typ, placed, enabledMask)
		nextResult := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or %s %s, %%%s\n", nextResult, typ, result, enabled)
		result = "%" + nextResult
		nextCursor := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add %s %s, %%%s\n", nextCursor, typ, cursor, maskBit)
		cursor = "%" + nextCursor
	}
	return result
}

// --- amd64_lower_permute.go ---
// Dword variable permutations share the complete full-vector data/index
// envelope and E4NF reads with qword variable permutations.
func (c *amd64Ctx) lowerVariableDwordPermute(op Op, ins Instr) (bool, bool, error) {
	form, known, err := x86VariableDwordPermuteProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	return c.lowerElementPermute(form, ins)
}

// --- amd64_lower_permute128.go ---
func (c *amd64Ctx) lowerPermute128(op Op, ins Instr) (bool, bool, error) {
	form, known, err := x86Permute128Properties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	if err := c.validateConflictFunnelMemory(ins, form.x86PackedBinaryForm); err != nil {
		return true, false, err
	}
	// Type6 has no selector-based fault suppression: even two zero halves
	// and dead results retain the complete unaligned m256 native access.
	first, err := c.loadX86PackedShiftBytes(ins.Args[form.first], 32, true)
	if err != nil {
		return true, false, err
	}
	second, err := c.loadPackedCompareBytes(ins.Args[form.second], 32)
	if err != nil {
		return true, false, err
	}
	a, b, selected := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <32 x i8> %s to <4 x i64>\n", a, first)
	fmt.Fprintf(c.b, "  %%%s = bitcast <32 x i8> %s to <4 x i64>\n", b, second)
	var indices []int
	var zeros []string
	hasZero := false
	for lane := 0; lane < 4; lane++ {
		at := form.sourceByte(lane * 8)
		zero := at < 0
		if zero {
			at = 0 // A constant select below does not observe this lane.
		}
		indices = append(indices, at/8)
		zeros = append(zeros, fmt.Sprint("i1 ", zero))
		hasZero = hasZero || zero
	}
	fmt.Fprintf(c.b, "  %%%s = shufflevector <4 x i64> %%%s, <4 x i64> %%%s, <4 x i32> %s\n",
		selected, a, b, llvmI32Mask(indices))
	if hasZero {
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select <4 x i1> <%s>, <4 x i64> zeroinitializer, <4 x i64> %%%s\n",
			value, strings.Join(zeros, ", "), selected)
		selected = value
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i64> %%%s to <32 x i8>\n", out, selected)
	return true, false, c.storePackedMoveOperand(ins.Args[form.destination], 32, "%"+out)
}

// --- amd64_lower_permute_qword.go ---
// Qword permutations reuse the complete typed operand and E4NF read machinery
// with VPERMIL, not its 128-bit selector or variable control/data ordering.
func (c *amd64Ctx) lowerQwordPermute(op Op, ins Instr) (bool, bool, error) {
	form, known, err := x86QwordPermuteProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	return c.lowerElementPermute(form, ins)
}

// --- amd64_lower_popcount_vector.go ---
type amd64PackedBitCountKind uint8

const (
	amd64PackedPopulationCount amd64PackedBitCountKind = iota
	amd64PackedLeadingZeroCount
)

type amd64PackedBitCountSpec struct {
	laneBits  int
	kind      amd64PackedBitCountKind
	broadcast bool
}

// amd64PackedBitCountSpecs models the complete Go 1.27 _yvexpandpd grammar
// for packed population-count and leading-zero-count instructions.
var amd64PackedBitCountSpecs = map[Op]amd64PackedBitCountSpec{
	"VPOPCNTB": {laneBits: 8, kind: amd64PackedPopulationCount},
	"VPOPCNTW": {laneBits: 16, kind: amd64PackedPopulationCount},
	"VPOPCNTD": {laneBits: 32, kind: amd64PackedPopulationCount, broadcast: true},
	"VPOPCNTQ": {laneBits: 64, kind: amd64PackedPopulationCount, broadcast: true},
	"VPLZCNTD": {laneBits: 32, kind: amd64PackedLeadingZeroCount, broadcast: true},
	"VPLZCNTQ": {laneBits: 64, kind: amd64PackedLeadingZeroCount, broadcast: true},
}

// lowerPackedBitCount implements X/Y/Z register or memory sources, K1-K7
// merge and .Z, and each opcode's scalar-memory broadcast forms.
func (c *amd64Ctx) lowerPackedBitCount(op Op, ins Instr) (ok bool, terminated bool, err error) {
	form, known, err := x86PackedBitCountProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	spec, byteWidth := form.spec, form.byteWidth
	source, destination := ins.Args[form.first], ins.Args[form.destination]
	mask := ""
	if form.mask >= 0 {
		mask, err = c.loadK(ins.Args[form.mask].Reg)
		if err != nil {
			return true, false, err
		}
	}

	lanes := byteWidth * 8 / spec.laneBits
	// E4 suppresses inactive native lanes; enabled reads remain observable
	// even when the computed count is dead. FP fields keep their full span.
	sourceValue, err := c.loadX86PackedShiftLanes(source, byteWidth, spec.laneBits, form.broadcast, mask)
	if err != nil {
		return true, false, err
	}
	computed := c.newTmp()
	if spec.kind == amd64PackedLeadingZeroCount {
		fmt.Fprintf(c.b, "  %%%s = call <%d x i%d> @llvm.ctlz.v%di%d(<%d x i%d> %s, i1 false)\n",
			computed, lanes, spec.laneBits, lanes, spec.laneBits, lanes, spec.laneBits, sourceValue)
	} else {
		fmt.Fprintf(c.b, "  %%%s = call <%d x i%d> @llvm.ctpop.v%di%d(<%d x i%d> %s)\n",
			computed, lanes, spec.laneBits, lanes, spec.laneBits, lanes, spec.laneBits, sourceValue)
	}
	result := "%" + computed
	if form.mask >= 0 {
		oldBytes, err := c.loadPackedCompareBytes(destination, byteWidth)
		if err != nil {
			return true, false, err
		}
		old := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, spec.laneBits, oldBytes)
		result = amd64ApplyIntegerLaneMask(c, lanes, spec.laneBits, result, old, mask, form.zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, spec.laneBits, result, byteWidth)
	return true, false, c.storePackedMoveOperand(destination, byteWidth, "%"+out)
}

// --- amd64_lower_random.go ---
// lowerHardwareRandom implements every Go 1.27 yrdrand form for both the
// RDRAND and RDSEED instruction families. Both instructions return success in
// CF and architecturally clear OF, SF, ZF, AF, and PF.
func (c *amd64Ctx) lowerHardwareRandom(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, known, err := x86HardwareRandomProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}

	typ := amd64IntegerTypeForBits(spec.bits)
	call := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call { %s, i32 } @llvm.x86.%s.%d()\n", call, typ, spec.native, spec.bits)
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractvalue { %s, i32 } %%%s, 0\n", value, typ, call)
	status := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractvalue { %s, i32 } %%%s, 1\n", status, typ, call)

	// SP is a legal Yrl destination in Go's 386 table. This instruction is the
	// modeled write itself, so permit storeRegSized to update the virtual SP.
	previousAllowSPWrite := c.allowSPWrite
	if c.goarch == "386" && ins.Args[0].Reg == SP {
		c.allowSPWrite = true
	}
	err = c.storeRegSized(ins.Args[0].Reg, typ, "%"+value)
	c.allowSPWrite = previousAllowSPWrite
	if err != nil {
		return true, false, err
	}

	carry := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ne i32 %%%s, 0\n", carry, status)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", carry, c.flagsCFSlot)
	c.clearX86StatusFlags(x86StatusAll &^ x86StatusCF)
	return true, false, nil
}

// --- amd64_lower_set.go ---
// lowerConditionalSet implements the complete Go 1.27 SETcc family. All 16
// names use yscond, whose single operand is the byte-register-or-memory Ymb
// class.
func (c *amd64Ctx) lowerConditionalSet(op Op, ins Instr) (ok bool, terminated bool, err error) {
	form, recognized, err := x86ConditionalSetProperties(op, ins, c.goarch)
	if !recognized {
		return false, false, nil
	}
	if err != nil {
		return true, false, err
	}
	condition, err := c.x86Condition(form.condition)
	if err != nil {
		return true, false, err
	}
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, i8 1, i8 0\n", value, condition)
	if err := c.storeConditionalSetByte(form.destination, "%"+value); err != nil {
		return true, false, err
	}
	return true, false, nil
}

func (c *amd64Ctx) storeConditionalSetByte(dst Operand, value string) error {
	switch dst.Kind {
	case OpReg:
		return c.storeRegSized(dst.Reg, I8, value)
	case OpMem:
		ptr, ptrType, err := c.ptrFromMem(dst.Mem)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store volatile i8 %s, %s %s, align 1\n", value, ptrType, ptr)
		return nil
	case OpSym:
		ptr, err := c.ptrFromSB(dst.Sym)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store volatile i8 %s, ptr %s, align 1\n", value, ptr)
		return nil
	case OpFP:
		return c.storeFPResult(dst.FPOffset, I8, value)
	default:
		return fmt.Errorf("expected Ymb destination, got %s", dst.String())
	}
}

// --- amd64_lower_variable_shift.go ---
type amd64PerLaneVariableShiftSpec struct {
	laneBits   int
	operation  string
	arithmetic bool
	// Shared raw grammar: 66.0F38 opcode and optional VEX generation.
	// W is fixed: W0 for dwords, W1 for words/qwords.
	opcode byte
	vex    bool
}

var amd64PerLaneVariableShiftSpecs = map[string]amd64PerLaneVariableShiftSpec{
	"VPSLLVW": {laneBits: 16, operation: "shl", opcode: 0x12},
	"VPSLLVD": {laneBits: 32, operation: "shl", opcode: 0x47, vex: true},
	"VPSLLVQ": {laneBits: 64, operation: "shl", opcode: 0x47, vex: true},
	"VPSRLVW": {laneBits: 16, operation: "lshr", opcode: 0x10},
	"VPSRLVD": {laneBits: 32, operation: "lshr", opcode: 0x45, vex: true},
	"VPSRLVQ": {laneBits: 64, operation: "lshr", opcode: 0x45, vex: true},
	"VPSRAVW": {laneBits: 16, operation: "ashr", arithmetic: true, opcode: 0x11},
	"VPSRAVD": {laneBits: 32, operation: "ashr", arithmetic: true, opcode: 0x46, vex: true},
	"VPSRAVQ": {laneBits: 64, operation: "ashr", arithmetic: true, opcode: 0x46},
}

// lowerPerLaneVariableShift implements the full Go 1.27 per-lane packed
// variable-shift family. The first Plan 9 source supplies one count per lane.
func (c *amd64Ctx) lowerPerLaneVariableShift(op Op, ins Instr) (ok bool, terminated bool, err error) {
	return c.lowerX86PackedShift(op, ins)
}

func (c *amd64Ctx) emitPerLaneVariableShift(spec amd64PerLaneVariableShiftSpec, lanes int, counts, data string) string {
	typeName := fmt.Sprintf("<%d x i%d>", lanes, spec.laneBits)
	limit := amd64SplatInteger(c, lanes, spec.laneBits, fmt.Sprintf("%d", spec.laneBits))
	inRange := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ult %s %s, %s\n", inRange, typeName, counts, limit)
	fallbackCount := "zeroinitializer"
	if spec.arithmetic {
		fallbackCount = amd64SplatInteger(c, lanes, spec.laneBits, fmt.Sprintf("%d", spec.laneBits-1))
	}
	safeCounts := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %s, %s %s\n", safeCounts, lanes, inRange, typeName, counts, typeName, fallbackCount)
	shifted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s %s %s, %%%s\n", shifted, spec.operation, typeName, data, safeCounts)
	if spec.arithmetic {
		return "%" + shifted
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %%%s, %s zeroinitializer\n", result, lanes, inRange, typeName, shifted, typeName)
	return "%" + result
}

// --- amd64_lower_xlat.go ---
func (c *amd64Ctx) lowerXLAT(op Op, ins Instr) (ok bool, terminated bool, err error) {
	known, err := x86XLATProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	addressType := I64
	if c.goarch == "386" {
		addressType = I32
	}
	base, err := c.evalIntSized(Operand{Kind: OpReg, Reg: BX}, addressType)
	if err != nil {
		return true, false, err
	}
	index, err := c.evalIntSized(Operand{Kind: OpReg, Reg: AL}, I8)
	if err != nil {
		return true, false, err
	}
	wideIndex, address := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext i8 %s to %s\n", wideIndex, index, addressType)
	fmt.Fprintf(c.b, "  %%%s = add %s %s, %%%s\n", address, addressType, base, wideIndex)
	addressValue := "%" + address
	if addressType == I32 {
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", wide, addressValue)
		addressValue = "%" + wide
	}
	pointer := c.ptrFromAddrI64(addressValue)
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load volatile i8, ptr %s, align 1\n", value, pointer)
	return true, false, c.storeRegSized(AL, I8, "%"+value)
}
