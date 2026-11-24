package plan9asm

import (
	"fmt"
	"strings"
)

// --- arm_lower_atomic_swap.go ---
func (c *armCtx) lowerARMAtomicSwap(op, cond string, ins Instr) error {
	if err := armRequireConditionOnlySuffix(ins); err != nil {
		return err
	}
	if len(ins.Args) != 3 ||
		ins.Args[0].Kind != OpReg || !isARMGeneralReg(ins.Args[0].Reg) ||
		ins.Args[1].Kind != OpMem || ins.Args[1].Mem.Base == "" || ins.Args[1].Mem.Off != 0 ||
		ins.Args[1].Mem.OffRaw != "" || ins.Args[1].Mem.Index != "" || ins.Args[1].Mem.Sym != "" ||
		ins.Args[2].Kind != OpReg || !isARMGeneralReg(ins.Args[2].Reg) {
		return fmt.Errorf("arm %s expects source register, (base register), destination register: %q", op, ins.Raw)
	}
	if cond != "" {
		return c.emitConditionalEffect(cond, func() error {
			return c.lowerARMAtomicSwap(op, "", ins)
		})
	}
	source, err := c.loadReg(ins.Args[0].Reg)
	if err != nil {
		return err
	}
	address, _, _, err := c.addrI32(ins.Args[1].Mem, false)
	if err != nil {
		return err
	}
	pointer := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i32 %s to ptr\n", pointer, address)
	if op == "SWPW" {
		old := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = atomicrmw xchg ptr %%%s, i32 %s seq_cst\n", old, pointer, source)
		return c.storeReg(ins.Args[2].Reg, "%"+old)
	}
	narrowed := c.newTmp()
	old := c.newTmp()
	extended := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i32 %s to i8\n", narrowed, source)
	fmt.Fprintf(c.b, "  %%%s = atomicrmw xchg ptr %%%s, i8 %%%s seq_cst\n", old, pointer, narrowed)
	fmt.Fprintf(c.b, "  %%%s = zext i8 %%%s to i32\n", extended, old)
	return c.storeReg(ins.Args[2].Reg, "%"+extended)
}

// --- arm_lower_bitfield.go ---
func (c *armCtx) lowerARMBitfield(op, cond string, ins Instr) error {
	if err := armRequireConditionOnlySuffix(ins); err != nil {
		return err
	}
	if len(ins.Args) != 3 && len(ins.Args) != 4 {
		return fmt.Errorf("arm %s expects width, lsb, dst or width, lsb, src, dst: %q", op, ins.Raw)
	}
	if op == "BFC" && len(ins.Args) != 3 {
		return fmt.Errorf("arm BFC expects width, lsb, dst: %q", ins.Raw)
	}
	if ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" ||
		ins.Args[1].Kind != OpImm || ins.Args[1].ImmRaw != "" {
		return fmt.Errorf("arm %s width and lsb must be resolved integer constants: %q", op, ins.Raw)
	}
	width, lsb := ins.Args[0].Imm, ins.Args[1].Imm
	if width <= 0 || width > 32 || lsb < 0 || lsb >= 32 || width+lsb > 32 {
		return fmt.Errorf("arm %s requires 1 <= width <= 32 and 0 <= lsb with width+lsb <= 32: %q", op, ins.Raw)
	}
	sourceOperand := ins.Args[len(ins.Args)-1]
	if len(ins.Args) == 4 {
		sourceOperand = ins.Args[2]
	}
	destination := ins.Args[len(ins.Args)-1]
	if sourceOperand.Kind != OpReg || !isARMGeneralReg(sourceOperand.Reg) ||
		destination.Kind != OpReg || !isARMGeneralReg(destination.Reg) {
		return fmt.Errorf("arm %s source and destination must be general registers: %q", op, ins.Raw)
	}
	source, err := c.loadReg(sourceOperand.Reg)
	if err != nil {
		return err
	}
	fieldMask := ^uint32(0)
	if width < 32 {
		fieldMask = uint32(1)<<uint(width) - 1
	}
	placedMask := fieldMask << uint(lsb)
	result := ""
	switch op {
	case "BFX", "BFXU":
		shifted := c.newTmp()
		if op == "BFX" {
			left := 32 - width - lsb
			fmt.Fprintf(c.b, "  %%%s = shl i32 %s, %d\n", shifted, source, left)
			extended := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = ashr i32 %%%s, %d\n", extended, shifted, 32-width)
			result = "%" + extended
		} else {
			fmt.Fprintf(c.b, "  %%%s = lshr i32 %s, %d\n", shifted, source, lsb)
			masked := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i32 %%%s, %d\n", masked, shifted, int32(fieldMask))
			result = "%" + masked
		}
	case "BFC":
		cleared := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i32 %s, %d\n", cleared, source, int32(^placedMask))
		result = "%" + cleared
	case "BFI":
		old, loadErr := c.loadReg(destination.Reg)
		if loadErr != nil {
			return loadErr
		}
		cleared := c.newTmp()
		masked := c.newTmp()
		shifted := c.newTmp()
		combined := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i32 %s, %d\n", cleared, old, int32(^placedMask))
		fmt.Fprintf(c.b, "  %%%s = and i32 %s, %d\n", masked, source, int32(fieldMask))
		fmt.Fprintf(c.b, "  %%%s = shl i32 %%%s, %d\n", shifted, masked, lsb)
		fmt.Fprintf(c.b, "  %%%s = or i32 %%%s, %%%s\n", combined, cleared, shifted)
		result = "%" + combined
	default:
		return fmt.Errorf("arm: unsupported bitfield instruction %s", op)
	}
	return c.selectRegWrite(destination.Reg, cond, result)
}

// --- arm_lower_extend_add.go ---
func (c *armCtx) lowerARMExtendAdd(op, cond string, ins Instr) error {
	if err := armRequireConditionOnlySuffix(ins); err != nil {
		return err
	}
	if len(ins.Args) != 2 && len(ins.Args) != 3 {
		return fmt.Errorf("arm %s expects rotated source, dst or rotated source, accumulator, dst: %q", op, ins.Raw)
	}
	sourceOperand := ins.Args[0]
	if sourceOperand.Kind != OpRegShift || sourceOperand.ShiftOp != ShiftRotate || sourceOperand.ShiftReg != "" ||
		!isARMGeneralReg(sourceOperand.Reg) ||
		(sourceOperand.ShiftAmount != 0 && sourceOperand.ShiftAmount != 8 && sourceOperand.ShiftAmount != 16 && sourceOperand.ShiftAmount != 24) {
		return fmt.Errorf("arm %s source must be a general register rotated right by 0, 8, 16, or 24: %q", op, ins.Raw)
	}
	accumulatorOperand := ins.Args[len(ins.Args)-1]
	if len(ins.Args) == 3 {
		accumulatorOperand = ins.Args[1]
	}
	destination := ins.Args[len(ins.Args)-1]
	if accumulatorOperand.Kind != OpReg || !isARMGeneralReg(accumulatorOperand.Reg) ||
		destination.Kind != OpReg || !isARMGeneralReg(destination.Reg) {
		return fmt.Errorf("arm %s accumulator and destination must be general registers: %q", op, ins.Raw)
	}
	rotated, err := c.evalShift(sourceOperand)
	if err != nil {
		return err
	}
	bits := 8
	if op == "XTAH" || op == "XTAHU" {
		bits = 16
	}
	narrowed := c.newTmp()
	extended := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i32 %s to i%d\n", narrowed, rotated, bits)
	if op == "XTAB" || op == "XTAH" {
		fmt.Fprintf(c.b, "  %%%s = sext i%d %%%s to i32\n", extended, bits, narrowed)
	} else {
		fmt.Fprintf(c.b, "  %%%s = zext i%d %%%s to i32\n", extended, bits, narrowed)
	}
	accumulator, err := c.loadReg(accumulatorOperand.Reg)
	if err != nil {
		return err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add i32 %s, %%%s\n", result, accumulator, extended)
	return c.selectRegWrite(destination.Reg, cond, "%"+result)
}

// --- arm_lower_parallel_byte.go ---
// lowerARMUnsignedParallelByteAddSub implements the complete three-register
// UADD8/USUB8 result family decoded by Go's vendored ARM instruction table.
// The four packed byte lanes deliberately wrap independently, matching the
// architectural data result rather than carrying between adjacent lanes.
func (c *armCtx) lowerARMUnsignedParallelByteAddSub(op, cond string, setFlags bool, ins Instr) error {
	if err := armRequireConditionOnlySuffix(ins); err != nil {
		return err
	}
	if setFlags {
		return fmt.Errorf("arm %s does not accept the .S suffix: %q", op, ins.Raw)
	}
	if len(ins.Args) != 3 {
		return fmt.Errorf("arm %s expects Rm, Rn, Rd: %q", op, ins.Raw)
	}
	for _, operand := range ins.Args {
		if operand.Kind != OpReg || !isARMParallelDataReg(operand.Reg) {
			return fmt.Errorf("arm %s accepts only R0-R14 registers: %q", op, ins.Raw)
		}
	}
	rm, err := c.loadReg(ins.Args[0].Reg)
	if err != nil {
		return err
	}
	rn, err := c.loadReg(ins.Args[1].Reg)
	if err != nil {
		return err
	}
	rmBytes := c.newTmp()
	rnBytes := c.newTmp()
	resultBytes := c.newTmp()
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast i32 %s to <4 x i8>\n", rmBytes, rm)
	fmt.Fprintf(c.b, "  %%%s = bitcast i32 %s to <4 x i8>\n", rnBytes, rn)
	operation := "add"
	if op == "USUB8" {
		operation = "sub"
	}
	fmt.Fprintf(c.b, "  %%%s = %s <4 x i8> %%%s, %%%s\n", resultBytes, operation, rnBytes, rmBytes)
	fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i8> %%%s to i32\n", result, resultBytes)
	return c.selectRegWrite(ins.Args[2].Reg, cond, "%"+result)
}

func isARMParallelDataReg(reg Reg) bool {
	s := strings.ToUpper(strings.TrimSpace(string(reg)))
	return isARMGeneralReg(reg) && s != "PC" && s != "R15"
}

// --- arm_lower_prefetch.go ---
func (c *armCtx) lowerPreload(op, cond string, ins Instr) (ok bool, terminated bool, err error) {
	switch op {
	case "PLD":
	default:
		return false, false, nil
	}
	if err := armRequireConditionOnlySuffix(ins); err != nil {
		return true, false, err
	}
	if len(ins.Args) != 1 || ins.Args[0].Kind != OpMem {
		return true, false, fmt.Errorf("arm PLD expects one register-relative memory operand: %q", ins.Raw)
	}
	mem := ins.Args[0].Mem
	if !isARMGeneralReg(mem.Base) || mem.Index != "" || mem.Sym != "" || mem.Off < -4095 || mem.Off > 4095 {
		return true, false, fmt.Errorf("arm PLD operand is absent from Go 1.27's C_SOREG optab row: %q", ins.Raw)
	}
	if cond != "" && !strings.EqualFold(cond, "AL") {
		err := c.emitConditionalEffect(cond, func() error {
			_, _, innerErr := c.lowerPreload(op, "", ins)
			return innerErr
		})
		return true, false, err
	}
	addr, _, _, err := c.addrI32(mem, false)
	if err != nil {
		return true, false, err
	}
	ptr := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i32 %s to ptr\n", ptr, addr)
	fmt.Fprintf(c.b, "  call void @llvm.prefetch.p0(ptr %%%s, i32 0, i32 3, i32 1)\n", ptr)
	return true, false, nil
}

// --- arm_lower_reverse_bits.go ---
func (c *armCtx) lowerARMReverseBits(op, cond string, ins Instr) error {
	if err := armRequireConditionOnlySuffix(ins); err != nil {
		return err
	}
	if len(ins.Args) != 2 ||
		ins.Args[0].Kind != OpReg || !isARMGeneralReg(ins.Args[0].Reg) ||
		ins.Args[1].Kind != OpReg || !isARMGeneralReg(ins.Args[1].Reg) {
		return fmt.Errorf("arm %s expects two general registers: %q", op, ins.Raw)
	}
	source, err := c.loadReg(ins.Args[0].Reg)
	if err != nil {
		return err
	}
	result := ""
	switch op {
	case "REV":
		reversed := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.bswap.i32(i32 %s)\n", reversed, source)
		result = "%" + reversed
	case "RBIT":
		reversed := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.bitreverse.i32(i32 %s)\n", reversed, source)
		result = "%" + reversed
	case "REV16":
		low := c.newTmp()
		high := c.newTmp()
		lowShifted := c.newTmp()
		highShifted := c.newTmp()
		combined := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i32 %s, 16711935\n", low, source)
		fmt.Fprintf(c.b, "  %%%s = and i32 %s, -16711936\n", high, source)
		fmt.Fprintf(c.b, "  %%%s = shl i32 %%%s, 8\n", lowShifted, low)
		fmt.Fprintf(c.b, "  %%%s = lshr i32 %%%s, 8\n", highShifted, high)
		fmt.Fprintf(c.b, "  %%%s = or i32 %%%s, %%%s\n", combined, lowShifted, highShifted)
		result = "%" + combined
	case "REVSH":
		narrowed := c.newTmp()
		reversed := c.newTmp()
		extended := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i32 %s to i16\n", narrowed, source)
		fmt.Fprintf(c.b, "  %%%s = call i16 @llvm.bswap.i16(i16 %%%s)\n", reversed, narrowed)
		fmt.Fprintf(c.b, "  %%%s = sext i16 %%%s to i32\n", extended, reversed)
		result = "%" + extended
	default:
		return fmt.Errorf("arm: unsupported reverse instruction %s", op)
	}
	return c.selectRegWrite(ins.Args[1].Reg, cond, result)
}

// --- arm_lower_word_extend.go ---
type armRawSXTB struct {
	condition   string
	rotation    int
	source      int
	destination int
}

func armConditionName(code int) string {
	return [...]string{"EQ", "NE", "CS", "CC", "MI", "PL", "VS", "VC", "HI", "LS", "GE", "LT", "GT", "LE", "AL"}[code]
}

// decodeARMRawSXTB covers every A32 SXTB Rd, Rm{, ROR #8|16|24}
// encoding: all four rotations, every register field, and the 15 executable
// conditions. Condition 0xf belongs to the unconditional instruction space.
func decodeARMRawSXTB(word uint32) (armRawSXTB, bool) {
	if word&0x0fff03f0 != 0x06af0070 || word>>28 == 0xf {
		return armRawSXTB{}, false
	}
	return armRawSXTB{
		condition:   armConditionName(int(word >> 28)),
		rotation:    int(word>>10&3) * 8,
		source:      int(word) & 15,
		destination: int(word>>12) & 15,
	}, true
}

func (c *armCtx) lowerRawSXTB(form armRawSXTB) error {
	if form.source == 15 || form.destination == 15 {
		return fmt.Errorf("arm SXTB cannot safely use PC")
	}
	source, err := c.loadReg(Reg(fmt.Sprintf("R%d", form.source)))
	if err != nil {
		return err
	}
	if form.rotation != 0 {
		rotated := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.fshr.i32(i32 %s, i32 %s, i32 %d)\n", rotated, source, source, form.rotation)
		source = "%" + rotated
	}
	narrowed := c.newTmp()
	extended := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i32 %s to i8\n", narrowed, source)
	fmt.Fprintf(c.b, "  %%%s = sext i8 %%%s to i32\n", extended, narrowed)
	return c.selectRegWrite(Reg(fmt.Sprintf("R%d", form.destination)), form.condition, "%"+extended)
}

// --- arm_lower_word_neon_bit_clear_immediate.go ---
type armRawNEONBitClearImmediate struct {
	quad        bool
	elementBits int
	shift       int
	destination int
	imm8        int
}

// decodeARMRawNEONBitClearImmediate covers all A32 VBIC modified-immediate
// forms accepted by LLVM 22: i16 byte positions 0/8 and i32 byte positions
// 0/8/16/24, with every imm8 value and D/Q destination register.
func decodeARMRawNEONBitClearImmediate(word uint32) (armRawNEONBitClearImmediate, bool) {
	const variable = uint32(0x01000000 | 0x00400000 | 0x00070000 |
		0x0000f000 | 0x00000f00 | 0x00000040 | 0x0000000f)
	if word&^variable != 0xf2800030 {
		return armRawNEONBitClearImmediate{}, false
	}
	cmode := int(word >> 8 & 15)
	elementBits := 32
	shift := 0
	switch cmode {
	case 1, 3, 5, 7:
		shift = (cmode - 1) / 2 * 8
	case 9, 11:
		elementBits = 16
		shift = (cmode - 9) / 2 * 8
	default:
		return armRawNEONBitClearImmediate{}, false
	}
	quad := word>>6&1 != 0
	destination := int(word>>12)&15 | int(word>>22&1)*16
	if quad && destination&1 != 0 {
		return armRawNEONBitClearImmediate{}, false
	}
	return armRawNEONBitClearImmediate{
		quad:        quad,
		elementBits: elementBits,
		shift:       shift,
		destination: destination,
		imm8:        int(word>>24&1)*128 | int(word>>16&7)*16 | int(word&15),
	}, true
}

func (c *armCtx) lowerRawNEONBitClearImmediate(form armRawNEONBitClearImmediate) error {
	elementType := fmt.Sprintf("i%d", form.elementBits)
	destination, lanes, err := c.loadARMRawNEONVector(
		form.destination, form.elementBits, form.quad, elementType,
	)
	if err != nil {
		return err
	}
	widthMask := uint64(1)<<form.elementBits - 1
	clearMask := widthMask &^ (uint64(form.imm8) << form.shift)
	constants := make([]string, lanes)
	for index := range constants {
		constants[index] = fmt.Sprintf("%s %d", elementType, clearMask)
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and <%d x %s> %s, <%s>\n",
		result, lanes, elementType, destination, strings.Join(constants, ", "))
	return c.storeARMRawNEONVector(
		form.destination, form.elementBits, form.quad, elementType, "%"+result,
	)
}

// --- arm_lower_word_neon_convert_float32.go ---
type armRawNEONConvertFloat32 struct {
	toFloat     bool
	unsigned    bool
	quad        bool
	destination int
	source      int
}

// decodeARMRawNEONConvertFloat32 covers all eight classic A32 NEON VCVT
// integer/float32 forms: signed or unsigned, both directions, and D or Q
// vectors. Fixed-point, FP16, and ARMv8 directed-rounding encodings are
// separate architectural families.
func decodeARMRawNEONConvertFloat32(word uint32) (armRawNEONConvertFloat32, bool) {
	if word&0xffbf0010 != 0xf3bb0000 {
		return armRawNEONConvertFloat32{}, false
	}
	op := int(word>>7) & 31
	if op < 0b01100 || op > 0b01111 {
		return armRawNEONConvertFloat32{}, false
	}
	quad := word>>6&1 != 0
	destination := int(word>>12)&15 | int(word>>22&1)*16
	source := int(word)&15 | int(word>>5&1)*16
	if quad && (destination&1 != 0 || source&1 != 0) {
		return armRawNEONConvertFloat32{}, false
	}
	return armRawNEONConvertFloat32{
		toFloat:     op == 0b01100 || op == 0b01101,
		unsigned:    op == 0b01101 || op == 0b01111,
		quad:        quad,
		destination: destination,
		source:      source,
	}, true
}

func (c *armCtx) lowerRawNEONConvertFloat32(form armRawNEONConvertFloat32) error {
	sourceType := "i32"
	destinationType := "float"
	wordKind := "s32"
	if form.unsigned {
		wordKind = "u32"
	}
	sourceKind, destinationKind := wordKind, "f32"
	if !form.toFloat {
		sourceType = "float"
		destinationType = "i32"
		sourceKind, destinationKind = "f32", wordKind
	}
	source, lanes, err := c.loadARMRawNEONVector(form.source, 32, form.quad, sourceType)
	if err != nil {
		return err
	}
	result := c.newTmp()
	// Advanced SIMD VCVT uses standard rounding/denormal controls, not the
	// scalar VFP operation's ambient FPSCR mode. Its cumulative exceptions
	// still update native FPSCR, even for dead outputs. Keep the whole D/Q
	// operation and order it with the existing VMRS/VMSR memory barriers.
	// LLVM22's w constraint selects D0..31 / Q0..15 for these vector widths.
	operation := "vcvt." + destinationKind + "." + sourceKind + " $0, $1"
	fmt.Fprintf(c.b, "  %%%s = call <%d x %s> asm sideeffect %q, %q(<%d x %s> %s)\n",
		result, lanes, destinationType, operation, "=w,w,~{memory}", lanes, sourceType, source)
	return c.storeARMRawNEONVector(form.destination, 32, form.quad, destinationType, "%"+result)
}

// --- arm_lower_word_neon_extract.go ---
type armRawNEONExtract struct {
	quad        bool
	destination int
	lhs         int
	rhs         int
	offset      int
}

// decodeARMRawNEONExtract covers A32 VEXT register forms. Element spellings
// of .8/.16/.32/.64 share the same byte-extract encoding; only the byte
// offset matters. D forms permit offsets 0..7 and Q forms 0..15.
func decodeARMRawNEONExtract(word uint32) (armRawNEONExtract, bool) {
	const variable = uint32(0x00400000 | 0x000f0000 | 0x0000f000 |
		0x00000f00 | 0x000000e0 | 0x0000000f)
	if word&^variable != 0xf2b00000 {
		return armRawNEONExtract{}, false
	}
	quad := word>>6&1 != 0
	destination := int(word>>12)&15 | int(word>>22&1)*16
	lhs := int(word>>16)&15 | int(word>>7&1)*16
	rhs := int(word)&15 | int(word>>5&1)*16
	offset := int(word >> 8 & 15)
	if !quad && offset >= 8 ||
		quad && (destination&1 != 0 || lhs&1 != 0 || rhs&1 != 0) {
		return armRawNEONExtract{}, false
	}
	return armRawNEONExtract{
		quad:        quad,
		destination: destination,
		lhs:         lhs,
		rhs:         rhs,
		offset:      offset,
	}, true
}

func (c *armCtx) lowerRawNEONExtract(form armRawNEONExtract) error {
	lhs, lanes, err := c.loadARMRawNEONVector(form.lhs, 8, form.quad, "i8")
	if err != nil {
		return err
	}
	rhs, _, err := c.loadARMRawNEONVector(form.rhs, 8, form.quad, "i8")
	if err != nil {
		return err
	}
	indices := make([]string, lanes)
	for index := range indices {
		indices[index] = fmt.Sprintf("i32 %d", form.offset+index)
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i8> %s, <%d x i8> %s, <%d x i32> <%s>\n",
		result, lanes, lhs, lanes, rhs, lanes, strings.Join(indices, ", "))
	return c.storeARMRawNEONVector(form.destination, 8, form.quad, "i8", "%"+result)
}

// --- arm_lower_word_neon_helpers.go ---
// loadARMRawNEONVector reads a D register or the consecutive D-register pair
// that encodes a Q register and views the bits as an LLVM vector.
func (c *armCtx) loadARMRawNEONVector(first, elementBits int, quad bool, elementType string) (string, int, error) {
	lanes := 64 / elementBits
	low, err := c.loadFReg(armRawVFPBackingReg(first, 64))
	if err != nil {
		return "", 0, err
	}
	bits := low
	totalBits := 64
	if quad {
		lanes *= 2
		totalBits = 128
		high, err := c.loadFReg(armRawVFPBackingReg(first+1, 64))
		if err != nil {
			return "", 0, err
		}
		lowWide := c.newTmp()
		highWide := c.newTmp()
		highShifted := c.newTmp()
		joined := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i64 %s to i128\n", lowWide, low)
		fmt.Fprintf(c.b, "  %%%s = zext i64 %s to i128\n", highWide, high)
		fmt.Fprintf(c.b, "  %%%s = shl i128 %%%s, 64\n", highShifted, highWide)
		fmt.Fprintf(c.b, "  %%%s = or i128 %%%s, %%%s\n", joined, lowWide, highShifted)
		bits = "%" + joined
	}
	vector := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast i%d %s to <%d x %s>\n", vector, totalBits, bits, lanes, elementType)
	return "%" + vector, lanes, nil
}

func (c *armCtx) storeARMRawNEONVector(first, elementBits int, quad bool, elementType, value string) error {
	lanes := 64 / elementBits
	totalBits := 64
	if quad {
		lanes *= 2
		totalBits = 128
	}
	bits := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x %s> %s to i%d\n", bits, lanes, elementType, value, totalBits)
	if !quad {
		return c.storeFReg(armRawVFPBackingReg(first, 64), "%"+bits)
	}
	low := c.newTmp()
	highWide := c.newTmp()
	high := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i128 %%%s to i64\n", low, bits)
	fmt.Fprintf(c.b, "  %%%s = lshr i128 %%%s, 64\n", highWide, bits)
	fmt.Fprintf(c.b, "  %%%s = trunc i128 %%%s to i64\n", high, highWide)
	if err := c.storeFReg(armRawVFPBackingReg(first, 64), "%"+low); err != nil {
		return err
	}
	return c.storeFReg(armRawVFPBackingReg(first+1, 64), "%"+high)
}

// --- arm_lower_word_neon_move_long.go ---
type armRawNEONMoveLong struct {
	unsigned    bool
	elementBits int
	destination int
	source      int
}

// decodeARMRawNEONMoveLong covers the complete A32 VMOVL family: signed and
// unsigned widening from 8-, 16-, or 32-bit lanes in a D register to a Q
// register.
func decodeARMRawNEONMoveLong(word uint32) (armRawNEONMoveLong, bool) {
	if word&0xfe800fd0 != 0xf2800a10 {
		return armRawNEONMoveLong{}, false
	}
	var elementBits int
	switch word >> 16 & 0x3f {
	case 0b001000:
		elementBits = 8
	case 0b010000:
		elementBits = 16
	case 0b100000:
		elementBits = 32
	default:
		return armRawNEONMoveLong{}, false
	}
	destination := int(word>>12)&15 | int(word>>22&1)*16
	if destination&1 != 0 {
		return armRawNEONMoveLong{}, false
	}
	return armRawNEONMoveLong{
		unsigned:    word>>24&1 != 0,
		elementBits: elementBits,
		destination: destination,
		source:      int(word)&15 | int(word>>5&1)*16,
	}, true
}

func (c *armCtx) lowerRawNEONMoveLong(form armRawNEONMoveLong) error {
	sourceBits, err := c.loadFReg(armRawVFPBackingReg(form.source, 64))
	if err != nil {
		return err
	}
	lanes := 64 / form.elementBits
	wideBits := form.elementBits * 2
	source := c.newTmp()
	result := c.newTmp()
	resultBits := c.newTmp()
	extend := "sext"
	if form.unsigned {
		extend = "zext"
	}
	fmt.Fprintf(c.b, "  %%%s = bitcast i64 %s to <%d x i%d>\n", source, sourceBits, lanes, form.elementBits)
	fmt.Fprintf(c.b, "  %%%s = %s <%d x i%d> %%%s to <%d x i%d>\n", result, extend, lanes, form.elementBits, source, lanes, wideBits)
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %%%s to i128\n", resultBits, lanes, wideBits, result)
	low := c.newTmp()
	highWide := c.newTmp()
	high := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i128 %%%s to i64\n", low, resultBits)
	fmt.Fprintf(c.b, "  %%%s = lshr i128 %%%s, 64\n", highWide, resultBits)
	fmt.Fprintf(c.b, "  %%%s = trunc i128 %%%s to i64\n", high, highWide)
	if err := c.storeFReg(armRawVFPBackingReg(form.destination, 64), "%"+low); err != nil {
		return err
	}
	return c.storeFReg(armRawVFPBackingReg(form.destination+1, 64), "%"+high)
}

// --- arm_lower_word_neon_move_narrow.go ---
type armRawNEONMoveNarrow struct {
	sourceBits  int
	destination int
	source      int
}

// decodeARMRawNEONMoveNarrow covers every non-saturating A32 VMOVN register
// form: 16-to-8, 32-to-16, and 64-to-32 narrowing from Q to D.
func decodeARMRawNEONMoveNarrow(word uint32) (armRawNEONMoveNarrow, bool) {
	const variable = uint32(0x004cf02f)
	if word&^variable != 0xf3b20200 {
		return armRawNEONMoveNarrow{}, false
	}
	size := int(word >> 18 & 3)
	if size == 3 {
		return armRawNEONMoveNarrow{}, false
	}
	source := int(word)&15 | int(word>>5&1)*16
	if source&1 != 0 {
		return armRawNEONMoveNarrow{}, false
	}
	return armRawNEONMoveNarrow{
		sourceBits:  16 << size,
		destination: int(word>>12)&15 | int(word>>22&1)*16,
		source:      source,
	}, true
}

func (c *armCtx) lowerRawNEONMoveNarrow(form armRawNEONMoveNarrow) error {
	sourceType := fmt.Sprintf("i%d", form.sourceBits)
	resultBits := form.sourceBits / 2
	resultType := fmt.Sprintf("i%d", resultBits)
	source, lanes, err := c.loadARMRawNEONVector(
		form.source, form.sourceBits, true, sourceType,
	)
	if err != nil {
		return err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc <%d x %s> %s to <%d x %s>\n",
		result, lanes, sourceType, source, lanes, resultType)
	return c.storeARMRawNEONVector(
		form.destination, resultBits, false, resultType, "%"+result,
	)
}

// --- arm_lower_word_neon_multiply_long_vector.go ---
type armRawNEONMultiplyLongVector struct {
	kind        string
	unsigned    bool
	elementBits int
	destination int
	lhs         int
	rhs         int
}

// decodeARMRawNEONMultiplyLongVector covers every signed and unsigned A32
// VMULL/VMLAL/VMLSL register form, for 8-, 16-, and 32-bit D-register lanes.
func decodeARMRawNEONMultiplyLongVector(word uint32) (armRawNEONMultiplyLongVector, bool) {
	kind := ""
	switch word & 0xfe800f50 {
	case 0xf2800c00:
		kind = "mul"
	case 0xf2800800:
		kind = "mla"
	case 0xf2800a00:
		kind = "mls"
	default:
		return armRawNEONMultiplyLongVector{}, false
	}
	size := int(word >> 20 & 3)
	if size == 3 {
		return armRawNEONMultiplyLongVector{}, false
	}
	destination := int(word>>12)&15 | int(word>>22&1)*16
	if destination&1 != 0 {
		return armRawNEONMultiplyLongVector{}, false
	}
	return armRawNEONMultiplyLongVector{
		kind:        kind,
		unsigned:    word>>24&1 != 0,
		elementBits: 8 << size,
		destination: destination,
		lhs:         int(word>>16)&15 | int(word>>7&1)*16,
		rhs:         int(word)&15 | int(word>>5&1)*16,
	}, true
}

func (c *armCtx) lowerRawNEONMultiplyLongVector(form armRawNEONMultiplyLongVector) error {
	narrowType := fmt.Sprintf("i%d", form.elementBits)
	wideType := fmt.Sprintf("i%d", form.elementBits*2)
	lhs, lanes, err := c.loadARMRawNEONVector(form.lhs, form.elementBits, false, narrowType)
	if err != nil {
		return err
	}
	rhs, _, err := c.loadARMRawNEONVector(form.rhs, form.elementBits, false, narrowType)
	if err != nil {
		return err
	}
	extend := "sext"
	if form.unsigned {
		extend = "zext"
	}
	lhsWide := c.newTmp()
	rhsWide := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s <%d x %s> %s to <%d x %s>\n",
		lhsWide, extend, lanes, narrowType, lhs, lanes, wideType)
	fmt.Fprintf(c.b, "  %%%s = %s <%d x %s> %s to <%d x %s>\n",
		rhsWide, extend, lanes, narrowType, rhs, lanes, wideType)
	return c.lowerARMRawNEONWideningProduct(
		form.kind, form.elementBits, form.destination, "%"+lhsWide, "%"+rhsWide,
	)
}

// --- arm_lower_word_neon_reverse.go ---
type armRawNEONReverse struct {
	blockBits   int
	elementBits int
	quad        bool
	destination int
	source      int
}

// decodeARMRawNEONReverse covers A32 VREV16.8, VREV32.8/.16, and
// VREV64.8/.16/.32 for both D and Q registers. Invalid equal-width and
// reserved register encodings are rejected.
func decodeARMRawNEONReverse(word uint32) (armRawNEONReverse, bool) {
	const variable = uint32(0x00400000 | 0x000c0000 | 0x0000f000 |
		0x00000180 | 0x00000060 | 0x0000000f)
	if word&^variable != 0xf3b00000 {
		return armRawNEONReverse{}, false
	}
	blockBits := 64
	switch word >> 7 & 3 {
	case 1:
		blockBits = 32
	case 2:
		blockBits = 16
	case 3:
		return armRawNEONReverse{}, false
	}
	elementBits := 8 << (word >> 18 & 3)
	if elementBits >= blockBits {
		return armRawNEONReverse{}, false
	}
	quad := word>>6&1 != 0
	destination := int(word>>12)&15 | int(word>>22&1)*16
	source := int(word)&15 | int(word>>5&1)*16
	if quad && (destination&1 != 0 || source&1 != 0) {
		return armRawNEONReverse{}, false
	}
	return armRawNEONReverse{
		blockBits:   blockBits,
		elementBits: elementBits,
		quad:        quad,
		destination: destination,
		source:      source,
	}, true
}

func (c *armCtx) lowerRawNEONReverse(form armRawNEONReverse) error {
	elementType := fmt.Sprintf("i%d", form.elementBits)
	source, lanes, err := c.loadARMRawNEONVector(
		form.source, form.elementBits, form.quad, elementType,
	)
	if err != nil {
		return err
	}
	blockLanes := form.blockBits / form.elementBits
	indices := make([]string, lanes)
	for lane := range indices {
		blockStart := lane / blockLanes * blockLanes
		index := blockStart + blockLanes - 1 - lane%blockLanes
		indices[lane] = fmt.Sprintf("i32 %d", index)
	}
	result := c.newTmp()
	fmt.Fprintf(c.b,
		"  %%%s = shufflevector <%d x %s> %s, <%d x %s> poison, <%d x i32> <%s>\n",
		result, lanes, elementType, source, lanes, elementType, lanes, strings.Join(indices, ", "),
	)
	return c.storeARMRawNEONVector(
		form.destination, form.elementBits, form.quad, elementType, "%"+result,
	)
}

// --- arm_lower_word_neon_shift_immediate.go ---
type armRawNEONShiftImmediate struct {
	elementBits int
	shift       int
	quad        bool
	destination int
	source      int
}

// Classic A32 VSHL immediate has one D/Q encoding for each 8-, 16-, 32-,
// and 64-bit element width. The highest set bit of imm7 selects the width;
// the remaining bits are the immediate shift. Signed and unsigned spellings
// have identical left-shift semantics and the same encoding.
func decodeARMRawNEONShiftImmediate(word uint32) (armRawNEONShiftImmediate, bool) {
	const variable = uint32(0x007ff0ef)
	const base = uint32(0xf2800510)
	if word&^variable != base {
		return armRawNEONShiftImmediate{}, false
	}
	imm7 := int(word>>16&0x3f) | int(word>>7&1)<<6
	if imm7 < 8 {
		return armRawNEONShiftImmediate{}, false
	}
	elementBits := 8
	for elementBits*2 <= imm7 {
		elementBits *= 2
	}
	quad := word>>6&1 != 0
	destination := int(word>>12)&15 | int(word>>22&1)*16
	source := int(word)&15 | int(word>>5&1)*16
	if quad && (destination&1 != 0 || source&1 != 0) {
		return armRawNEONShiftImmediate{}, false
	}
	return armRawNEONShiftImmediate{
		elementBits: elementBits,
		shift:       imm7 - elementBits,
		quad:        quad,
		destination: destination,
		source:      source,
	}, true
}

func (c *armCtx) lowerRawNEONShiftImmediate(form armRawNEONShiftImmediate) error {
	elementType := fmt.Sprintf("i%d", form.elementBits)
	source, lanes, err := c.loadARMRawNEONVector(
		form.source, form.elementBits, form.quad, elementType,
	)
	if err != nil {
		return err
	}
	counts := make([]string, lanes)
	for index := range counts {
		counts[index] = fmt.Sprintf("%s %d", elementType, form.shift)
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shl <%d x %s> %s, <%s>\n",
		result, lanes, elementType, source, strings.Join(counts, ", "))
	return c.storeARMRawNEONVector(
		form.destination, form.elementBits, form.quad, elementType, "%"+result,
	)
}

// --- arm_lower_word_neon_shift_right_narrow.go ---
type armRawNEONShiftRightNarrow struct {
	sourceBits  int
	shift       int
	destination int
	source      int
}

// decodeARMRawNEONShiftRightNarrow covers all non-saturating A32 VSHRN
// immediate forms: i16-to-i8, i32-to-i16, and i64-to-i32, with shifts 1
// through the destination element width and all D/Q register fields.
func decodeARMRawNEONShiftRightNarrow(word uint32) (armRawNEONShiftRightNarrow, bool) {
	const variable = uint32(0x007ff02f)
	if word&^variable != 0xf2800810 {
		return armRawNEONShiftRightNarrow{}, false
	}
	imm6 := int(word >> 16 & 0x3f)
	if imm6 < 8 {
		return armRawNEONShiftRightNarrow{}, false
	}
	resultBits := 8
	for resultBits*2 <= imm6 {
		resultBits *= 2
	}
	if resultBits > 32 {
		return armRawNEONShiftRightNarrow{}, false
	}
	sourceBits := resultBits * 2
	shift := sourceBits - imm6
	if shift < 1 || shift > resultBits {
		return armRawNEONShiftRightNarrow{}, false
	}
	source := int(word)&15 | int(word>>5&1)*16
	if source&1 != 0 {
		return armRawNEONShiftRightNarrow{}, false
	}
	return armRawNEONShiftRightNarrow{
		sourceBits:  sourceBits,
		shift:       shift,
		destination: int(word>>12)&15 | int(word>>22&1)*16,
		source:      source,
	}, true
}

func (c *armCtx) lowerRawNEONShiftRightNarrow(form armRawNEONShiftRightNarrow) error {
	sourceType := fmt.Sprintf("i%d", form.sourceBits)
	resultBits := form.sourceBits / 2
	resultType := fmt.Sprintf("i%d", resultBits)
	source, lanes, err := c.loadARMRawNEONVector(
		form.source, form.sourceBits, true, sourceType,
	)
	if err != nil {
		return err
	}
	counts := make([]string, lanes)
	for index := range counts {
		counts[index] = fmt.Sprintf("%s %d", sourceType, form.shift)
	}
	shifted := c.newTmp()
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = lshr <%d x %s> %s, <%s>\n",
		shifted, lanes, sourceType, source, strings.Join(counts, ", "))
	fmt.Fprintf(c.b, "  %%%s = trunc <%d x %s> %%%s to <%d x %s>\n",
		result, lanes, sourceType, shifted, lanes, resultType)
	return c.storeARMRawNEONVector(
		form.destination, resultBits, false, resultType, "%"+result,
	)
}

// --- arm_lower_word_neon_structure_one_lane.go ---
// decodeARMRawNEONStructureOneLane covers A32 VLD1/VST1 one-lane transfers
// for 8-, 16-, and 32-bit elements, including all lane, register, alignment,
// and post-index fields. It shares the typed memory lowerer with VLD4/VST4.
func decodeARMRawNEONStructureOneLane(word uint32) (armRawNEONStructureLane, bool) {
	if word&0xff900000 != 0xf4800000 {
		return armRawNEONStructureLane{}, false
	}
	form := armRawNEONStructureLane{
		load:   word>>21&1 != 0,
		first:  int(word>>12)&15 | int(word>>22&1)*16,
		stride: 1,
		base:   int(word>>16) & 15,
		offset: int(word) & 15,
	}
	switch word >> 8 & 15 {
	case 0:
		if word>>4&1 != 0 {
			return armRawNEONStructureLane{}, false
		}
		form.elementBits = 8
		form.lane = int(word >> 5 & 7)
	case 4:
		if word>>5&1 != 0 {
			return armRawNEONStructureLane{}, false
		}
		form.elementBits = 16
		form.lane = int(word >> 6 & 3)
		if word>>4&1 != 0 {
			form.alignment = 2
		}
	case 8:
		if word>>6&1 != 0 {
			return armRawNEONStructureLane{}, false
		}
		form.elementBits = 32
		form.lane = int(word >> 7 & 1)
		switch word >> 4 & 3 {
		case 0:
		case 3:
			form.alignment = 4
		default:
			return armRawNEONStructureLane{}, false
		}
	default:
		return armRawNEONStructureLane{}, false
	}
	return form, true
}

// --- arm_lower_word_neon_transpose.go ---
type armRawNEONTranspose struct {
	quad        bool
	elementBits int
	first       int
	second      int
}

// decodeARMRawNEONTranspose covers A32 VTRN.8/.16/.32 in D and Q registers.
// Both operand fields are read and written by the instruction.
func decodeARMRawNEONTranspose(word uint32) (armRawNEONTranspose, bool) {
	const variable = uint32(0x004cf06f)
	if word&^variable != 0xf3b20080 {
		return armRawNEONTranspose{}, false
	}
	size := int(word >> 18 & 3)
	if size == 3 {
		return armRawNEONTranspose{}, false
	}
	quad := word>>6&1 != 0
	first := int(word>>12)&15 | int(word>>22&1)*16
	second := int(word)&15 | int(word>>5&1)*16
	if quad && (first&1 != 0 || second&1 != 0) {
		return armRawNEONTranspose{}, false
	}
	return armRawNEONTranspose{
		quad:        quad,
		elementBits: 8 << size,
		first:       first,
		second:      second,
	}, true
}

func (c *armCtx) lowerRawNEONTranspose(form armRawNEONTranspose) error {
	elementType := fmt.Sprintf("i%d", form.elementBits)
	first, lanes, err := c.loadARMRawNEONVector(
		form.first, form.elementBits, form.quad, elementType,
	)
	if err != nil {
		return err
	}
	second, _, err := c.loadARMRawNEONVector(
		form.second, form.elementBits, form.quad, elementType,
	)
	if err != nil {
		return err
	}
	firstIndices := make([]string, lanes)
	secondIndices := make([]string, lanes)
	for pair := 0; pair < lanes/2; pair++ {
		firstIndices[2*pair] = fmt.Sprintf("i32 %d", 2*pair)
		firstIndices[2*pair+1] = fmt.Sprintf("i32 %d", lanes+2*pair)
		secondIndices[2*pair] = fmt.Sprintf("i32 %d", 2*pair+1)
		secondIndices[2*pair+1] = fmt.Sprintf("i32 %d", lanes+2*pair+1)
	}
	firstResult := c.newTmp()
	secondResult := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x %s> %s, <%d x %s> %s, <%d x i32> <%s>\n",
		firstResult, lanes, elementType, first, lanes, elementType, second,
		lanes, strings.Join(firstIndices, ", "))
	fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x %s> %s, <%d x %s> %s, <%d x i32> <%s>\n",
		secondResult, lanes, elementType, first, lanes, elementType, second,
		lanes, strings.Join(secondIndices, ", "))
	if err := c.storeARMRawNEONVector(
		form.first, form.elementBits, form.quad, elementType, "%"+firstResult,
	); err != nil {
		return err
	}
	return c.storeARMRawNEONVector(
		form.second, form.elementBits, form.quad, elementType, "%"+secondResult,
	)
}

// --- arm_lower_word_vfp_move.go ---
type armRawVFPMove struct {
	condition   string
	bits        int
	destination int
	source      int
}

// decodeARMRawVFPMove covers the complete A32 scalar VMOV (register) family:
// every condition and all S0..S31 and D0..D31 source/destination fields. Raw
// single-register moves need a dedicated path because x/arch's Go syntax uses
// F<n> for even S registers and S<n> for odd ones, while source-level Go F
// registers represent a different register view.
func decodeARMRawVFPMove(word uint32) (armRawVFPMove, bool) {
	const mask = uint32(0x0fbf0ed0)
	const base = uint32(0x0eb00a40)
	if word&mask != base {
		return armRawVFPMove{}, false
	}
	condition, ok := armRawCondition(word >> 28)
	if !ok {
		return armRawVFPMove{}, false
	}
	bits := 32
	destination := int(word>>12) & 15
	source := int(word) & 15
	if word>>8&1 != 0 {
		bits = 64
		destination += int(word>>22&1) * 16
		source += int(word>>5&1) * 16
	} else {
		destination = destination*2 + int(word>>22&1)
		source = source*2 + int(word>>5&1)
	}
	return armRawVFPMove{
		condition:   condition,
		bits:        bits,
		destination: destination,
		source:      source,
	}, true
}

func (c *armCtx) lowerRawVFPMove(form armRawVFPMove) error {
	if form.condition != "" && form.condition != "AL" {
		condition := form.condition
		form.condition = "AL"
		return c.emitConditionalEffect(condition, func() error {
			return c.lowerRawVFPMove(form)
		})
	}
	if form.bits == 32 {
		value, err := c.loadARMRawSingleBits(form.source)
		if err != nil {
			return err
		}
		return c.storeARMRawSingleBits(form.destination, value, "")
	}
	value, err := c.loadFReg(armRawVFPBackingReg(form.source, 64))
	if err != nil {
		return err
	}
	return c.storeFReg(armRawVFPBackingReg(form.destination, 64), value)
}

// --- arm_lower_word_vfp_status.go ---
type armRawVFPStatusTransfer struct {
	toCore    bool
	toFlags   bool
	condition string
	core      int
}

// decodeARMRawVFPStatusTransfer covers VMRS Rt,FPSCR, VMSR FPSCR,Rt, and the
// VMRS APSR_nzcv,FPSCR form for every executable A32 condition. PC is reserved
// as a VMSR source and denotes APSR_nzcv only in the VMRS direction.
func decodeARMRawVFPStatusTransfer(word uint32) (armRawVFPStatusTransfer, bool) {
	const mask = uint32(0x0fff0fff)
	key := word & mask
	toCore := false
	switch key {
	case 0x0ee10a10:
	case 0x0ef10a10:
		toCore = true
	default:
		return armRawVFPStatusTransfer{}, false
	}
	condition, ok := armRawCondition(word >> 28)
	if !ok {
		return armRawVFPStatusTransfer{}, false
	}
	core := int(word>>12) & 15
	if !toCore && core == 15 {
		return armRawVFPStatusTransfer{}, false
	}
	return armRawVFPStatusTransfer{
		toCore:    toCore,
		toFlags:   toCore && core == 15,
		condition: condition,
		core:      core,
	}, true
}

func (c *armCtx) lowerRawVFPStatusTransfer(form armRawVFPStatusTransfer) error {
	if form.condition != "" && form.condition != "AL" {
		condition := form.condition
		form.condition = "AL"
		return c.emitConditionalEffect(condition, func() error {
			return c.lowerRawVFPStatusTransfer(form)
		})
	}
	if form.toFlags {
		if !c.flagsWritten && !c.vfpCompareWritten {
			return fmt.Errorf("%w: raw VMRS has no preceding modeled VFP flag write", ErrProbeNeedsContext)
		}
		status := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i32 asm sideeffect %q, %q()\n", status, "vmrs $0, fpscr", "=r,~{memory}")
		c.storeFlagsFromStatus("%" + status)
		return nil
	}
	core := Reg(fmt.Sprintf("R%d", form.core))
	if form.toCore {
		status := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i32 asm sideeffect %q, %q()\n", status, "vmrs $0, fpscr", "=r,~{memory}")
		return c.storeReg(core, "%"+status)
	}
	status, err := c.loadReg(core)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(i32 %s)\n", "vmsr fpscr, $0", "r,~{memory}", status)
	return nil
}
