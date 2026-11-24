package plan9asm

import (
	"fmt"
	"golang.org/x/arch/x86/x86asm"
	"strings"
)

// --- amd64_raw_average.go ---
// The complete VEX/EVEX physical decoder is the only producer of the private
// marker which distinguishes raw mode32 masks from named Go's operand limit.
func decodedX86PackedAverageInstruction(code []byte, mode int) (Instr, int, bool, error) {
	return decodedX86PackedAverageInstructionWithMemory(code, mode, x86RawMemoryDecoder{})
}

func decodedX86PackedAverageInstructionWithMemory(code []byte, mode int, memory x86RawMemoryDecoder) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || p.mapNumber != 1 || p.pp != 1 || p.opcode != 0xe0 && p.opcode != 0xe3 {
		return Instr{}, 0, false, nil
	}
	if p.broadcast {
		return Instr{}, 0, true, fmt.Errorf("packed average has no broadcast or rounding encoding")
	}
	op, bits := Op("VPAVGB"), 8
	if p.opcode == 0xe3 {
		op, bits = "VPAVGW", 16
	}
	// WIG is a hardware property; the named Go encoder always emits W0.
	return decodedX86BinaryVectorOperandsWithMemory(code, p, mode, op, bits, memory)
}

// --- amd64_raw_blend_variable.go ---
// VEX variable blends encode the mask register in imm8[7:4], not an ordinary
// immediate. Intel's AVX/AVX2 tables specify 66.0F3A.W0, X/Y widths and no
// EVEX forms. The low nibble is ignored; in 32-bit mode bit 7 is also ignored.
func decodedX86VariableBlendInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || p.mapNumber != 3 {
		return Instr{}, 0, false, nil
	}
	var op Op
	for candidate, spec := range amd64VariableBlendSpecs {
		if spec.vector && spec.opcode == p.opcode {
			op = candidate
			break
		}
	}
	if op == "" {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("variable blend: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.evex || p.w || p.pp != 1 {
		return fail("requires VEX.128/256.66.0F3A.W0")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	if mode == 32 {
		if p.r != 0 || p.x != 0 {
			return fail("legacy LES encoding is not a 32-bit VEX instruction")
		}
		// Three-byte VEX ignores these high register selectors outside
		// 64-bit mode, independently of the imm8 mask-register selector.
		p.b = 0
		p.upper &= 7
	}
	prefix := "X"
	if p.vectorLength != 0 {
		prefix = "Y"
	}
	source, size, err := decodedX86VEXVectorRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, prefix)
	if err != nil {
		return Instr{}, 0, true, err
	}
	immediate := p.modRM + size
	if len(code) <= immediate {
		return fail("missing mask-register selector byte")
	}
	mask := int(code[immediate] >> 4)
	if mode == 32 {
		mask &= 7
	}
	reg := func(index int) Operand {
		return Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", prefix, index))}
	}
	args := []Operand{reg(mask), source, reg(p.upper), reg(int(code[p.modRM]>>3&7) + p.r*8)}
	return Instr{
		// This exact physical four-operand instruction is valid in mode32,
		// unlike Go's named frontend spelling. No other raw family acquires
		// that syntax role; the complete source replay seals this flag too.
		Op: op, Args: args, x86Encoded: true,
		Raw: fmt.Sprintf("%s %s, %s, %s, %s", op, args[0].String(), source.String(), args[2].String(), args[3].String()),
	}, immediate + 1, true, nil
}

// --- amd64_raw_bmi2_shift.go ---
// All six Go _ybextrl forms use VEX.L0. Intel XED's hsw-bmi-vex-isa
// table leaves W unconstrained in not64 mode, so Q bytes decode as L on 386.
func decodedX86BMI2ShiftInstruction(code []byte, mode int) (Instr, int, bool, error) {
	return decodedX86BMI2ShiftInstructionWithMemory(code, mode, x86RawMemoryDecoder{})
}

func decodedX86BMI2ShiftInstructionWithMemory(code []byte, mode int, memory x86RawMemoryDecoder) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || p.mapNumber != 2 || p.opcode != 0xf7 || p.pp == 0 {
		return Instr{}, 0, false, nil
	}

	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("BMI2 variable shift: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.evex || p.vectorLength != 0 {
		return fail("requires VEX.L0 encoding")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	if mode == 32 && (p.r != 0 || p.b != 0 || p.x != 0 || p.upper >= 8) {
		return fail("extended register in 32-bit mode")
	}

	bits := 32
	if p.w && mode == 64 {
		bits = 64
	}
	var op Op
	for name, spec := range amd64BMI2ShiftSpecs {
		if !spec.immediate && spec.bits == bits && spec.prefix == p.pp {
			op = name
			break
		}
	}

	source, size, err := memory.scalar(code[p.modRM:], mode, p.b, p.x, p.segment, 1)
	if err != nil {
		return Instr{}, 0, true, err
	}
	count, _ := decodedX86GeneralRegister(p.upper)
	destination, _ := decodedX86GeneralRegister(int(code[p.modRM]>>3&7) + p.r*8)
	instruction := Instr{
		Op: op,
		Args: []Operand{
			{Kind: OpReg, Reg: count},
			source,
			{Kind: OpReg, Reg: destination},
		},
		Raw: fmt.Sprintf("%s %s, %s, %s", op, count, source.String(), destination),
	}
	return instruction, p.modRM + size, true, nil
}

// --- amd64_raw_byte_shift.go ---
// decodedX86RawVectorByteShiftInstruction covers Go's VPSLLDQ/VPSRLDQ
// _yvpslldq table: VEX X/Y register forms and EVEX X/Y/Z register or memory
// forms, all with an imm8. ModRM.reg is the opcode extension (/7 or /3),
// while VEX.vvvv or EVEX.vvvvv names the destination.
func decodedX86RawVectorByteShiftInstruction(code []byte, mode int) (Instr, int, bool, error) {
	return decodedX86RawVectorByteShiftInstructionWithMemory(code, mode, x86RawMemoryDecoder{})
}

func decodedX86RawVectorByteShiftInstructionWithMemory(code []byte, mode int, memory x86RawMemoryDecoder) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || p.mapNumber != 1 || p.pp != 1 || p.opcode != 0x73 {
		return Instr{}, 0, false, nil
	}
	if len(code) <= p.modRM {
		return Instr{}, 0, true, fmt.Errorf("vector byte shift: missing ModRM byte")
	}
	group := int(code[p.modRM]>>3) & 7
	if group != 3 && group != 7 {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("vector byte shift: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.addressOverride || p.r != 0 || p.vectorLength > 2 ||
		p.evex && !p.fixed || p.mask != 0 || p.zero || p.broadcast {
		return fail("invalid prefix, mask or vector length")
	}
	registerSource := code[p.modRM]>>6 == 3
	if !p.evex && !registerSource {
		return fail("VEX byte shift requires a register source")
	}
	if mode == 32 && (p.upper >= 8 || registerSource && (p.b != 0 || p.x != 0)) {
		return fail("extended vector register in 32-bit mode")
	}
	width := [...]string{"X", "Y", "Z"}[p.vectorLength]
	var source Operand
	var consumed int
	var err error
	if p.evex {
		source, consumed, err = memory.evex(code[p.modRM:], mode, p.b, p.x, p.segment, width, 16<<p.vectorLength)
	} else {
		source, consumed, err = memory.vex(code[p.modRM:], mode, p.b, p.x, p.segment, width)
	}
	if err != nil {
		return Instr{}, 0, true, err
	}
	immIndex := p.modRM + consumed
	if len(code) <= immIndex {
		return fail("missing imm8")
	}
	op := Op("VPSRLDQ")
	if group == 7 {
		op = "VPSLLDQ"
	}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", width, p.upper))}
	args := []Operand{{Kind: OpImm, Imm: int64(code[immIndex])}, source, destination}
	encoding := x86RawPackedShiftVEX
	if p.evex {
		encoding = x86RawPackedShiftEVEX
	}
	return Instr{
		Op: op, Args: args, x86Encoded: true,
		Raw:                    fmt.Sprintf("%s %s, %s, %s", op, args[0].String(), source.String(), destination.String()),
		x86PackedShiftEncoding: encoding,
		x86PackedShiftW:        p.w,
	}, immIndex + 1, true, nil
}

// --- amd64_raw_bzhi.go ---
// decodedX86RawBZHIInstruction follows Go's two _ybextrl rows, BZHIL/Q.
// Both use VEX.128.0F38.W{0,1} F5 /r with a register index, register or
// memory source, and register destination. In 32-bit mode W is ignored.
func decodedX86RawBZHIInstruction(code []byte, mode int) (Instr, int, bool, error) {
	return decodedX86RawBZHIInstructionWithMemory(code, mode, x86RawMemoryDecoder{})
}

func decodedX86RawBZHIInstructionWithMemory(code []byte, mode int, memory x86RawMemoryDecoder) (Instr, int, bool, error) {
	return decodedX86ScalarBitFieldInstructionWithMemory(code, mode, memory, 0xf5, "BZHI")
}

// BEXTR has the same complete VEX/ModRM/SIB field grammar as BZHI, not
// its numerical control or FLAGS. Only the physical boundary consumer uses
// this entry; ordinary source decoding keeps its existing x86asm contract.
func decodedX86BEXTRInstructionWithMemory(code []byte, mode int, memory x86RawMemoryDecoder) (Instr, int, bool, error) {
	return decodedX86ScalarBitFieldInstructionWithMemory(code, mode, memory, 0xf7, "BEXTR")
}

func decodedX86ScalarBitFieldInstructionWithMemory(code []byte, mode int, memory x86RawMemoryDecoder, opcode int, stem string) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || p.mapNumber != 2 || p.opcode != opcode || p.pp != 0 {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("%s: %s", stem, message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.evex || p.vectorLength != 0 {
		return fail("requires VEX.L0 encoding")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	if mode == 32 && (p.r != 0 || p.b != 0 || p.x != 0 || p.upper >= 8) {
		return fail("extended register in 32-bit mode")
	}
	op := Op(stem + "L")
	if p.w && mode == 64 {
		op = Op(stem + "Q")
	}
	source, size, err := memory.scalar(code[p.modRM:], mode, p.b, p.x, p.segment, 1)
	if err != nil {
		return Instr{}, 0, true, err
	}
	index, _ := decodedX86GeneralRegister(p.upper)
	destination, _ := decodedX86GeneralRegister(int(code[p.modRM]>>3&7) + p.r*8)
	return Instr{
		Op: op,
		Args: []Operand{
			{Kind: OpReg, Reg: index}, source, {Kind: OpReg, Reg: destination},
		},
		Raw: fmt.Sprintf("%s %s, %s, %s", op, index, source.String(), destination),
	}, p.modRM + size, true, nil
}

// --- amd64_raw_endbranch.go ---
// ENDBR changes CET tracking, not GP/SIMD, FLAGS or storage. Numerical
// observers may preserve existing facts only for the exact named/raw form.
// The lowerer still emits the native opcode; this supplies no entry authority.
func x86EndBranchPreservesSourceState(ins Instr) bool {
	if ins.Op != "ENDBR64" && ins.Op != "ENDBR32" || len(ins.Args) != 0 ||
		ins.x86RawNearReturn != nil || ins.x86AddressBits != 0 ||
		ins.x86UnboundAddressOverride || ins.x86SegmentPrefix != 0 {
		return false
	}
	origin := ins.x86SourceRaw
	if origin == nil {
		return ins.Op == "ENDBR64" && !ins.x86Encoded
	}
	return ins.x86Encoded && origin.op == ins.Op && len(origin.args) == 0
}

// These instructions have different native effects. Only their preservation
// of numerical source facts is shared, never their lowering or CET semantics.
func x86PreservesNumericalSourceState(ins Instr) bool {
	return x86NOPPreservesSourceState(ins) || x86EndBranchPreservesSourceState(ins)
}

// ENDBR32/ENDBR64 have fixed, operand-free encodings (Intel SDM, volume 2).
// x86asm does not decode them yet. Preserve the actual instruction rather than
// replacing the CET state transition with a NOP. Go names only ENDBR64, so
// x86Encoded also keeps ENDBR32 confined to validated raw input.
func decodedX86EndBranchInstruction(code []byte) (Instr, int, bool) {
	if len(code) < 4 || code[0] != 0xf3 || code[1] != 0x0f || code[2] != 0x1e {
		return Instr{}, 0, false
	}
	var op Op
	switch code[3] {
	case 0xfa:
		op = "ENDBR64"
	case 0xfb:
		op = "ENDBR32"
	default:
		return Instr{}, 0, false
	}
	return Instr{Op: op, Raw: string(op), x86Encoded: true}, 4, true
}

// --- amd64_raw_evex_madd.go ---
// decodedX86EVEXPackedMADDInstruction covers the EVEX rows of Go's
// _yvandnpd optab shared by VPMADDUBSW and VPMADDWD. Neither row permits
// EVEX.b broadcasting, but both permit K masks and zeroing at X/Y/Z widths.
func decodedX86EVEXPackedMADDInstruction(code []byte, mode int) (Instr, int, bool, error) {
	return decodedX86EVEXPackedMADDInstructionWithMemory(code, mode, x86RawMemoryDecoder{})
}

func decodedX86EVEXPackedMADDInstructionWithMemory(code []byte, mode int, memory x86RawMemoryDecoder) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || !p.evex || p.pp != 1 {
		return Instr{}, 0, false, nil
	}
	op := map[[2]int]Op{
		{1, 0xf5}: "VPMADDWD",
		{2, 0x04}: "VPMADDUBSW",
	}[[2]int{p.mapNumber, p.opcode}]
	if op == "" {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("EVEX packed multiply-add: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if !p.fixed || p.broadcast || p.addressOverride || p.vectorLength > 2 {
		return fail("invalid EVEX fixed, width, broadcast, address, or vector-length bits")
	}
	// Both opcode-specific ISA rows are WIG. Full validated physical bytes,
	// including mode32 masks, use the common private decoder producer.
	return decodedX86BinaryVectorOperandsWithMemory(code, p, mode, op, 16, memory)
}

// --- amd64_raw_explicit_mask_move.go ---
// Go 1.27's _yvmaskmovpd table describes the four VEX X/Y masked load/store
// families. Opcode bit 1 selects store; W selects the D/Q integer lane.
var x86RawExplicitMaskMoveOps = map[int]Op{
	0x2c: "VMASKMOVPS",
	0x2d: "VMASKMOVPD",
	0x8c: "VPMASKMOVD",
}

func decodedX86ExplicitMaskMoveInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || p.evex || p.mapNumber != 2 {
		return Instr{}, 0, false, nil
	}
	// The floating store opcodes are 2E/2F; integer stores use 8E.
	base := p.opcode &^ 2
	op, known := x86RawExplicitMaskMoveOps[base]
	if !known {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("explicit mask move: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if p.pp != 1 || p.vectorLength > 1 || p.w && base != 0x8c {
		return fail("invalid VEX prefix or width")
	}
	if base == 0x8c && p.w {
		op = "VPMASKMOVQ"
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	if code[p.modRM]>>6 == 3 {
		return fail("explicit mask move requires a memory operand")
	}
	width := "X"
	if p.vectorLength == 1 {
		width = "Y"
	}
	memory, consumed, err := decodedX86VEXVectorRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, width)
	if err != nil {
		return Instr{}, 0, true, err
	}
	data := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", width, int(code[p.modRM]>>3&7)+p.r*8))}
	mask := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", width, p.upper))}
	args := []Operand{memory, mask, data}
	if p.opcode&2 != 0 {
		args = []Operand{data, mask, memory}
	}
	return Instr{
		Op:         op,
		Args:       args,
		Raw:        fmt.Sprintf("%s %s, %s, %s", op, args[0].String(), args[1].String(), args[2].String()),
		x86Encoded: true,
	}, p.modRM + consumed, true, nil
}

// --- amd64_raw_far_return.go ---
// decodedX86FarReturn preserves the actual operand-size attribute before
// x86asm.GoSyntax erases LRET's width or emits Intel's IRET/IRETD aliases.
// In both 32- and 64-bit modes a bare far return has a 32-bit operand size;
// only an effective REX.W promotes it to 64 bits. See Intel SDM volume 2,
// RET and IRET/IRETD/IRETQ, and Go's shared x86 ynone/yret encoder rows.
func decodedX86FarReturn(inst x86asm.Inst) (syntax string, recognized bool, err error) {
	kind := amd64InterruptReturn
	switch inst.Op {
	case x86asm.LRET:
		kind = amd64FarReturn
	case x86asm.IRET:
		if inst.DataSize != 16 {
			return "", true, fmt.Errorf("raw IRET has inconsistent operand size %d", inst.DataSize)
		}
	case x86asm.IRETD:
		if inst.DataSize != 32 {
			return "", true, fmt.Errorf("raw IRETD has inconsistent operand size %d", inst.DataSize)
		}
	case x86asm.IRETQ:
		if inst.DataSize != 64 {
			return "", true, fmt.Errorf("raw IRETQ has inconsistent operand size %d", inst.DataSize)
		}
	default:
		return "", false, nil
	}
	if (inst.Mode != 32 && inst.Mode != 64) || (inst.Mode == 32 && inst.DataSize == 64) {
		return "", true, fmt.Errorf("raw %s operand size %d is not supported in mode %d", inst.Op, inst.DataSize, inst.Mode)
	}
	for _, prefix := range inst.Prefix {
		if prefix == 0 {
			continue
		}
		// Register only the size prefixes represented by the typed family.
		// Never silently drop LOCK, REP, segment or address-size prefixes.
		// Decoder-rejected prefix orderings remain explicit decode failures.
		if prefix&x86asm.PrefixInvalid != 0 || (prefix&0xff != x86asm.PrefixDataSize && !prefix.IsREX()) {
			return "", true, fmt.Errorf("raw %s has an invalid or unregistered prefix %s", inst.Op, prefix)
		}
		if prefix.IsREX() && inst.Mode != 64 {
			return "", true, fmt.Errorf("raw %s has a REX prefix outside 64-bit mode", inst.Op)
		}
	}
	for _, extra := range inst.Args[1:] {
		if extra != nil {
			return "", true, fmt.Errorf("raw %s has extra operands", inst.Op)
		}
	}
	argument := ""
	if inst.Args[0] != nil {
		immediate, ok := inst.Args[0].(x86asm.Imm)
		if kind != amd64FarReturn || !ok || immediate < 0 || immediate > 65535 {
			return "", true, fmt.Errorf("raw %s requires no operand or an encoded unsigned imm16", inst.Op)
		}
		argument = fmt.Sprintf(" $%d", immediate)
	}
	for op, spec := range amd64FarReturnSpecs {
		if spec.kind == kind && spec.bits == inst.DataSize {
			return string(op) + argument, true, nil
		}
	}
	return "", true, fmt.Errorf("raw %s has unregistered operand size %d", inst.Op, inst.DataSize)
}

// --- amd64_raw_gfni.go ---
// The Go 1.27 table has one GFNI family: multiply (0F38 CF, W0) and the
// affine/inverse pair (0F3A CE/CF, W1). Its VEX rows are X/Y; EVEX adds Z,
// masks, zeroing and, only for the affine matrix source, qword broadcast.
func decodedX86GFNIInstruction(code []byte, mode int) (Instr, int, bool, error) {
	return decodedX86GFNIInstructionWithMemory(code, mode, x86RawMemoryDecoder{})
}

func decodedX86GFNIInstructionWithMemory(code []byte, mode int, memory x86RawMemoryDecoder) (Instr, int, bool, error) {
	p, ok := decodeX86RawVectorEncoding(code)
	if !ok {
		return Instr{}, 0, false, nil
	}

	var op Op
	var immediate bool
	switch {
	case p.mapNumber == 2 && p.opcode == 0xcf:
		op = "VGF2P8MULB"
	case p.mapNumber == 3 && p.opcode == 0xce:
		op, immediate = "VGF2P8AFFINEQB", true
	case p.mapNumber == 3 && p.opcode == 0xcf:
		op, immediate = "VGF2P8AFFINEINVQB", true
	default:
		return Instr{}, 0, false, nil
	}
	if p.w != immediate {
		return Instr{}, 0, true, fmt.Errorf("%s has invalid W bit", op)
	}
	if p.broadcast && !immediate {
		return Instr{}, 0, true, fmt.Errorf("%s has no broadcast form", op)
	}

	laneBits := 8
	if immediate {
		laneBits = 64
	}
	instruction, length, known, err := decodedX86BinaryVectorOperandsWithMemory(code, p, mode, op, laneBits, memory)
	if err != nil || !immediate {
		return instruction, length, known, err
	}
	return decodedX86VectorLeadingImm8(code, instruction, length)
}

// --- amd64_raw_horizontal_integer.go ---
// Go's VPHADD/PHSUB family has two _yvaddsubpd rows, X and Y, without
// EVEX/masks. W is ignored (Go emits W0); Intel XED leaves W unconstrained:
// https://github.com/intelxed/xed/blob/main/datafiles/avx/avx-isa.txt
func decodedX86VEXHorizontalIntegerInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || p.mapNumber != 2 {
		return Instr{}, 0, false, nil
	}
	var op Op
	for name, spec := range amd64HorizontalIntegerSpecs {
		if spec.vector && int(spec.opcode) == p.opcode {
			op = name
			break
		}
	}
	if op == "" {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("horizontal integer: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.evex || p.pp != 1 || p.vectorLength > 1 {
		return fail("requires VEX.66.0F38 X/Y encoding")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	if mode == 32 && (p.r != 0 || p.x != 0 || p.b != 0 || p.upper >= 8) {
		return fail("extended register in 32-bit mode")
	}
	width := []string{"X", "Y"}[p.vectorLength]
	source2, size, err := decodedX86VEXVectorRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, width)
	if err != nil {
		return Instr{}, 0, true, err
	}
	source1 := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", width, p.upper))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", width, int(code[p.modRM]>>3&7)+p.r*8))}
	return Instr{
		Op: op, Args: []Operand{source2, source1, destination},
		Raw: fmt.Sprintf("%s %s, %s, %s", op, source2.String(), source1.String(), destination.String()),
	}, p.modRM + size, true, nil
}

// --- amd64_raw_implicit_mask_move.go ---
// MASKMOVDQU and VMASKMOVDQU encode data in ModRM.reg and the
// mask in ModRM.r/m. Neither form encodes the DI memory destination.
func decodedX86ImplicitVectorMaskMove(code []byte, mode int) (Instr, int, bool, error) {
	op, modRM, reg, rm := Op("MASKMOVDQU"), 3, 0, 0
	var segment byte
	addressOverride := false
	fail := func(reason string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("implicit vector mask store: %s", reason)
	}
	if p, vector := decodeX86RawVectorEncoding(code); vector {
		if p.evex || p.mapNumber != 1 || p.opcode != 0xf7 {
			return Instr{}, 0, false, nil
		}
		// W is ignored, while the encoded vvvv field is reserved and
		// must be all ones (zero after complementing).
		if p.pp != 1 || p.vectorLength != 0 || p.upper != 0 {
			return fail("invalid VEX prefix")
		}
		if mode == 32 && (p.r != 0 || p.x != 0 || p.b != 0) {
			return fail("extended VEX register encoding in 32-bit mode")
		}
		op, modRM, reg, rm = "VMASKMOVDQU", p.modRM, p.r, p.b
		switch p.segment {
		case FS:
			segment = 0x64
		case GS:
			segment = 0x65
		}
		addressOverride = p.addressOverride
	} else {
		// The generic decoder keeps legacy address-size overrides unbound.
		// Only the exact default-address SSE encoding enters this path.
		if len(code) < 3 || code[0] != 0x66 {
			return Instr{}, 0, false, nil
		}
		if mode == 64 && code[1]&0xf0 == 0x40 {
			reg, rm, modRM = int(code[1]>>2&1), int(code[1]&1), modRM+1
		}
		if len(code) < modRM || code[modRM-2] != 0x0f || code[modRM-1] != 0xf7 {
			return Instr{}, 0, false, nil
		}
	}
	if len(code) <= modRM || code[modRM]>>6 != 3 {
		return fail("expected a register ModRM")
	}
	mask := Reg(fmt.Sprintf("X%d", rm*8+int(code[modRM]&7)))
	data := Reg(fmt.Sprintf("X%d", reg*8+int(code[modRM]>>3&7)))
	ins := Instr{
		Op:   op,
		Args: []Operand{{Kind: OpReg, Reg: mask}, {Kind: OpReg, Reg: data}},
		Raw:  fmt.Sprintf("%s %s, %s", op, mask, data),

		x86Encoded:       true,
		x86SegmentPrefix: segment,
	}
	if addressOverride {
		ins.x86AddressBits = mode / 2
		ins.x86UnboundAddressOverride = true
	}
	return ins, modRM + 1, true, nil
}

// --- amd64_raw_integer_dot.go ---
func decodedX86IntegerPackedDotInstruction(code []byte, mode int) (Instr, int, bool, error) {
	return decodedX86IntegerPackedDotInstructionWithMemory(code, mode, x86RawMemoryDecoder{})
}

func decodedX86IntegerPackedDotInstructionWithMemory(code []byte, mode int, memory x86RawMemoryDecoder) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || p.mapNumber != 2 || p.evex && p.pp == 2 {
		return Instr{}, 0, false, nil // BF16 owns EVEX.F3, not integer VNNI.
	}
	var op Op
	for name, spec := range amd64PackedDotProductSpecs {
		if !spec.bfloat && int(spec.opcode) == p.opcode {
			op = name
			break
		}
	}
	if op == "" {
		return Instr{}, 0, false, nil
	}
	if p.w {
		return Instr{}, 0, true, fmt.Errorf("integer dot-product encoding requires W0")
	}
	ins, size, known, err := decodedX86BinaryVectorOperandsWithMemory(code, p, mode, op, 32, memory)
	if err != nil || !known {
		return ins, size, known, err
	}
	if size > 15 {
		return Instr{}, 0, true, fmt.Errorf("integer dot-product instruction exceeds 15 bytes")
	}
	ins.x86VectorBytes = 16 << p.vectorLength
	ins.x86PackedDotEncoding = x86RawPackedDotVEX
	if p.evex {
		ins.x86PackedDotEncoding = x86RawPackedDotEVEX
	}
	return ins, size, true, nil
}

// --- amd64_raw_kshift.go ---
// Go 1.27 _ykshiftlb uses opcode 30/31 for right and 32/33 for left;
// VEX.W distinguishes B/W or D/Q at each opcode.
var x86RawMaskShiftOps = [4][2]Op{
	{"KSHIFTRB", "KSHIFTRW"},
	{"KSHIFTRD", "KSHIFTRQ"},
	{"KSHIFTLB", "KSHIFTLW"},
	{"KSHIFTLD", "KSHIFTLQ"},
}

func decodedX86RawMaskShiftInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, recognized := decodeX86RawVectorEncoding(code)
	if !recognized || p.evex || p.mapNumber != 3 || p.pp != 1 || p.opcode < 0x30 || p.opcode > 0x33 {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("mask shift: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if p.vectorLength != 0 || p.upper != 0 || p.r != 0 || p.b != 0 || p.x != 0 {
		return fail("invalid reserved VEX bit")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	modRM := code[p.modRM]
	if modRM>>6 != 3 {
		return fail("KSHIFT requires a K-register source")
	}
	if len(code) <= p.modRM+1 {
		return fail("missing imm8 shift count")
	}
	w := 0
	if p.w {
		w = 1
	}
	op := x86RawMaskShiftOps[p.opcode-0x30][w]
	count := code[p.modRM+1]
	source := modRM & 7
	destination := modRM >> 3 & 7
	args := []Operand{
		{Kind: OpImm, Imm: int64(count)},
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", source))},
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", destination))},
	}
	return Instr{
		Op:   op,
		Args: args,
		Raw:  fmt.Sprintf("%s $%d, K%d, K%d", op, count, source, destination),
	}, p.modRM + 2, true, nil
}

// --- amd64_raw_legacy_scalar_rip.go ---
// These Go legacy SSE scalar families read a fixed-width RIP-relative source
// and update only a vector register or flags. A source-local constant can be
// materialized without losing an in-place memory write or relocation.
var x86RawLegacyScalarReadOps = map[Op]bool{
	"MOVL": true, "MOVQ": true, "MOVLQSX": true,
	"UCOMISD": true, "UCOMISS": true, "COMISD": true, "COMISS": true,
	"CMPSS": true, "CMPSD": true,
	"ADDSS": true, "ADDSD": true, "SUBSS": true, "SUBSD": true,
	"MULSS": true, "MULSD": true, "DIVSS": true, "DIVSD": true,
	"MINSS": true, "MINSD": true, "MAXSS": true, "MAXSD": true,
	"SQRTSS": true, "SQRTSD": true,
}

func decodeX86RawLegacyScalarRIPData(
	code []byte, offset int, inst x86asm.Inst, syntax string,
) (Instr, x86RawLiteralRange, bool, error) {
	if inst.Mode != 64 || inst.AddrSize != 64 || inst.PCRel != 4 ||
		inst.MemBytes != 4 && inst.MemBytes != 8 {
		return Instr{}, x86RawLiteralRange{}, false, nil
	}
	op := Op(strings.Fields(syntax)[0])
	if !x86RawLegacyScalarReadOps[op] {
		return Instr{}, x86RawLiteralRange{}, false, nil
	}
	if _, ok := inst.Args[0].(x86asm.Reg); !ok {
		return Instr{}, x86RawLiteralRange{}, false, nil
	}
	mem, ok := inst.Args[1].(x86asm.Mem)
	if !ok || mem.Base != x86asm.RIP {
		return Instr{}, x86RawLiteralRange{}, false, nil
	}
	if len(code) <= offset || code[offset] == 0x64 || code[offset] == 0x65 || code[offset] == 0x67 {
		return Instr{}, x86RawLiteralRange{}, false, nil
	}
	modRMIndex := offset + inst.PCRelOff - 1
	if modRMIndex < offset || modRMIndex >= len(code) || code[modRMIndex]&0xc7 != 0x05 {
		return Instr{}, x86RawLiteralRange{}, false, nil
	}
	trailing := inst.Len - inst.PCRelOff - inst.PCRel
	if trailing != 0 && (op != "CMPSS" && op != "CMPSD" || trailing != 1) {
		return Instr{}, x86RawLiteralRange{}, false, nil
	}
	patched, data, literal, err := x86RawRIPBytesWithSuffix(code, offset, modRMIndex, inst.MemBytes, trailing)
	if err != nil {
		return Instr{}, x86RawLiteralRange{}, true, err
	}
	physical, err := x86asm.Decode(patched, 64)
	if err != nil || physical.Len != len(patched) {
		return Instr{}, x86RawLiteralRange{}, true, fmt.Errorf("patched legacy scalar encoding is invalid: %v", err)
	}
	patchedSyntax, err := decodedX86GoSyntax(physical, patched)
	if err != nil {
		return Instr{}, x86RawLiteralRange{}, true, err
	}
	instrs, err := parseDecodedX86Instruction(patchedSyntax)
	if err != nil || len(instrs) != 1 || len(instrs[0].Args) < 2 || instrs[0].Args[0].Kind != OpMem {
		return Instr{}, x86RawLiteralRange{}, true, fmt.Errorf("patched legacy scalar instruction %q has no memory source: %v", patchedSyntax, err)
	}
	setX86RawRIPDataOperand(&instrs[0], 0, data)
	return instrs[0], literal, true, nil
}

// --- amd64_raw_mask_blend.go ---
// decodedX86RawMaskBlendInstruction covers all six Go 1.27 _yvblendmpd
// operations across EVEX X/Y/Z, optional K mask and zeroing, and permitted
// D/Q scalar broadcasts. The shared typed operand decoder handles ModRM/SIB.
func decodedX86RawMaskBlendInstruction(code []byte, mode int) (Instr, int, bool, error) {
	return decodedX86RawMaskBlendInstructionWithMemory(code, mode, x86RawMemoryDecoder{})
}

func decodedX86RawMaskBlendInstructionWithMemory(code []byte, mode int, memory x86RawMemoryDecoder) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || !p.evex || p.mapNumber != 2 || p.pp != 1 {
		return Instr{}, 0, false, nil
	}
	var op Op
	var laneBits int
	switch p.opcode {
	case 0x65:
		if p.w {
			op, laneBits = "VBLENDMPD", 64
		} else {
			op, laneBits = "VBLENDMPS", 32
		}
	case 0x64:
		if p.w {
			op, laneBits = "VPBLENDMQ", 64
		} else {
			op, laneBits = "VPBLENDMD", 32
		}
	case 0x66:
		if p.w {
			op, laneBits = "VPBLENDMW", 16
		} else {
			op, laneBits = "VPBLENDMB", 8
		}
	default:
		return Instr{}, 0, false, nil
	}
	if mode == 32 && p.mask != 0 {
		return Instr{}, 0, true, fmt.Errorf("386 masked %s exceeds Go's three-operand frontend", op)
	}
	return decodedX86BinaryVectorOperandsWithMemory(code, p, mode, op, laneBits, memory)
}

// --- amd64_raw_memory_decoder.go ---
// The zero value retains the raw source decoder's layout restrictions. Only
// original native byte observers select physicalPC: they observe whole native
// instruction boundaries and discards these operands. A physical RIP+disp32
// is not a source symbol, bounded literal, numerical value, or read permission.
type x86RawMemoryDecoder struct {
	physicalPC bool
}

func (d x86RawMemoryDecoder) vexTransfer(code []byte, mode, bExt, xExt int, segment Reg, vector bool) (Operand, int, error) {
	if len(code) == 0 || code[0]>>6 == 3 || !d.physicalPC {
		return decodedX86VEXRMOperand(code, mode, bExt, xExt, segment, vector)
	}
	return decodedX86RMSourceWithPC(code, mode, bExt, xExt, segment, 1, true)
}

func (d x86RawMemoryDecoder) scalar(code []byte, mode, bExt, xExt int, segment Reg, width int) (Operand, int, error) {
	return decodedX86RMSourceWithPC(code, mode, bExt, xExt, segment, width, d.physicalPC)
}

func (d x86RawMemoryDecoder) evex(code []byte, mode, bExt, xExt int, segment Reg, bank string, scale int) (Operand, int, error) {
	if len(code) == 0 || code[0]>>6 == 3 {
		return decodedX86EVEXRMOperand(code, mode, bExt, xExt, segment, bank, scale)
	}
	return decodedX86RMSourceWithPC(code, mode, bExt, xExt, segment, scale, d.physicalPC)
}

func (d x86RawMemoryDecoder) vex(code []byte, mode, bExt, xExt int, segment Reg, bank string) (Operand, int, error) {
	if len(code) == 0 || code[0]>>6 == 3 {
		return decodedX86VEXVectorRMOperand(code, mode, bExt, xExt, segment, bank)
	}
	return decodedX86RMSourceWithPC(code, mode, bExt, xExt, segment, 1, d.physicalPC)
}

// --- amd64_raw_minmax.go ---
// VEX B/W/D ignores W. EVEX B/W also ignores W; D/Q shares an opcode with
// fixed W0/W1, and Q has no VEX encoding. The remaining operand grammar is
// shared with per-lane shifts, not inferred from the legacy disassembler.
func decodedX86PackedIntegerMinMaxInstruction(code []byte, mode int) (Instr, int, bool, error) {
	return decodedX86PackedIntegerMinMaxInstructionWithMemory(code, mode, x86RawMemoryDecoder{})
}

func decodedX86PackedIntegerMinMaxInstructionWithMemory(code []byte, mode int, memory x86RawMemoryDecoder) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched {
		return Instr{}, 0, false, nil
	}

	for name, spec := range amd64PackedIntegerMinMaxSpecs {
		if p.mapNumber != spec.mapNumber || p.opcode != spec.opcode {
			continue
		}
		if !p.evex && spec.laneBits == 64 {
			continue
		}
		if p.evex && spec.laneBits >= 32 && p.w != (spec.laneBits == 64) {
			continue
		}

		return decodedX86BinaryVectorOperandsWithMemory(code, p, mode, Op(name), spec.laneBits, memory)
	}
	return Instr{}, 0, false, nil
}

// --- amd64_raw_minpos.go ---
// Intel XED's AVX table specifies VL128, V66, V0F38 and NOVSR; W is ignored.
// There are no Y/Z, EVEX, mask, immediate or three-operand forms.
func decodedX86MinimumPositionInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	spec := amd64MinimumPositionSpecs["VPHMINPOSUW"]
	if !matched || p.mapNumber != spec.mapNumber || p.opcode != spec.opcode {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("minimum position: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.evex || p.vectorLength != 0 || p.pp != 1 || p.upper != 0 {
		return fail("requires VEX.128.66 with reserved vvvv")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	if mode == 32 && (p.r != 0 || p.x != 0 || p.b != 0) {
		return fail("extended register in 32-bit mode")
	}
	source, size, err := decodedX86VEXVectorRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, "X")
	if err != nil {
		return Instr{}, 0, true, err
	}
	dst := Reg(fmt.Sprintf("X%d", int(code[p.modRM]>>3&7)+p.r*8))
	return Instr{
		Op:   "VPHMINPOSUW",
		Args: []Operand{source, {Kind: OpReg, Reg: dst}},
		Raw:  fmt.Sprintf("VPHMINPOSUW %s, %s", source.String(), dst),
	}, p.modRM + size, true, nil
}

// --- amd64_raw_mixed_layout.go ---
// These legacy SSE/SSE2 symbol loads occur between generated raw instruction
// spans. Their exact Go-assembler lengths are needed only to locate raw
// PC-relative targets; the named instructions still lower semantically.
var x86RawMixedSSESymbolReadOps = map[Op]bool{
	"ADDPD": true, "ADDPS": true, "MULPD": true, "MULPS": true,
	"ANDPD": true, "ANDPS": true, "ANDNPD": true, "ANDNPS": true,
	"XORPD": true, "XORPS": true, "CMPPD": true, "CMPPS": true,
	"PAND": true, "PANDN": true, "POR": true, "PXOR": true,
	"PADDB": true, "PADDW": true, "PADDL": true, "PADDQ": true,
	"PSUBL": true, "PCMPGTL": true, "PCMPEQL": true,
	"PMULHUW": true, "PMADDWL": true, "PMINUB": true, "PMAXUB": true,
	"MOVQ": true,
}

func x86RawMixedSSESymbolReadSize(ins Instr) (int, bool) {
	if !x86RawMixedSSESymbolReadOps[ins.Op] || len(ins.Args) < 2 ||
		ins.Args[0].Kind != OpSym || ins.Args[1].Kind != OpReg {
		return 0, false
	}
	if _, _, ok := parseSBRef(ins.Args[0].Sym); !ok {
		return 0, false
	}
	register, ok := amd64ParseXReg(ins.Args[1].Reg)
	if !ok || register >= 16 {
		return 0, false
	}
	compare := ins.Op == "CMPPD" || ins.Op == "CMPPS"
	if compare {
		if len(ins.Args) != 3 || ins.Args[2].Kind != OpImm || ins.Args[2].Imm < 0 || ins.Args[2].Imm > 255 {
			return 0, false
		}
	} else if len(ins.Args) != 2 {
		return 0, false
	}
	// 0F opcode, ModRM and disp32 = 7 bytes. Packed-double/integer and
	// MOVQ forms have one mandatory prefix; X8..X15 add one REX byte.
	length := 7
	if ins.Op == "MOVQ" || len(ins.Op) > 0 && ins.Op[0] == 'P' ||
		len(ins.Op) >= 2 && ins.Op[len(ins.Op)-2:] == "PD" {
		length++
	}
	if register >= 8 {
		length++
	}
	if compare {
		length++
	}
	return length, true
}

// --- amd64_raw_movemask.go ---
// Decode Go's VEX _yvmovmskpd family before x/arch can mistake opcode 50/D7
// for a legacy PUSH/XLATB. The source is always a vector register; ModRM.reg
// names the GP destination and vvvv is reserved.
func decodedX86VEXMoveMaskInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || p.evex || p.mapNumber != 1 {
		return Instr{}, 0, false, nil
	}
	var op Op
	for name, spec := range amd64MoveMaskSpecs {
		if spec.vector && spec.opcode == p.opcode && spec.prefix == p.pp {
			op = name
			break
		}
	}
	if op == "" {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("VEX move mask: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if p.upper != 0 || p.vectorLength > 1 {
		return fail("reserved vvvv or vector length")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	if code[p.modRM]>>6 != 3 {
		return fail("source must be a vector register")
	}
	if mode == 32 && (p.r != 0 || p.b != 0 || p.x != 0) {
		return fail("extended register in 32-bit mode")
	}
	width := "X"
	if p.vectorLength == 1 {
		width = "Y"
	}
	source := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", width, int(code[p.modRM]&7)+p.b*8))}
	destinationNumber := int(code[p.modRM]>>3&7) + p.r*8
	destinationReg, valid := decodedX86GeneralRegister(destinationNumber)
	if !valid {
		return fail("invalid GP destination register")
	}
	destination := Operand{Kind: OpReg, Reg: destinationReg}
	return Instr{
		Op:   op,
		Args: []Operand{source, destination},
		Raw:  fmt.Sprintf("%s %s, %s", op, source.String(), destination.String()),
	}, p.modRM + 1, true, nil
}

// --- amd64_raw_movhlps.go ---
var x86RawVectorHighLowMoveOps = map[int]Op{
	0x12: "VMOVHLPS",
	0x16: "VMOVLHPS",
}

// The Go 1.27 _yvmovhlps table has exactly two register-only 128-bit rows.
// ModRM memory encodings belong to the separate VMOVLPS/VMOVHPS family.
func decodedX86RawVectorHighLowMoveInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, recognized := decodeX86RawVectorEncoding(code)
	if !recognized || p.mapNumber != 1 || p.pp != 0 {
		return Instr{}, 0, false, nil
	}
	op, owned := x86RawVectorHighLowMoveOps[p.opcode]
	if !owned {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("vector high/low move: %s", message)
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	if code[p.modRM]>>6 != 3 {
		return Instr{}, 0, false, nil
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if p.vectorLength != 0 || p.evex && (!p.fixed || p.w || p.mask != 0 || p.zero || p.broadcast) {
		return fail("invalid 128-bit VEX/EVEX register form")
	}
	if !p.evex && mode == 32 && (p.r != 0 || p.upper >= 8) {
		return fail("extended VEX register in 32-bit mode")
	}
	var first Operand
	var consumed int
	var err error
	if p.evex {
		first, consumed, err = decodedX86EVEXRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, "X", 16)
	} else {
		first, consumed, err = decodedX86VEXVectorRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, "X")
	}
	if err != nil {
		return Instr{}, 0, true, err
	}
	second := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", p.upper))}
	destinationNumber := int(code[p.modRM]>>3&7) + p.r*8
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", destinationNumber))}
	args := []Operand{first, second, destination}
	printed := make([]string, len(args))
	for index, arg := range args {
		printed[index] = arg.String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(printed, ", "))}, p.modRM + consumed, true, nil
}

// --- amd64_raw_nop.go ---
// The decoder discards NOP's inert ModRM/SIB fields only after validating the
// complete encoding. Preserve existing source facts through that exact handoff,
// not through a different physical instruction or an unbound address contract.
// This observation creates no numerical, pointer, memory or raw-entry fact.
func x86NOPPreservesSourceState(ins Instr) bool {
	if ins.Op != "NOP" || len(ins.Args) != 0 || ins.x86Encoded || ins.x86RawNearReturn != nil ||
		ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride || ins.x86SegmentPrefix != 0 {
		return false
	}
	origin := ins.x86SourceRaw
	return origin == nil || origin.op == "NOP" && len(origin.args) == 0
}

// The pinned decoder lacks the REX.W form of 0F 1F /0 (LLVM 22 NOOPQ).
// Only its operand width is inert. Keep every other prefix and use the decoder
// for the complete ModRM/SIB/displacement length and prefix validity. This
// narrowly scoped adapter never changes 90's XCHG/PAUSE aliases or another
// opcode, and its result is consumed only by the operand-free NOP handoff.
func decodedX86REXWNOP(code []byte) (x86asm.Inst, bool) {
	if len(code) > 15 {
		code = code[:15]
	}
	i := 0
	for i < len(code) {
		switch code[i] {
		case 0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65, 0x66, 0x67, 0xf0, 0xf2, 0xf3:
			i++
		default:
			goto opcode
		}
	}

opcode:
	if i+4 > len(code) || code[i]&0xf8 != 0x48 ||
		code[i+1] != 0x0f || code[i+2] != 0x1f || code[i+3]&0x38 != 0 {
		return x86asm.Inst{}, false
	}
	var adjusted [15]byte
	copy(adjusted[:], code)
	adjusted[i] &^= 8
	inst, err := x86asm.Decode(adjusted[:len(code)], 64)
	if err != nil || inst.Op != x86asm.NOP || inst.Len <= i+3 {
		return x86asm.Inst{}, false
	}
	return inst, true
}

// --- amd64_raw_pack.go ---
// Go 1.27's four VPACK rows share the same three-operand grammar. The two
// dword-to-word operations also permit EVEX 32-bit memory broadcast.
var x86RawPackedNarrowOps = map[[2]int]struct {
	op        Op
	broadcast bool
	evexW0    bool
}{
	{1, 0x6b}: {op: "VPACKSSDW", broadcast: true, evexW0: true},
	{1, 0x63}: {op: "VPACKSSWB"},
	{2, 0x2b}: {op: "VPACKUSDW", broadcast: true, evexW0: true},
	{1, 0x67}: {op: "VPACKUSWB"},
}

func decodedX86VectorPackedSaturatingNarrowInstruction(code []byte, mode int) (Instr, int, bool, error) {
	return decodedX86VectorPackedSaturatingNarrowInstructionWithMemory(code, mode, x86RawMemoryDecoder{})
}

func decodedX86VectorPackedSaturatingNarrowInstructionWithMemory(code []byte, mode int, memory x86RawMemoryDecoder) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched {
		return Instr{}, 0, false, nil
	}
	spec, known := x86RawPackedNarrowOps[[2]int{p.mapNumber, p.opcode}]
	if !known {
		return Instr{}, 0, false, nil
	}
	// Intel's VEX pack rows ignore W. EVEX dword inputs require W0,
	// while EVEX word inputs also ignore W. Go happens to emit W0 for all;
	// that chosen encoding is not the complete legal physical grammar.
	if p.evex && spec.evexW0 && p.w {
		return Instr{}, 0, true, fmt.Errorf("packed saturating narrow: unsupported W bit")
	}
	bits := 16
	if spec.broadcast {
		bits = 32
	}
	return decodedX86BinaryVectorOperandsWithMemory(code, p, mode, spec.op, bits, memory)
}

// --- amd64_raw_packed_sign.go ---
// Go 1.27's _yvaddsubpd table gives all three VPSIGN instructions exactly
// the same VEX.128/VEX.256 register-and-memory operand grammar.
var x86RawPackedSignOps = [...]Op{"VPSIGNB", "VPSIGNW", "VPSIGND"}

func decodedX86RawPackedSignInstruction(code []byte, mode int) (Instr, int, bool, error) {
	return decodedX86RawPackedSignInstructionWithMemory(code, mode, x86RawMemoryDecoder{})
}

func decodedX86RawPackedSignInstructionWithMemory(code []byte, mode int, memory x86RawMemoryDecoder) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || p.mapNumber != 2 || p.opcode < 0x08 || p.opcode > 0x0a {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("packed sign: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.evex || p.pp != 1 || p.addressOverride {
		return fail("packed sign requires VEX.66.0F38.WIG without address override")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	width := [...]string{"X", "Y"}[p.vectorLength]
	destinationNumber := int(code[p.modRM]>>3&7) + p.r*8
	if mode == 32 && (destinationNumber >= 8 || p.upper >= 8) {
		return fail("extended vector register unavailable in 32-bit mode")
	}
	source, consumed, err := memory.vex(code[p.modRM:], mode, p.b, p.x, p.segment, width)
	if err != nil {
		return Instr{}, 0, true, err
	}
	data := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", width, p.upper))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", width, destinationNumber))}
	op := x86RawPackedSignOps[p.opcode-0x08]
	args := []Operand{source, data, destination}
	printed := []string{source.String(), data.String(), destination.String()}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(printed, ", "))}, p.modRM + consumed, true, nil
}

// --- amd64_raw_packed_widen_conversion.go ---
// The eight packed float-to-(u)int64 conversions share Go 1.27's
// _yvcvtps2qq and _yvcvtpd2qq grammars. Their source width is determined
// by the float lane size and destination width, with common mask, zeroing,
// broadcast, and embedded rounding/SAE rules.
var x86RawPackedWidenConversionByOpcode = map[int]Op{
	0x7b: "VCVTPS2QQ",
	0x79: "VCVTPS2UQQ",
	0x7a: "VCVTTPS2QQ",
	0x78: "VCVTTPS2UQQ",
}

var x86RawPackedDoubleConversionByOpcode = map[int]Op{
	0x7b: "VCVTPD2QQ",
	0x79: "VCVTPD2UQQ",
	0x7a: "VCVTTPD2QQ",
	0x78: "VCVTTPD2UQQ",
}

func decodedX86PackedWidenConversionInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || !p.evex || p.mapNumber != 1 || p.pp != 1 || p.opcode < 0x78 || p.opcode > 0x7b {
		return Instr{}, 0, false, nil
	}
	return decodedX86PackedNumericConversionInstruction(code, mode)
}

// --- amd64_raw_parallel_bits.go ---
// PDEP/PEXT share Go's _yandnl register/memory-mask grammar. Intel XED's
// datafiles/hswbmi/hsw-bmi-vex-isa.xed.txt confirms W is ignored in not64
// mode, while L must be zero. This is BMI2, not an arbitrary AVX fallback.
func decodedX86ParallelBitsInstruction(code []byte, mode int) (Instr, int, bool, error) {
	return decodedX86ParallelBitsInstructionWithMemory(code, mode, x86RawMemoryDecoder{})
}

func decodedX86ParallelBitsInstructionWithMemory(code []byte, mode int, memory x86RawMemoryDecoder) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || p.mapNumber != 2 || p.opcode != 0xf5 || (p.pp != 2 && p.pp != 3) {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("parallel bit operation: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.evex || p.vectorLength != 0 {
		return fail("requires VEX.L0 encoding")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	if mode == 32 && (p.r != 0 || p.b != 0 || p.x != 0 || p.upper >= 8) {
		return fail("extended register in 32-bit mode")
	}
	bits := 32
	if p.w && mode == 64 {
		bits = 64
	}
	var op Op
	for name, spec := range x86TernaryGPSpecs {
		if spec.operation != x86TernaryANDN && spec.bits == bits && spec.prefix == p.pp {
			op = name
			break
		}
	}
	mask, size, err := memory.scalar(code[p.modRM:], mode, p.b, p.x, p.segment, 1)
	if err != nil {
		return Instr{}, 0, true, err
	}
	src, _ := decodedX86GeneralRegister(p.upper)
	dst, _ := decodedX86GeneralRegister(int(code[p.modRM]>>3&7) + p.r*8)
	return Instr{Op: op, Args: []Operand{mask, {Kind: OpReg, Reg: src}, {Kind: OpReg, Reg: dst}}, Raw: fmt.Sprintf("%s %s, %s, %s", op, mask.String(), src, dst)}, p.modRM + size, true, nil
}

// --- amd64_raw_portio.go ---
// decodedX86ScalarPortIOInstruction covers Go's complete yin table: input
// and output, byte/word/long, with either an immediate port or implicit DX.
// x/arch's GoSyntax prints the architectural accumulator and DX operands,
// whereas Go's assembler source syntax omits both. Its old decoder also calls
// the byte encodings INL/OUTL. Decode these small fixed forms from the opcode.
func decodedX86ScalarPortIOInstruction(code []byte) (Instr, int, bool, error) {
	if len(code) == 0 {
		return Instr{}, 0, false, nil
	}
	index := 0
	word := false
	if code[index] == 0x66 {
		word = true
		index++
		if len(code) == index {
			return Instr{}, 0, false, nil
		}
	}
	opcode := code[index]
	if opcode < 0xe4 || (opcode > 0xe7 && opcode < 0xec) || opcode > 0xef {
		return Instr{}, 0, false, nil
	}
	input := opcode == 0xe4 || opcode == 0xe5 || opcode == 0xec || opcode == 0xed
	byteWidth := opcode&1 == 0
	name := "OUT"
	if input {
		name = "IN"
	}
	width := "L"
	if byteWidth {
		width = "B"
	} else if word {
		width = "W"
	}
	index++
	var args []Operand
	if opcode >= 0xe4 && opcode <= 0xe7 {
		if len(code) == index {
			return Instr{}, 0, true, fmt.Errorf("missing immediate port byte")
		}
		args = []Operand{{Kind: OpImm, Imm: int64(code[index])}}
		index++
	}
	op := Op(name + width)
	raw := string(op)
	if len(args) != 0 {
		raw = fmt.Sprintf("%s $%d", op, args[0].Imm)
	}
	return Instr{Op: op, Args: args, Raw: raw}, index, true, nil
}

// --- amd64_raw_prefix.go ---
// Intel specifies that the r/m field is ignored for each unprefixed register
// fence encoding. The pinned decoder recognizes only the canonical r/m=0,
// and the cache-line recognizer otherwise mistakes SFENCE /7 for CLFLUSH.
// Do not strip or reinterpret any prefix here: those remain independently
// decoded and validated, including LOCK and the distinct 66 memory forms.
func decodedX86OrderingFenceInstruction(code []byte, mode int) (Instr, int, bool) {
	if mode != 32 && mode != 64 || len(code) < 3 || code[0] != 0x0f || code[1] != 0xae || code[2]>>6 != 3 {
		return Instr{}, 0, false
	}
	op := Op("")
	switch code[2] >> 3 & 7 {
	case 5:
		op = "LFENCE"
	case 6:
		op = "MFENCE"
	case 7:
		op = "SFENCE"
	default:
		return Instr{}, 0, false
	}
	return Instr{Op: op}, 3, true
}

// x/arch keeps invalidity in metadata that GoSyntax can erase or print as a
// standalone prefix with the real instruction in its operands. Reject before
// any width/alias rewrite. PrefixIgnored alone is not machine invalidity.
func decodedX86PrefixError(inst x86asm.Inst) error {
	for _, prefix := range inst.Prefix {
		if prefix&x86asm.PrefixInvalid != 0 {
			return fmt.Errorf("raw %s has a machine-invalid prefix 0x%02x", inst.Op, byte(prefix))
		}
	}
	for _, prefix := range inst.Prefix {
		if prefix&0xff == x86asm.PrefixLOCK && prefix&x86asm.PrefixIgnored == 0 {
			// This is valid native syntax, not invalid source. The existing
			// standalone LOCK lowerer cannot bind a printed whole RMW or its
			// atomic effect. Do not silently discard the following opcode.
			return fmt.Errorf("%w: raw LOCK %s requires its complete atomic prefix/operand effect", ErrProbeNeedsContext, inst.Op)
		}
		if prefix&(x86asm.PrefixIgnored|x86asm.PrefixImplicit) != 0 {
			continue
		}
		switch prefix {
		case x86asm.PrefixXACQUIRE, x86asm.PrefixXRELEASE, x86asm.PrefixBND:
			// GoSyntax uses only the low prefix byte for REP/REPNE. That
			// textual repeater is not the original transactional or bounds
			// effect and can leak onto a later string operation.
			return fmt.Errorf("%w: raw %s %s requires its complete native prefix effect", ErrProbeNeedsContext, prefix, inst.Op)
		}
	}
	return nil
}

// --- amd64_raw_qq_to_float.go ---
// x86RawQQToFloatForm maps opcode and mandatory prefix to the Go 1.27
// QWORD-to-PS/PD optabs. PS narrows the Y/Z destination by one vector width.
func x86RawQQToFloatForm(p x86RawVectorEncoding) (base Op, narrow bool, ok bool) {
	switch {
	case p.opcode == 0x5b && p.pp == 0:
		return "VCVTQQ2PS", true, true
	case p.opcode == 0x7a && p.pp == 3:
		return "VCVTUQQ2PS", true, true
	case p.opcode == 0xe6 && p.pp == 2:
		return "VCVTQQ2PD", false, true
	case p.opcode == 0x7a && p.pp == 2:
		return "VCVTUQQ2PD", false, true
	default:
		return "", false, false
	}
}

// decodedX86RawQQToFloatInstruction handles all four EVEX QWORD-to-PS/PD
// conversion families, including every X/Y/Z, K-mask, broadcast, and
// maximum-width embedded-rounding form.
func decodedX86RawQQToFloatInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || !p.evex || !p.w || p.mapNumber != 1 {
		return Instr{}, 0, false, nil
	}
	if _, _, known := x86RawQQToFloatForm(p); !known {
		return Instr{}, 0, false, nil
	}
	return decodedX86PackedNumericConversionInstruction(code, mode)
}

// --- amd64_raw_round.go ---
// decodedX86RawVEXRoundInstruction implements Go's four VROUND PS/PD/SS/SD
// opcode rows. The packed forms reserve vvvv; scalar forms use it as their
// upper-lane source. Every form has a trailing imm8.
func decodedX86RawVEXRoundInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || p.mapNumber != 3 || p.pp != 1 || p.opcode < 0x08 || p.opcode > 0x0b {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("VROUND: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.evex || p.w || p.addressOverride {
		return fail("requires VEX.W0 without address override")
	}
	scalar := p.opcode >= 0x0a
	if scalar && p.vectorLength != 0 || !scalar && p.upper != 0 {
		return fail("invalid scalar vector length or packed reserved vvvv")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	destinationNumber := int(code[p.modRM]>>3&7) + p.r*8
	if mode == 32 && (destinationNumber >= 8 || p.upper >= 8 || p.b != 0 || p.x != 0) {
		return fail("extended register in 32-bit mode")
	}
	width := "X"
	if p.vectorLength != 0 {
		width = "Y"
	}
	source, consumed, err := decodedX86VEXVectorRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, width)
	if err != nil {
		return Instr{}, 0, true, err
	}
	immIndex := p.modRM + consumed
	if len(code) <= immIndex {
		return fail("missing imm8")
	}
	args := []Operand{{Kind: OpImm, Imm: int64(code[immIndex])}, source}
	if scalar {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", p.upper))})
	}
	args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", width, destinationNumber))})
	op := [...]Op{"VROUNDPS", "VROUNDPD", "VROUNDSS", "VROUNDSD"}[p.opcode-0x08]
	printed := make([]string, len(args))
	for index := range args {
		printed[index] = args[index].String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(printed, ", "))}, immIndex + 1, true, nil
}

// --- amd64_raw_sad.go ---
// Go 1.27 has three vector SAD encodings: VPSADBW is 66/0F/F6 in
// VEX X/Y and EVEX X/Y/Z, VMPSADBW is VEX 66/0F3A/42 with imm8 in X/Y,
// and VDBPSADBW is the corresponding EVEX X/Y/Z immediate form with an
// optional writemask. Legacy PSADBW and MPSADBW use the x86asm path.
func decodedX86RawPackedSADInstruction(code []byte, mode int) (Instr, int, bool, error) {
	return decodedX86RawPackedSADInstructionWithMemory(code, mode, x86RawMemoryDecoder{})
}

func decodedX86RawPackedSADInstructionWithMemory(code []byte, mode int, memory x86RawMemoryDecoder) (Instr, int, bool, error) {
	p, recognized := decodeX86RawVectorEncoding(code)
	if !recognized || p.pp != 1 {
		return Instr{}, 0, false, nil
	}
	var op Op
	withImmediate := false
	switch {
	case p.mapNumber == 1 && p.opcode == 0xf6:
		op = "VPSADBW"
	case p.mapNumber == 3 && p.opcode == 0x42 && !p.evex:
		op, withImmediate = "VMPSADBW", true
	case p.mapNumber == 3 && p.opcode == 0x42 && p.evex:
		op, withImmediate = "VDBPSADBW", true
	default:
		return Instr{}, 0, false, nil
	}
	if p.w && op == "VDBPSADBW" {
		return Instr{}, 0, true, fmt.Errorf("%s: invalid W bit", op)
	}
	if !p.evex && p.vectorLength == 2 {
		return Instr{}, 0, true, fmt.Errorf("%s: VEX does not encode Z registers", op)
	}
	if p.broadcast || p.mask != 0 && op != "VDBPSADBW" {
		return Instr{}, 0, true, fmt.Errorf("%s: invalid broadcast or writemask form", op)
	}
	ins, length, known, err := decodedX86BinaryVectorOperandsWithMemory(code, p, mode, op, 16, memory)
	if err != nil || !withImmediate {
		return ins, length, known, err
	}
	return decodedX86VectorLeadingImm8(code, ins, length)
}

// --- amd64_raw_scalar_broadcast.go ---
// Go's _yvbroadcastss/_yvbroadcastsd tables share the typed VEX/EVEX
// prefix grammar. The scalar input width, output width and mask are separate
// axes: SD has no 128-bit destination, and disp8 scales by scalar input size.
func decodedX86ScalarBroadcastInstruction(code []byte, mode int) (Instr, int, bool, error) {
	return decodedX86ScalarBroadcastInstructionWithMemory(code, mode, x86RawMemoryDecoder{})
}

func decodedX86ScalarBroadcastInstructionWithMemory(code []byte, mode int, memory x86RawMemoryDecoder) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || p.mapNumber != 2 || (p.opcode != 0x18 && p.opcode != 0x19) {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("scalar broadcast: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if p.pp != 1 || p.upper != 0 || p.broadcast {
		return fail("reserved prefix, vvvv/V' or broadcast field")
	}
	double := p.opcode == 0x19
	if p.vectorLength > 2 || double && p.vectorLength == 0 {
		return fail("invalid vector width")
	}
	if p.evex {
		if !p.fixed || p.w != double {
			return fail("invalid EVEX fixed or width bit")
		}
	} else if p.w {
		return fail("VEX.W must be zero")
	}
	if p.zero && p.mask == 0 {
		return fail("zeroing requires a nonzero mask")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	if mode == 32 && (p.r != 0 || p.b != 0 || p.x != 0) {
		return fail("extended register in 32-bit mode")
	}
	op, bytes := Op("VBROADCASTSS"), 4
	if double {
		op, bytes = "VBROADCASTSD", 8
	}
	var source Operand
	var size int
	var err error
	if p.evex {
		source, size, err = memory.evex(code[p.modRM:], mode, p.b, p.x, p.segment, "X", bytes)
	} else {
		source, size, err = memory.vex(code[p.modRM:], mode, p.b, p.x, p.segment, "X")
	}
	if err != nil {
		return Instr{}, 0, true, err
	}
	reg := int(code[p.modRM]>>3&7) + p.r*8
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", []string{"X", "Y", "Z"}[p.vectorLength], reg))}
	args := []Operand{source, destination}
	printed := source.String() + ", " + destination.String()
	if p.mask != 0 {
		mask := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", p.mask))}
		args = []Operand{source, mask, destination}
		printed = source.String() + ", " + mask.String() + ", " + destination.String()
	}
	if p.zero {
		op += ".Z"
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, printed)}, p.modRM + size, true, nil
}

// --- amd64_raw_scalar_flag_compare.go ---
// Go's four _yvcomisd entries share X/m,X and EVEX register-only SAE.
// Prefix fields stay typed: EVEX.b means SAE here, never memory broadcast;
// disp8 scales by the scalar width. VEX W and EVEX LL are ignored. Intel
// SDM COMISS/UCOMISS explicitly warns that VEX.L=1 can behave unpredictably
// across processor generations; decoder acceptance is not a portable opcode
// contract and cannot authorize changing those original bytes to VEX.L=0.
func decodedX86ScalarFlagCompareInstruction(code []byte, mode int) (Instr, int, bool, error) {
	return decodedX86ScalarFlagCompareInstructionWithMemory(code, mode, x86RawMemoryDecoder{})
}

func decodedX86ScalarFlagCompareInstructionWithMemory(code []byte, mode int, memory x86RawMemoryDecoder) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || p.mapNumber != 1 || (p.opcode != 0x2e && p.opcode != 0x2f) {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("scalar flag compare: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if (p.pp != 0 && p.pp != 1) || p.upper != 0 || p.mask != 0 || p.zero {
		return fail("reserved prefix, vvvv/V', mask or zeroing field")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	double := p.pp == 1
	if p.evex && (!p.fixed || p.w != double) {
		return fail("invalid EVEX fixed or scalar width bit")
	}
	if p.broadcast && code[p.modRM]>>6 != 3 {
		return fail("SAE requires a register source")
	}
	if mode == 32 && (p.r != 0 || p.b != 0 || p.x != 0) {
		return fail("extended register in 32-bit mode")
	}
	op := Op("VCOMISS")
	if p.opcode == 0x2e {
		op = "VUCOMISS"
	}
	bytes := 4
	if double {
		op = op[:len(op)-1] + "D"
		bytes = 8
	}
	if p.broadcast {
		op += ".SAE"
	}
	var source Operand
	var size int
	var err error
	if p.evex {
		source, size, err = memory.evex(code[p.modRM:], mode, p.b, p.x, p.segment, "X", bytes)
	} else {
		source, size, err = memory.vex(code[p.modRM:], mode, p.b, p.x, p.segment, "X")
	}
	if err != nil {
		return Instr{}, 0, true, err
	}
	if !p.evex && p.vectorLength != 0 {
		return Instr{}, 0, true, fmt.Errorf("%w: scalar flag comparison VEX.L=1 lacks a portable physical opcode contract", ErrProbeNeedsContext)
	}
	dst := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", int(code[p.modRM]>>3&7)+p.r*8))}
	return Instr{Op: op, Args: []Operand{source, dst}, Raw: fmt.Sprintf("%s %s, %s", op, source.String(), dst.String()),
		x86ScalarFlagCompareEVEX: p.evex,
	}, p.modRM + size, true, nil
}

// --- amd64_raw_scalar_reciprocal.go ---
// Intel RCPSS/RSQRTSS share legacy F3.0F and VEX.LIG.F3.0F.WIG
// register/m32 rows. Ignored W/L bits do not widen the selected scalar or
// change the upper source. EVEX belongs to other estimate families.
func decodedX86RawScalarReciprocalInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, vector := decodeX86RawVectorEncoding(code)
	if vector {
		if p.mapNumber != 1 || p.pp != 2 || p.opcode != 0x52 && p.opcode != 0x53 {
			return Instr{}, 0, false, nil
		}
	} else {
		i := 0
		mandatory := false
		for i < len(code) {
			switch code[i] {
			case 0x64:
				p.segment = FS
			case 0x65:
				p.segment = GS
			case 0x67:
				p.addressOverride = true
			case 0xf3:
				mandatory = true
			default:
				goto legacy
			}
			i++
		}
	legacy:
		rex := byte(0)
		if i < len(code) && code[i]&0xf0 == 0x40 {
			rex = code[i]
			i++
		}
		if !mandatory || len(code) < i+2 || code[i] != 0x0f || code[i+1] != 0x52 && code[i+1] != 0x53 {
			return Instr{}, 0, false, nil
		}
		p.opcode, p.modRM = int(code[i+1]), i+2
		p.r, p.x, p.b = int(rex>>2&1), int(rex>>1&1), int(rex&1)
		if mode == 32 && rex != 0 {
			return Instr{}, 0, true, fmt.Errorf("scalar reciprocal: REX unavailable in 32-bit mode")
		}
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("scalar reciprocal: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.evex || p.addressOverride {
		return fail("EVEX or address-size override has no scalar estimate source contract")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	if mode == 32 && (p.r != 0 || p.x != 0 || p.b != 0 || p.upper >= 8) {
		return fail("extended physical register in 32-bit mode")
	}
	source, consumed, err := decodedX86VEXVectorRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, "X")
	if err != nil {
		return Instr{}, 0, true, err
	}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", int(code[p.modRM]>>3&7)+p.r*8))}
	op := Op("RCPSS")
	if p.opcode == 0x52 {
		op = "RSQRTSS"
	}
	args := []Operand{source, destination}
	printed := source.String() + ", " + destination.String()
	if vector {
		op = "V" + op
		base := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", p.upper))}
		args = []Operand{source, base, destination}
		printed = source.String() + ", " + base.String() + ", " + destination.String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, printed)}, p.modRM + consumed, true, nil
}

// --- amd64_raw_segment_prefixes.go ---
// x86RawSegmentPrefixes retains physical prefix observations without deciding
// whether a particular instruction or source mode accepts them.
func x86RawSegmentPrefixes(code []byte) (length int, segment Reg, addressOverride bool) {
	for length < len(code) {
		switch code[length] {
		case 0x64:
			segment = FS
		case 0x65:
			segment = GS
		case 0x67:
			addressOverride = true
		default:
			return
		}
		length++
	}
	return
}

// --- amd64_raw_svm.go ---
// decodedX86SystemManagementInstruction covers AMD's fixed 0F 01 D8-DF
// system-management family and Intel's matching KVM hypercall, VMCALL.
// golang.org/x/arch/x86asm does not decode
// these privileged instructions, so packages conventionally spell them as
// Plan 9 BYTE directives even though LLVM 22 can assemble their mnemonics.
func decodedX86SystemManagementInstruction(code []byte) (Instr, int, bool) {
	if len(code) < 3 || code[0] != 0x0f || code[1] != 0x01 {
		return Instr{}, 0, false
	}
	if code[2] == 0xc1 {
		return Instr{Op: "VMCALL", Raw: "VMCALL"}, 3, true
	}
	if code[2] < 0xd8 || code[2] > 0xdf {
		return Instr{}, 0, false
	}
	ops := [...]Op{
		"VMRUN",
		"VMMCALL",
		"VMLOAD",
		"VMSAVE",
		"STGI",
		"CLGI",
		"SKINIT",
		"INVLPGA",
	}
	op := ops[code[2]-0xd8]
	return Instr{Op: op, Raw: string(op)}, 3, true
}

// --- amd64_raw_text_frame.go ---
// Naked emission preserves the raw directive bytes, not obj6's additional
// Go frame, wrapper or stack-split prologue. Keep this source boundary explicit
// even when the body's bytes are data rather than decodable instructions.
func validateX86AddressSensitiveRawText(fn Func, goarch string) error {
	if fn.FrameSize != 0 || fn.ArgSize != 0 {
		return fmt.Errorf("%w: address-sensitive raw TEXT needs its source Go frame/argument transport contract", ErrProbeNeedsContext)
	}
	if len(fn.Instrs) == 0 || fn.Instrs[0].Op != OpTEXT {
		return fmt.Errorf("%w: address-sensitive raw TEXT needs an actual source TEXT header", ErrProbeNeedsContext)
	}
	_, rest := splitOpcode(fn.Instrs[0].Raw)
	parts := strings.Split(rest, ",")
	if len(parts) != 2 && len(parts) != 3 {
		return fmt.Errorf("%w: address-sensitive raw TEXT needs a resolved source header", ErrProbeNeedsContext)
	}
	if !strings.HasPrefix(strings.TrimSpace(parts[len(parts)-1]), "$") {
		return fmt.Errorf("%w: address-sensitive raw TEXT needs a known source frame", ErrProbeNeedsContext)
	}
	frame, args, err := parseTEXTFrame(parts)
	if err != nil || frame != fn.FrameSize || args != fn.ArgSize {
		return fmt.Errorf("%w: address-sensitive raw TEXT source frame differs from its retained metadata", ErrProbeNeedsContext)
	}
	var flags uint64
	if len(parts) == 3 {
		expression := globlFlagName.ReplaceAllStringFunc(parts[1], func(name string) string {
			if value, known := goTextFlagValues[name]; known {
				return value
			}
			return name
		})
		var known bool
		flags, known = parseImmExpr(strings.TrimSpace(expression))
		if !known {
			return fmt.Errorf("%w: address-sensitive raw TEXT flags need actual Go source context", ErrProbeNeedsContext)
		}
	}
	if flags & ^uint64(2|4|512) != 0 {
		return fmt.Errorf("%w: address-sensitive raw TEXT requires unmodeled Go prologue/entry flags", ErrProbeNeedsContext)
	}
	if goarch == "386" && flags&4 == 0 {
		return fmt.Errorf("%w: address-sensitive 386 raw TEXT cannot omit Go's stack-split prologue", ErrProbeNeedsContext)
	}
	return nil
}

// --- amd64_raw_unaligned_load.go ---
func decodedX86VEXUnalignedLoadInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || p.mapNumber != 1 || p.opcode != 0xf0 || p.pp != 3 {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("VLDDQU: %s", message)
	}
	if mode != 32 && mode != 64 || p.evex || p.vectorLength > 1 || p.upper != 0 || p.addressOverride {
		return fail("invalid mode, VEX generation, length, reserved vvvv or address size")
	}
	if len(code) <= p.modRM || code[p.modRM]>>6 == 3 {
		return fail("missing or non-memory ModRM")
	}
	if mode == 32 && (p.r != 0 || p.b != 0 || p.x != 0) {
		return fail("extended register unavailable in physical mode32")
	}
	bank := []string{"X", "Y"}[p.vectorLength]
	source, size, err := decodedX86VEXVectorRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, bank)
	if err != nil {
		return Instr{}, 0, true, err
	}
	if p.modRM+size > 15 {
		return fail("instruction exceeds 15 bytes")
	}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", bank, int(code[p.modRM]>>3&7)+p.r*8))}
	ins := Instr{Op: "VLDDQU", Args: []Operand{source, destination}, x86Encoded: true}
	ins.Raw = fmt.Sprintf("VLDDQU %s,%s", source.String(), destination.String())
	return ins, p.modRM + size, true, nil
}

// --- amd64_raw_variable_shift.go ---
// Go has five VEX+EVEX D/Q members and four EVEX-only W/Q members.
// All use per-element counts, not the scalar count of VPSLL/PSRL/PSRA.
func decodedX86PerLaneVariableShiftInstruction(code []byte, mode int) (Instr, int, bool, error) {
	return decodedX86PerLaneVariableShiftInstructionWithMemory(code, mode, x86RawMemoryDecoder{})
}

func decodedX86PerLaneVariableShiftInstructionWithMemory(code []byte, mode int, memory x86RawMemoryDecoder) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	// F3.0F38 opcodes 10-12 are single-source narrowing instructions,
	// not a malformed 66.0F38 per-lane shift. Other wrong prefixes remain
	// owned here so callers get an explicit invalid-form diagnostic.
	if !matched || p.mapNumber != 2 || p.pp == 2 {
		return Instr{}, 0, false, nil
	}
	var op Op
	var spec amd64PerLaneVariableShiftSpec
	owned := false
	for name, candidate := range amd64PerLaneVariableShiftSpecs {
		if int(candidate.opcode) != p.opcode {
			continue
		}
		owned = true
		if p.w == (candidate.laneBits != 32) {
			op, spec = Op(name), candidate
			break
		}
	}
	if !owned {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("per-lane variable shift: %s", message)
	}
	if op == "" {
		return fail("invalid element width bit")
	}
	if !p.evex && !spec.vex {
		return fail("instruction requires EVEX encoding")
	}

	ins, consumed, known, err := decodedX86BinaryVectorOperandsWithMemory(code, p, mode, op, spec.laneBits, memory)
	if known && err == nil {
		ins.x86PackedShiftEncoding = x86RawPackedShiftVEX
		if p.evex {
			ins.x86PackedShiftEncoding = x86RawPackedShiftEVEX
		}
		ins.x86PackedShiftW = p.w
	}
	return ins, consumed, known, err
}

// --- amd64_raw_vecflags.go ---
// Go's _yvptest table has the same X/m128,X and Y/m256,Y grammar for all
// three VEX vector-test instructions. Legacy PTEST uses the same two-operand
// shape but is decoded by x/arch's existing SSE path.
var x86RawVectorTestOpcodes = map[int]Op{
	0x17: "VPTEST",
	0x0e: "VTESTPS",
	0x0f: "VTESTPD",
}

func decodedX86VEXVectorTestInstruction(code []byte, mode int) (Instr, int, bool, error) {
	return decodedX86VEXVectorTestInstructionWithMemory(code, mode, x86RawMemoryDecoder{})
}

func decodedX86VEXVectorTestInstructionWithMemory(code []byte, mode int, memory x86RawMemoryDecoder) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || p.evex || p.mapNumber != 2 {
		return Instr{}, 0, false, nil
	}
	op, recognized := x86RawVectorTestOpcodes[p.opcode]
	if !recognized {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("VEX vector test: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if p.pp != 1 || p.upper != 0 || p.vectorLength > 1 {
		return fail("invalid 66 prefix, reserved vvvv or vector length")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	if mode == 32 && (p.r != 0 || p.x != 0 || p.b != 0) {
		return fail("extended register in 32-bit mode")
	}
	width := "X"
	if p.vectorLength == 1 {
		width = "Y"
	}
	source, size, err := memory.vex(code[p.modRM:], mode, p.b, p.x, p.segment, width)
	if err != nil {
		return Instr{}, 0, true, err
	}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", width, int(code[p.modRM]>>3&7)+p.r*8))}
	return Instr{
		Op:   op,
		Args: []Operand{source, destination},
		Raw:  fmt.Sprintf("%s %s, %s", op, source.String(), destination.String()),
	}, p.modRM + size, true, nil
}

// --- amd64_raw_vector_zero.go ---
// The pinned x/arch decoder calls both VEX.L variants VZEROUPPER and accepts
// reserved pp/vvvv values. Decode this complete zero-operand family before
// generic fallback, binding the actual bytes rather than its printed opcode.
func decodedX86VectorZeroInstruction(code []byte, mode int) (Instr, int, bool, error) {
	i, forbidden := 0, false
	for i < len(code) {
		prefix := code[i]
		switch {
		case prefix == 0x26 || prefix == 0x2e || prefix == 0x36 || prefix == 0x3e || prefix == 0x64 || prefix == 0x65 || prefix == 0x67:
		case prefix == 0x66 || prefix == 0xf0 || prefix == 0xf2 || prefix == 0xf3 || mode == 64 && prefix >= 0x40 && prefix <= 0x4f:
			forbidden = true
		default:
			goto prefixEnd
		}
		i++
	}
prefixEnd:
	if i >= len(code) || code[i] != 0xc4 && code[i] != 0xc5 {
		return Instr{}, 0, false, nil
	}
	payload, opcode, length := i+1, i+2, i+3
	if code[i] == 0xc4 {
		payload, opcode, length = i+2, i+3, i+4
	}
	if opcode >= len(code) {
		return Instr{}, 0, false, nil
	}
	if mode == 32 && code[i+1]&0xc0 != 0xc0 {
		// These bytes are legacy LES/LDS, not a mode32 VEX prefix.
		return Instr{}, 0, false, nil
	}
	if code[opcode] != 0x77 || code[i] == 0xc4 && code[i+1]&31 != 1 {
		return Instr{}, 0, false, nil
	}
	if mode != 32 && mode != 64 || forbidden || length > 15 || code[payload]&3 != 0 || code[payload]&0x78 != 0x78 {
		return Instr{}, 0, true, fmt.Errorf("reserved raw VEX vector-zero encoding %x in mode%d", code[:length], mode)
	}
	for op, spec := range x86VectorZeroSpecs {
		if spec.vexLength == code[payload]>>2&1 {
			return Instr{Op: op, Raw: string(op)}, length, true, nil
		}
	}
	return Instr{}, 0, true, fmt.Errorf("unregistered raw VEX vector-zero length")
}

// --- amd64_raw_vpinsr_evex.go ---
// Go 1.27's _yvpinsrb table has one EVEX.128 row for each scalar width.
// VEX forms use decodedX86VPINSRInstruction; the EVEX row extends X
// base/destination registers to X31 and scales disp8 by the scalar width.
func decodedX86EVEXVPINSRInstruction(code []byte, mode int) (Instr, int, bool, error) {
	return decodedX86EVEXVPINSRInstructionWithMemory(code, mode, x86RawMemoryDecoder{})
}

func decodedX86EVEXVPINSRInstructionWithMemory(code []byte, mode int, memory x86RawMemoryDecoder) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || !p.evex || p.pp != 1 {
		return Instr{}, 0, false, nil
	}
	op := Op("")
	laneBytes := 0
	switch {
	case p.mapNumber == 3 && p.opcode == 0x20 && !p.w:
		op, laneBytes = "VPINSRB", 1
	case p.mapNumber == 1 && p.opcode == 0xc4 && !p.w:
		op, laneBytes = "VPINSRW", 2
	case p.mapNumber == 3 && p.opcode == 0x22 && !p.w:
		op, laneBytes = "VPINSRD", 4
	case p.mapNumber == 3 && p.opcode == 0x22 && p.w:
		op, laneBytes = "VPINSRQ", 8
	default:
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("raw EVEX %s: %s", op, message)
	}
	if mode != 64 {
		return fail("Go assembler exposes this EVEX form only on amd64")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if !p.fixed || p.vectorLength != 0 || p.mask != 0 || p.zero || p.broadcast {
		return fail("invalid EVEX fixed, length, mask, zeroing or broadcast bits")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	modRM := code[p.modRM]
	source, consumed, err := memory.scalar(
		code[p.modRM:], mode, p.b, p.x, p.segment, laneBytes,
	)
	if err != nil {
		return Instr{}, 0, true, err
	}
	immediateIndex := p.modRM + consumed
	if len(code) <= immediateIndex {
		return fail("missing immediate byte")
	}
	immediate := Operand{Kind: OpImm, Imm: int64(code[immediateIndex])}
	base := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", p.upper))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", int(modRM>>3&7)+p.r*8))}
	args := []Operand{immediate, source, base, destination}
	return Instr{
		Op:   op,
		Args: args,
		Raw:  fmt.Sprintf("%s %s, %s, %s, %s", op, immediate.String(), source.String(), base.String(), destination.String()),
	}, immediateIndex + 1, true, nil
}
