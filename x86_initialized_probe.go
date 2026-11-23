package plan9asm

import (
	"fmt"
	"strings"
)

// InitializedMaskLogicalProbeSequence constructs a counterfactual source probe
// for the complete K-register logical family. It is not evidence about the
// original program's inputs, a source binding, or permission to access memory.
// The returned sequence explicitly initializes only the actual mask inputs and
// retains the original instruction. Callers must probe/translate it separately.
func InitializedMaskLogicalProbeSequence(goarch string, ins Instr) ([]Instr, bool, error) {
	spec, known, err := x86MaskLogicalProperties(ins.Op, ins, goarch)
	if !known || err != nil {
		return nil, known, err
	}
	if !x86ResultNamedPredicateInstruction(ins) {
		return nil, true, fmt.Errorf("initialized mask logical probe requires an exact named instruction, not raw encoding or address overrides")
	}
	inputs := 2
	if spec.kind == amd64MaskNot {
		inputs = 1
	}
	sequence := []Instr{{
		Op: "MOVL", Raw: "MOVL $3,AX",
		Args: []Operand{{Kind: OpImm, Imm: 3}, {Kind: OpReg, Reg: "AX"}},
	}}
	seen := make(map[Reg]bool)
	for _, input := range ins.Args[:inputs] {
		if seen[input.Reg] {
			continue
		}
		seen[input.Reg] = true
		sequence = append(sequence, Instr{
			Op: "KMOVD", Raw: fmt.Sprintf("KMOVD AX,%s", input.Reg),
			Args: []Operand{{Kind: OpReg, Reg: "AX"}, input},
		})
	}
	return append(sequence, ins), true, nil
}

// InitializedVectorRegisterProbeSequence builds an object-only probe for
// named x86 SIMD forms with a typed effect and register or literal operands. It
// defines the explicit registers (including masked merge destinations) and
// any implicit register reads listed in the effect. The original instruction
// is retained unchanged.
func InitializedVectorRegisterProbeSequence(goarch string, ins Instr) ([]Instr, bool, error) {
	if goarch != "386" && goarch != "amd64" || !x86ResultNamedPredicateInstruction(ins) ||
		x86Mode32VectorRegisterContext(ins, goarch) != nil {
		return nil, false, nil
	}
	inputs, memoryBytes, valid := initializedVectorOperands(goarch, ins)
	if !valid || memoryBytes != 0 {
		return nil, false, nil
	}
	return initializedVectorProbeSequence(goarch, ins, inputs)
}

// InitializedVectorMemoryProbeSequence prepares a single SIMD memory operand
// using a declared pointer parameter named memory at 0(FP).
// It keeps the original addressing expression. When a VSIB operand has no
// base register, the pointer supplies the vector of numerical indices.
func InitializedVectorMemoryProbeSequence(goarch string, ins Instr) ([]Instr, bool, error) {
	return initializedVectorMemoryProbeSequence(goarch, ins, false)
}

// InitializedVectorNumericMemoryProbeSequence uses a machine-word integer
// argument named memory at 0(FP). The exact same value supplies both address
// fields. The caller must choose a value with a valid effective address to run
// this object probe.
func InitializedVectorNumericMemoryProbeSequence(goarch string, ins Instr) ([]Instr, bool, error) {
	return initializedVectorMemoryProbeSequence(goarch, ins, true)
}

func initializedVectorMemoryProbeSequence(goarch string, ins Instr, numericAddress bool) ([]Instr, bool, error) {
	if goarch != "386" && goarch != "amd64" || !x86ResultNamedPredicateInstruction(ins) ||
		x86Mode32VectorRegisterContext(ins, goarch) != nil {
		return nil, false, nil
	}
	if form, known, err := x86VSIBProperties(ins, goarch); known {
		if numericAddress || err != nil || form.prefetch {
			return nil, false, nil
		}
		memory := form.memory.Mem
		if memory.Base == SP || memory.OffRaw != "" || memory.Segment != "" || memory.IndexExt != "" ||
			!x86MemoryDisplacementValid(memory.Off, goarch) {
			return nil, false, nil
		}
		registers := []Operand{form.data, form.mask}
		index := Operand{Kind: OpReg, Reg: memory.Index}
		var activeMask Reg
		if !form.evex {
			activeMask = form.mask.Reg
		}
		if memory.Base != "" {
			return initializedVectorMemorySequence(goarch, ins, memory.Base, append(registers, index), activeMask)
		}
		// Load the complete index from the caller so the object contains
		// an actual data-dependent address, including sign extension and scale.
		sequence, known, err := initializedVectorMemorySequence(goarch, ins, AX, registers, activeMask)
		if !known || err != nil {
			return nil, known, err
		}
		indices := Operand{Kind: OpMem, Mem: MemRef{Base: AX}}
		return append(sequence[:len(sequence)-1], x86ProbeInstruction("VMOVUPS", indices, index), ins), true, nil
	}
	memory, memoryIndex := initializedOrdinaryProbeMemory(goarch, ins)
	if memoryIndex < 0 || numericAddress != (memory.Base == memory.Index) {
		return nil, false, nil
	}
	base, valid := initializedX86GPRegister(goarch, Operand{Kind: OpReg, Reg: memory.Base})
	if !numericAddress && !valid && x86DataBPPackedRead(ins, goarch) == memoryIndex {
		base, valid = BP, true
	}
	if !valid {
		return nil, false, nil
	}
	inputs, memoryBytes, valid := initializedVectorOperands(goarch, ins)
	if !valid || memoryBytes < 1 || memoryBytes > 64 {
		return nil, false, nil
	}
	registers := make([]Operand, 0, len(inputs)+1)
	for _, input := range inputs {
		if input.Kind == OpMem {
			continue
		}
		if numericAddress {
			if root, valid := initializedX86GPRegister(goarch, input); valid && root == memory.Base {
				continue // The argument also supplies this explicit register view.
			}
		}
		registers = append(registers, input)
	}
	if memory.Index != "" && !numericAddress {
		registers = append(registers, Operand{Kind: OpReg, Reg: memory.Index})
	}
	return initializedVectorMemorySequence(goarch, ins, base, registers, "")
}

func initializedVectorMemorySequence(goarch string, ins Instr, base Reg, registers []Operand, activeMask Reg) ([]Instr, bool, error) {
	for _, input := range registers {
		if root, valid := initializedX86GPRegister(goarch, input); valid && root == base {
			return nil, false, nil // The base and an independent numeric input cannot share a register.
		}
	}
	sequence, known, err := initializedVectorProbeSequence(goarch, ins, registers)
	if !known || err != nil {
		return nil, known, err
	}
	sequence = sequence[:len(sequence)-1]
	if activeMask != "" {
		// VEX gather uses vector lane sign bits. Keep the accesses active
		// instead of compiling a fixture with an all-zero mask.
		mask := Operand{Kind: OpReg, Reg: activeMask}
		sequence = append(sequence, x86ProbeInstruction("VPCMPEQD", mask, mask, mask))
	}
	return append(sequence, initializedProbeMemoryBinding(goarch, base), ins), true, nil
}

func initializedVectorProbeSequence(goarch string, ins Instr, inputs []Operand) ([]Instr, bool, error) {
	var widths [32]int
	var masks [8]bool
	var gp []Reg
	seenGP := make(map[Reg]bool)
	hasSIMD := false
	add := func(operand Operand) bool {
		if operand.Kind == OpImm {
			return operand.ImmRaw == ""
		}
		if operand.Kind != OpReg {
			return false
		}
		reg := operand.Reg
		width := amd64VectorByteWidth(reg)
		if index, vector := amd64VectorRegisterIndex(reg, width); vector {
			if index >= len(widths) || goarch == "386" && index >= 8 {
				return false
			}
			if width > widths[index] {
				widths[index] = width
			}
			hasSIMD = true
			return true
		}
		if index, mask := amd64ParseKReg(reg); mask {
			masks[index] = true
			hasSIMD = true
			return true
		}
		root, valid := initializedX86GPRegister(goarch, operand)
		if !valid {
			return false
		}
		if !seenGP[root] {
			gp = append(gp, root)
			seenGP[root] = true
		}
		return true
	}
	for _, operand := range inputs {
		if !add(operand) {
			return nil, false, nil
		}
	}
	if !hasSIMD {
		return nil, false, nil
	}

	var sequence []Instr
	for index, used := range masks {
		if !used {
			continue
		}
		if len(sequence) == 0 {
			sequence = append(sequence, x86ProbeInstruction("MOVL", Operand{Kind: OpImm, Imm: -1}, Operand{Kind: OpReg, Reg: AX}))
		}
		mask := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", index))}
		sequence = append(sequence, x86ProbeInstruction("KMOVD", Operand{Kind: OpReg, Reg: AX}, mask))
	}
	for _, reg := range gp {
		sequence = append(sequence, x86ProbeInstruction("MOVL", Operand{Kind: OpImm, Imm: 1}, Operand{Kind: OpReg, Reg: reg}))
	}
	for index, width := range widths {
		if width == 0 {
			continue
		}
		switch {
		case index >= 16 || width == 64:
			z := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d", index))}
			sequence = append(sequence, x86ProbeInstruction("VPXORD", z, z, z))
		case width == 32:
			y := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("Y%d", index))}
			sequence = append(sequence, x86ProbeInstruction("VXORPS", y, y, y))
		default:
			x := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", index))}
			sequence = append(sequence, x86ProbeInstruction("XORPS", x, x))
		}
	}
	return append(sequence, ins), true, nil
}

func initializedVectorOperands(goarch string, ins Instr) ([]Operand, int64, bool) {
	// The typed floating compare parser has already validated the literal.
	// In the legacy spelling a bare predicate is an OpSym in the parsed
	// source. Take only the form's actual inputs and retain that spelling.
	if form, known, err := x86FloatCompareProperties(ins, goarch); known {
		if err != nil {
			return nil, 0, false
		}
		inputs := []Operand{ins.Args[form.first], ins.Args[form.second]}
		if form.mask >= 0 {
			inputs = append(inputs, ins.Args[form.mask])
		}
		return inputs, int64(form.memoryBytes), true
	}

	effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, goarch)
	if !known {
		return initializedExplicitSIMDOperands(goarch, ins)
	}
	if err != nil || effect.flagsRead != 0 {
		return nil, 0, false
	}
	if effect.dynamicMemory {
		// Compact/expand accesses a mask-selected prefix. The full vector
		// width bounds that prefix for a probe using a declared pointer.
		form, known, err := x86PackedCompactProperties(ins.Op, ins, goarch)
		if !known || err != nil || form.memory < 0 || form.undefinedOpcode() {
			return nil, 0, false
		}
		return ins.Args, int64(form.byteWidth), true
	}
	inputs := make([]Operand, 0, len(ins.Args)+len(effect.operands))
	for _, operand := range ins.Args {
		// The typed effects below already enumerate the actual register
		// reads of four-source ranges, including the encoded alignment.
		if operand.Kind != OpRegList {
			inputs = append(inputs, operand)
		}
	}
	var memoryBytes int64
	for _, input := range effect.operands {
		if input.operand.Kind == OpMem || input.operand.Kind == OpSym {
			if input.index < 0 || input.index >= len(ins.Args) || input.width <= 0 ||
				memoryBytes != 0 && memoryBytes != input.width {
				return nil, 0, false
			}
			memoryBytes = input.width
		}
		if input.read {
			inputs = append(inputs, input.operand)
		}
	}
	return inputs, memoryBytes, true
}

// These complete family grammars expose every register in the original
// operand list, including a merge destination. Their validated memory tuple
// must stay independent of the output vector width.
func initializedExplicitSIMDOperands(goarch string, ins Instr) ([]Operand, int64, bool) {
	if f, known, err := x86PackedShiftProperties(ins.Op, ins, goarch); known {
		if err != nil || f.mmx {
			return nil, 0, false
		}
		inputs := append([]Operand(nil), ins.Args...)
		inputs[f.count] = f.countOperand
		return inputs, int64(f.memoryBytes), true
	}
	if f, known, err := x86BroadcastProperties(ins.Op, ins, goarch); known {
		width := int64(0)
		if err == nil && isAMD64MemoryOperand(ins.Args[0]) {
			width = int64(f.sourceBytes)
		}
		return ins.Args, width, err == nil
	}
	if f, known, err := x86FloatArithmeticProperties(ins, goarch, ""); known {
		return ins.Args, int64(f.memoryBytes), err == nil
	}
	if f, known, err := amd64PackedVectorMoveProperties(ins, goarch); known {
		return ins.Args, initializedSIMDMemoryWidth(f.memory, f.byteWidth), err == nil && !f.undefinedOpcode()
	}
	if f, known, err := x86InsertExtractProperties(ins, goarch); known {
		return ins.Args, initializedSIMDMemoryWidth(f.memory, f.spec.chunk), err == nil && !f.undefinedOpcode()
	}
	if f, known, err := x86ScalarLaneProperties(ins, goarch); known {
		return ins.Args, initializedSIMDMemoryWidth(f.memory, f.bits/8), err == nil
	}
	if f, known, err := amd64ScalarVectorMoveProperties(ins, goarch); known {
		return ins.Args, initializedSIMDMemoryWidth(f.memory, f.spec.bits/8), err == nil
	}
	if f, known, err := x86GPSIMDTransferProperties(ins, goarch); known {
		return ins.Args, initializedSIMDMemoryWidth(f.memory, f.bits/8), err == nil && !f.mmx
	}
	const packedFamilies = x86PackedArithmeticAdd | x86PackedArithmeticSubtract | x86PackedArithmeticLowMultiply
	if f, known, err := x86PackedArithmeticProperties(ins.Op, ins, goarch, packedFamilies); known {
		return ins.Args, int64(f.memoryBytes), err == nil && !f.mmx
	}
	if f, known, err := x86PackedLogicalProperties(ins, goarch); known {
		return ins.Args, int64(f.memoryBytes), err == nil && !f.mmx
	}
	if f, _, known, err := x86FixedVectorValueProperties(ins, goarch); known {
		return ins.Args, int64(f.memoryBytes), err == nil && !f.mmx
	}
	if f, known, err := x86PackedNarrowProperties(ins, goarch); known {
		return ins.Args, int64(f.memoryBytes), err == nil && !f.mmx
	}
	if f, known, err := x86PackedUnpackProperties(ins, goarch); known {
		return ins.Args, int64(f.memoryBytes), err == nil && !f.mmx
	}
	if f, known, err := x86DuplicateMoveProperties(ins.Op, ins, goarch); known {
		return ins.Args, int64(f.memoryBytes), err == nil
	}
	if f, known, err := x86SignedPackedFloatProperties(ins, goarch); known {
		return ins.Args, int64(f.memoryBytes), err == nil && !f.mmx
	}
	if f, known, err := x86SqrtProperties(ins, goarch); known {
		return ins.Args, int64(f.memoryBytes), err == nil
	}
	if f, known, err := x86PackedSADProperties(ins, goarch); known {
		return ins.Args, int64(f.memoryBytes), err == nil
	}
	if f, known, err := x86NonTemporalVectorProperties(ins.Op, ins, goarch); known {
		return ins.Args, int64(f.move.byteWidth), err == nil && !f.trap
	}
	if _, known, err := x86MaskValueProperties(ins.Op, ins, goarch); known {
		return ins.Args, 0, err == nil
	}
	if _, known, err := x86MaskVectorProperties(ins, goarch); known {
		return ins.Args, 0, err == nil
	}
	return nil, 0, false
}

func initializedSIMDMemoryWidth(memory, bytes int) int64 {
	if memory < 0 {
		return 0
	}
	return int64(bytes)
}

// InitializedScalarRegisterProbeSequence constructs an object-only probe for
// register-only GP forms. Implicit accumulator multiplication and division
// have dedicated inputs. Other families use their typed operand and FLAGS
// dependencies. The original instruction is retained unchanged.
func InitializedScalarRegisterProbeSequence(goarch string, ins Instr) ([]Instr, bool, error) {
	if goarch != "386" && goarch != "amd64" || !x86ResultNamedPredicateInstruction(ins) {
		return nil, false, nil
	}
	move := Op("MOVL")
	if goarch == "amd64" {
		move = "MOVQ"
	}
	seed := func(reg Reg, value int64) Instr {
		return x86ProbeInstruction(move, Operand{Kind: OpImm, Imm: value}, Operand{Kind: OpReg, Reg: reg})
	}
	if form, known, err := x86ConditionalSetProperties(ins.Op, ins, goarch); known {
		if _, valid := initializedX86GPRegister(goarch, form.destination); err != nil || !valid {
			return nil, false, nil
		}
		ax := Operand{Kind: OpReg, Reg: AX}
		return []Instr{seed(AX, 1), x86ProbeInstruction("CMPL", ax, ax), ins}, true, nil
	}
	if form, known, err := x86ImplicitMultiplyProperties(ins.Op, ins, goarch); known {
		root, valid := initializedX86GPRegister(goarch, form.source)
		if err != nil || !valid {
			return nil, false, nil
		}
		sequence := []Instr{seed(AX, 0x101)}
		if root != AX {
			sequence = append(sequence, seed(root, 0x101))
		}
		return append(sequence, ins), true, nil
	}
	form, known, err := x86ImplicitDivideProperties(ins.Op, ins, goarch)
	if !known {
		return initializedX86GPEffectProbe(goarch, ins, seed)
	}
	root, valid := initializedX86GPRegister(goarch, form.source)
	if err != nil || !valid {
		return nil, false, nil
	}

	// A divisor that aliases the high half cannot have the ordinary
	// positive-dividend setup. Signed -1/-1 fits. Unsigned division of
	// this shape always faults; retain that instruction in the object.
	highHalf := form.spec.bits == 8 && strings.EqualFold(string(form.source.Reg), "AH") || form.spec.bits != 8 && root == DX
	low, high := int64(1), int64(0)
	if form.spec.signed && highHalf {
		low, high = -1, -1
	}
	sequence := []Instr{seed(AX, low)}
	if form.spec.bits != 8 {
		sequence = append(sequence, seed(DX, high))
	}
	if root != AX && !highHalf {
		// Both the low and high byte spellings of this root see 1.
		sequence = append(sequence, seed(root, 0x101))
	}
	return append(sequence, ins), true, nil
}

func initializedX86GPEffectProbe(goarch string, ins Instr, seed func(Reg, int64) Instr) ([]Instr, bool, error) {
	// Source spelling must still be register-only, including any operands
	// that the byte dependencies omit (for example, zeroing or count zero).
	for _, operand := range ins.Args {
		if operand.Kind == OpImm && operand.ImmRaw == "" && !operand.ImmIsFloat {
			continue
		}
		if _, valid := initializedX86GPRegister(goarch, operand); !valid {
			return nil, false, nil
		}
	}
	effect, valid := initializedX86GPInputs(goarch, ins)
	if !valid || effect.dynamicMemory {
		return nil, false, nil
	}
	var sequence []Instr
	if effect.flagsRead != 0 {
		ax := Operand{Kind: OpReg, Reg: AX}
		sequence = append(sequence, x86ProbeInstruction("CMPL", ax, ax))
	}
	seen := make(map[Reg]bool)
	for _, input := range effect.operands {
		if input.operand.Kind == OpImm {
			continue
		}
		root, valid := initializedX86GPRegister(goarch, input.operand)
		if !valid {
			return nil, false, nil
		}
		if input.read && !seen[root] {
			// The low five/six bits give a count of two, including for a
			// variable W double shift. Every byte is initialized.
			sequence = append(sequence, seed(root, 0x01020202))
			seen[root] = true
		}
	}
	if len(sequence) == 0 {
		return nil, false, nil
	}
	return append(sequence, ins), true, nil
}

func initializedX86GPInputs(goarch string, ins Instr) (x86TypedByteEffect, bool) {
	if form, known, err := x86ScalarShiftProperties(ins.Op, ins, goarch); known {
		// The fixture supplies the variable count explicitly. Use the
		// input effect because the output effect depends on that count.
		if err != nil {
			return x86TypedByteEffect{}, false
		}
		return form.inputEffect(), true
	}
	if form, known, err := x86ScalarCompareProperties(ins.Op, ins, goarch); known {
		if err != nil {
			return x86TypedByteEffect{}, false
		}
		width := int64(form.bits / 8)
		return x86TypedByteEffect{operands: []x86TypedByteOperand{
			{index: 0, operand: form.args[0], width: width, read: true},
			{index: 1, operand: form.args[1], width: width, read: true},
		}}, true
	}
	effect, known, err := x86TypedGPByteEffect(ins.Op, ins, goarch)
	if !known {
		effect, known, err = initializedX86GPTypedRead(ins, goarch)
	}
	return effect, known && err == nil
}

// These families read a fixed memory tuple and may also consume the old
// destination. Reuse their typed effects for both independent pointer and
// shared numerical address probes.
func initializedX86GPTypedRead(ins Instr, goarch string) (x86TypedByteEffect, bool, error) {
	if effect, known, err := x86TypedBitScanByteEffect(ins, goarch); known {
		return effect, true, err
	}
	if effect, known, err := x86TypedCRC32ByteEffect(ins.Op, ins, goarch); known {
		return effect, true, err
	}
	return x86TypedSegmentQueryByteEffect(ins.Op, ins, goarch)
}

// InitializedScalarMemoryProbeSequence supplies one explicit pointer
// argument and the typed GP/FLAGS inputs of a fixed-width memory form. The
// fixture establishes neither original-source storage nor a safe divisor.
func InitializedScalarMemoryProbeSequence(goarch string, ins Instr) ([]Instr, bool, error) {
	return initializedScalarMemoryProbeSequence(goarch, ins, false)
}

// InitializedScalarNumericMemoryProbeSequence supplies a machine-word address
// when a paired native read shares its base with another numerical input.
// The caller must supply a valid effective address to execute the fixture.
func InitializedScalarNumericMemoryProbeSequence(goarch string, ins Instr) ([]Instr, bool, error) {
	return initializedScalarMemoryProbeSequence(goarch, ins, true)
}

func initializedScalarMemoryProbeSequence(goarch string, ins Instr, numericAddress bool) ([]Instr, bool, error) {
	if goarch != "386" && goarch != "amd64" || !x86ResultNamedPredicateInstruction(ins) {
		return nil, false, nil
	}
	memory, memoryIndex := initializedOrdinaryProbeMemory(goarch, ins)
	if memoryIndex < 0 {
		return nil, false, nil
	}
	base, valid := initializedX86GPRegister(goarch, Operand{Kind: OpReg, Reg: memory.Base})
	if !valid {
		return nil, false, nil
	}
	var index Reg
	if memory.Index != "" {
		index, valid = initializedX86GPRegister(goarch, Operand{Kind: OpReg, Reg: memory.Index})
		if !valid || !numericAddress && index == base {
			return nil, false, nil
		}
	}
	if numericAddress {
		_, known, err := x86ScalarArithmeticNativeReadProperties(ins, goarch)
		if !known && err == nil {
			_, known, err = initializedX86GPTypedRead(ins, goarch)
		}
		if !known || err != nil {
			return nil, false, nil
		}
	}
	for i, operand := range ins.Args {
		if i == memoryIndex || operand.Kind == OpImm && operand.ImmRaw == "" && !operand.ImmIsFloat {
			continue
		}
		if _, valid := initializedX86GPRegister(goarch, operand); !valid {
			return nil, false, nil
		}
	}

	effect, valid := initializedX86GPInputs(goarch, ins)
	if !valid {
		if load, known, err := x86ScalarNativeLoadProperties(ins.Op, ins, goarch); known && err == nil {
			// The load defines its destination, including a base register
			// that is read to form the address before being overwritten.
			_, valid = initializedX86GPRegister(goarch, Operand{Kind: OpReg, Reg: load.destination})
			effect.operands = []x86TypedByteOperand{{index: 0, operand: load.source, width: load.bytes, read: true}}
		} else if store, known, err := x86ScalarNativeStoreProperties(ins.Op, ins, goarch); known && err == nil {
			effect.operands = []x86TypedByteOperand{
				{index: 0, operand: store.source, width: store.bytes, read: true},
				{index: 1, operand: store.destination, width: store.bytes, write: true},
			}
			valid = true
		} else if form, known, err := x86ConditionalSetProperties(ins.Op, ins, goarch); known && err == nil {
			effect = x86TypedByteEffect{flagsRead: x86ByteConditionFlags(form.condition),
				operands: []x86TypedByteOperand{{index: 0, operand: form.destination, width: 1, write: true}}}
			valid = true
		} else if multiply, known, err := x86TypedImplicitMultiplyByteEffect(ins.Op, ins, goarch); known && err == nil {
			effect, valid = multiply, true
		} else if conversion, known, err := x86TypedScalarFloatIntegerByteEffect(ins.Op, ins, goarch); known && err == nil {
			effect, valid = conversion, true
		}
	}
	division, divides, err := x86ImplicitDivideProperties(ins.Op, ins, goarch)
	if divides && err == nil && division.source.Kind == OpMem {
		width := int64(division.spec.bits / 8)
		effect.operands = []x86TypedByteOperand{
			{index: 0, operand: division.source, width: width, read: true},
			{index: -1, operand: Operand{Kind: OpReg, Reg: AX}, width: width, read: true},
		}
		if width != 1 {
			effect.operands = append(effect.operands, x86TypedByteOperand{
				index: -1, operand: Operand{Kind: OpReg, Reg: DX}, width: width, read: true,
			})
		}
		valid = true
	}
	if !valid || effect.dynamicMemory {
		return nil, false, nil
	}

	move := Op("MOVL")
	if goarch == "amd64" {
		move = "MOVQ"
	}
	var sequence []Instr
	seeded := make(map[Reg]bool)
	seed := func(register Reg, value int64) {
		if !seeded[register] {
			sequence = append(sequence, x86ProbeInstruction(move, Operand{Kind: OpImm, Imm: value}, Operand{Kind: OpReg, Reg: register}))
			seeded[register] = true
		}
	}
	hasMemory, sharedBase := false, index == base
	for _, input := range effect.operands {
		if input.operand.Kind == OpMem {
			if input.index != memoryIndex || input.width < 1 || input.width > 8 {
				return nil, false, nil
			}
			hasMemory = true
			continue
		}
		if !input.read || input.operand.Kind == OpImm {
			continue
		}
		root, valid := initializedX86GPRegister(goarch, input.operand)
		if !valid || !numericAddress && root == base {
			return nil, false, nil
		}
		if root == base {
			sharedBase = true
			continue // The final machine-word argument load supplies these same bits.
		}
		value := int64(0x01020202)
		switch {
		case divides && root == DX:
			value = 0
		case divides || root == index:
			value = 1
		}
		seed(root, value)
	}
	if !hasMemory || numericAddress && !sharedBase {
		return nil, false, nil
	}
	if index != "" && index != base {
		seed(index, 1)
	}
	if effect.flagsRead != 0 {
		seed(AX, 1)
		ax := Operand{Kind: OpReg, Reg: AX}
		sequence = append(sequence, x86ProbeInstruction("CMPL", ax, ax))
	}
	return append(sequence, initializedProbeMemoryBinding(goarch, base), ins), true, nil
}

func initializedOrdinaryProbeMemory(goarch string, ins Instr) (MemRef, int) {
	index := -1
	var memory MemRef
	for i, operand := range ins.Args {
		if operand.Kind != OpMem {
			continue
		}
		candidate := operand.Mem
		if index >= 0 || candidate.Base == "" || candidate.Sym != "" || candidate.OffRaw != "" ||
			candidate.Segment != "" || candidate.IndexExt != "" || candidate.Index == "" && candidate.Scale != 0 ||
			!x86MemoryRegisterEncodingValid(candidate, goarch) {
			return MemRef{}, -1
		}
		memory, index = candidate, i
	}
	return memory, index
}

func initializedProbeMemoryBinding(goarch string, base Reg) Instr {
	move := Op("MOVQ")
	if goarch == "386" {
		move = "MOVL"
	}
	return x86ProbeInstruction(move, Operand{Kind: OpFP, FPName: "memory"}, Operand{Kind: OpReg, Reg: base})
}

func initializedX86GPRegister(goarch string, operand Operand) (Reg, bool) {
	if operand.Kind != OpReg {
		return "", false
	}
	root, valid := x86CallerGP(operand.Reg)
	return root, valid && isX86YrlRegisterForArch(root, goarch) && !x86LogicalSourceFrameRegister(root, goarch)
}

func x86ProbeInstruction(op Op, operands ...Operand) Instr {
	args := make([]string, len(operands))
	for i, operand := range operands {
		args[i] = operand.String()
	}
	return Instr{Op: op, Raw: string(op) + " " + strings.Join(args, ","), Args: operands}
}
