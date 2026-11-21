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
// The sequence keeps the exact original addressing expression. Its caller
// must supply the extent and alignment if the resulting function is executed.
func InitializedVectorMemoryProbeSequence(goarch string, ins Instr) ([]Instr, bool, error) {
	if goarch != "386" && goarch != "amd64" || !x86ResultNamedPredicateInstruction(ins) ||
		x86Mode32VectorRegisterContext(ins, goarch) != nil {
		return nil, false, nil
	}
	if form, known, err := x86VSIBProperties(ins, goarch); known {
		if err != nil || form.prefetch {
			return nil, false, nil
		}
		memory := form.memory.Mem
		if memory.OffRaw != "" || memory.Segment != "" || memory.IndexExt != "" ||
			!x86MemoryDisplacementValid(memory.Off, goarch) {
			return nil, false, nil
		}
		registers := []Operand{form.data, form.mask, {Kind: OpReg, Reg: memory.Index}}
		var activeMask Reg
		if !form.evex {
			activeMask = form.mask.Reg
		}
		return initializedVectorMemorySequence(goarch, ins, memory.Base, registers, activeMask)
	}
	var memory MemRef
	for _, operand := range ins.Args {
		if operand.Kind != OpMem {
			continue
		}
		if memory.Base != "" || operand.Mem.Base == "" || operand.Mem.Sym != "" ||
			operand.Mem.OffRaw != "" || operand.Mem.Segment != "" || operand.Mem.IndexExt != "" ||
			operand.Mem.Index == "" && operand.Mem.Scale != 0 ||
			!x86MemoryRegisterEncodingValid(operand.Mem, goarch) {
			return nil, false, nil
		}
		memory = operand.Mem
	}
	if memory.Base == "" {
		return nil, false, nil
	}
	inputs, memoryBytes, valid := initializedVectorOperands(goarch, ins)
	if !valid || memoryBytes < 1 || memoryBytes > 64 {
		return nil, false, nil
	}
	registers := make([]Operand, 0, len(inputs)+1)
	for _, input := range inputs {
		if input.Kind != OpMem {
			registers = append(registers, input)
		}
	}
	if memory.Index != "" {
		registers = append(registers, Operand{Kind: OpReg, Reg: memory.Index})
	}
	return initializedVectorMemorySequence(goarch, ins, memory.Base, registers, "")
}

func initializedVectorMemorySequence(goarch string, ins Instr, addressBase Reg, registers []Operand, activeMask Reg) ([]Instr, bool, error) {
	base, valid := initializedX86GPRegister(goarch, Operand{Kind: OpReg, Reg: addressBase})
	if !valid {
		return nil, false, nil
	}
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
	move := Op("MOVQ")
	if goarch == "386" {
		move = "MOVL"
	}
	bind := x86ProbeInstruction(move, Operand{Kind: OpFP, FPName: "memory"}, Operand{Kind: OpReg, Reg: base})
	return append(sequence, bind, ins), true, nil
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
	if err != nil || effect.dynamicMemory || effect.flagsRead != 0 {
		return nil, 0, false
	}
	inputs := append([]Operand(nil), ins.Args...)
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
		width := int64(0)
		if f.memory >= 0 {
			width = int64(f.byteWidth)
		}
		return ins.Args, width, err == nil && !f.undefinedOpcode()
	}
	const packedFamilies = x86PackedArithmeticAdd | x86PackedArithmeticSubtract | x86PackedArithmeticLowMultiply
	if f, known, err := x86PackedArithmeticProperties(ins.Op, ins, goarch, packedFamilies); known {
		return ins.Args, int64(f.memoryBytes), err == nil && !f.mmx
	}
	if f, known, err := x86PackedLogicalProperties(ins, goarch); known {
		return ins.Args, int64(f.memoryBytes), err == nil && !f.mmx
	}
	return nil, 0, false
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
		if err != nil || form.hasMemory() {
			return x86TypedByteEffect{}, false
		}
		return form.inputEffect(), true
	}
	if form, known, err := x86ScalarCompareProperties(ins.Op, ins, goarch); known {
		if err != nil || form.memory != -1 {
			return x86TypedByteEffect{}, false
		}
		width := int64(form.bits / 8)
		return x86TypedByteEffect{operands: []x86TypedByteOperand{
			{index: 0, operand: form.args[0], width: width, read: true},
			{index: 1, operand: form.args[1], width: width, read: true},
		}}, true
	}
	effect, known, err := x86TypedGPByteEffect(ins.Op, ins, goarch)
	return effect, known && err == nil
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
