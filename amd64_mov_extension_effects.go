package plan9asm

import (
	"fmt"
	"strings"
)

type amd64ScalarExtensionMoveSpec struct {
	sourceBits      int
	destinationBits int
	signed          bool
	rejectedOn386   bool
	byteClass       bool
}

// These fourteen rows use Go's ymb_rl or yml_rl tables. MOVSWW/MOVZWW
// read a word despite using ymb_rl and its byte-register ModRM spellings.
var amd64ScalarExtensionMoveSpecs = map[Op]amd64ScalarExtensionMoveSpec{
	"MOVBWSX": {sourceBits: 8, destinationBits: 16, signed: true, byteClass: true},
	"MOVBWZX": {sourceBits: 8, destinationBits: 16, byteClass: true},
	"MOVBLSX": {sourceBits: 8, destinationBits: 32, signed: true, byteClass: true},
	"MOVBLZX": {sourceBits: 8, destinationBits: 32, byteClass: true},
	"MOVBQSX": {sourceBits: 8, destinationBits: 64, signed: true, rejectedOn386: true, byteClass: true},
	"MOVBQZX": {sourceBits: 8, destinationBits: 64, rejectedOn386: true, byteClass: true},
	"MOVWLSX": {sourceBits: 16, destinationBits: 32, signed: true},
	"MOVWLZX": {sourceBits: 16, destinationBits: 32},
	"MOVWQSX": {sourceBits: 16, destinationBits: 64, signed: true, rejectedOn386: true},
	"MOVWQZX": {sourceBits: 16, destinationBits: 64, rejectedOn386: true},
	"MOVLQSX": {sourceBits: 32, destinationBits: 64, signed: true, rejectedOn386: true},
	"MOVLQZX": {sourceBits: 32, destinationBits: 64},
	"MOVSWW":  {sourceBits: 16, destinationBits: 16, signed: true, byteClass: true},
	"MOVZWW":  {sourceBits: 16, destinationBits: 16, byteClass: true},
}

type x86ScalarExtensionForm struct {
	spec   amd64ScalarExtensionMoveSpec
	source Operand
	result Reg
}

func x86ScalarExtensionProperties(op Op, ins Instr, arch string) (x86ScalarExtensionForm, bool, error) {
	op = Op(strings.ToUpper(string(op)))
	spec, recognized := amd64ScalarExtensionMoveSpecs[op]
	if !recognized {
		return x86ScalarExtensionForm{}, false, nil
	}
	fail := func(reason string) (x86ScalarExtensionForm, bool, error) {
		return x86ScalarExtensionForm{}, true, fmt.Errorf("%s %s %s: %q", arch, op, reason, ins.Raw)
	}
	if ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) || len(ins.Args) != 2 {
		return fail("requires matching opcode and two operands")
	}
	if arch == "386" && spec.rejectedOn386 {
		return fail("is outside Go's 386 extension tables")
	}
	if arch == "386" && op == "MOVLQZX" {
		// Px is an ordinary MOVL in 386 mode, not a 64-bit write.
		spec.destinationBits = 32
	}
	source, destination := ins.Args[0], ins.Args[1]
	if projected, segment, err := x86NamedSegmentMemorySource(ins, source, arch); segment {
		if err != nil {
			return x86ScalarExtensionForm{}, true, err
		}
		source = projected
	}
	if destination.Kind != OpReg || !isX86YrlRegisterForArch(destination.Reg, arch) {
		return fail("expects a Yrl destination register")
	}
	if source.Kind == OpReg {
		valid := isX86YrlRegisterForArch(source.Reg, arch)
		if spec.byteClass {
			valid = isGoYmbRegisterForArch(source.Reg, arch)
		}
		if !valid {
			return fail("source register is outside its Go class")
		}
		if spec.byteClass && spec.sourceBits == 16 {
			source.Reg = amd64YmbEffectiveRegister(source.Reg, 16)
		} else if spec.sourceBits == 8 && arch != "386" &&
			(spec.destinationBits == 64 || x86ExtensionHighRegister(destination.Reg)) {
			// A REX prefix changes ModRM 4..7 from AH/CH/DH/BH to the
			// low bytes of SP/BP/SI/DI. Go emits those actual bytes too.
			switch source.Reg {
			case AH, CH, DH, BH:
				source.Reg = amd64YmbEffectiveRegister(source.Reg, 16)
			}
		}
	} else if !isAMD64MemoryOperand(source) ||
		source.Kind == OpSym && !x86PackedShiftMemoryValid(source, arch) {
		return fail("expects a register or memory source")
	}
	if source.Kind == OpMem && !x86MemoryRegistersValidForArch(source.Mem, arch) {
		return fail("memory source has an invalid address register")
	}
	return x86ScalarExtensionForm{spec: spec, source: source, result: destination.Reg}, true, nil
}

func x86ExtensionHighRegister(register Reg) bool {
	switch register {
	case "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15":
		return true
	default:
		return false
	}
}

func x86ScalarMoveMemoryBytes(ins Instr, operand int, arch string) int64 {
	if form, known, err := x86ConditionalMoveProperties(ins.Op, ins, arch); known {
		if err == nil && operand == 0 && isAMD64MemoryOperand(form.source) {
			return int64(form.bits / 8)
		}
		return 0
	}
	op := Op(normalizeInstructionOpcode(x86SourceMoveInstruction(ins, arch).Op))
	if _, recognized, err := x86ConditionalSetProperties(ins.Op, ins, arch); recognized {
		if err == nil && operand == 0 {
			return 1
		}
		return 0
	}
	if width := x86RawReturnScalarMoveBytes(op); width != 0 {
		return width
	}
	form, recognized, err := x86ScalarExtensionProperties(op, ins, arch)
	if !recognized || err != nil || operand != 0 {
		return 0
	}
	return int64(form.spec.sourceBits / 8)
}

func x86CallerExtensionStep(ins *Instr, state *x86SourceStackState, proof *x86GoCallerRegionProof) (bool, bool) {
	form, recognized, err := x86ScalarExtensionProperties(ins.Op, *ins, "amd64")
	if !recognized || err != nil {
		return recognized, false
	}
	width := int64(form.spec.sourceBits / 8)
	if !x86CallerMemoryStep(ins, state, proof, width) {
		return true, false
	}
	if form.source.Kind != OpMem && !x86CallerNumericRead(form.source, width, state) {
		return true, false
	}
	return true, x86CallerNumericWrite(form.result, int64(form.spec.destinationBits/8), state)
}
