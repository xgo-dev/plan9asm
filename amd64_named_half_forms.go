package plan9asm

import (
	"errors"
	"fmt"
	"strings"
)

type x86RawNamedHalfEncoding uint8

const (
	x86RawNamedHalfAbsent x86RawNamedHalfEncoding = iota
	x86RawNamedHalfVEX
	x86RawNamedHalfEVEX
)

// Active input/output bytes differ from both physical register carriers.
// Immediate-first narrowing also writes memory; it is not a source-memory
// conversion with its operands reversed after permissions have been granted.
type x86NamedHalfForm struct {
	narrow, evex, sae, zeroing                                    bool
	source, destination, mask, memory                             int
	lanes, sourceBytes, destinationBytes, inputBytes, outputBytes int
	immediate                                                     byte
	conversion                                                    x86PackedConversionForm
}

func (f x86NamedHalfForm) undefinedOpcode() bool {
	return f.narrow && f.memory == f.destination && f.zeroing
}

func x86NamedHalfProperties(op Op, ins Instr, arch string) (x86NamedHalfForm, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	if base != "VCVTPH2PS" && base != "VCVTPS2PH" {
		return x86NamedHalfForm{}, false, nil
	}
	f := x86NamedHalfForm{narrow: base == "VCVTPS2PH", destination: len(ins.Args) - 1, mask: -1, memory: -1}
	fail := func() (x86NamedHalfForm, bool, error) {
		return f, true, fmt.Errorf("%s %s outside complete named half conversion grammar: %q", arch, op, ins.Raw)
	}
	if arch != "386" && arch != "amd64" || ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return fail()
	}
	properties, err := parseAMD64HalfConversionSuffix(strings.ToUpper(string(op)), base)
	if err != nil {
		return f, true, err
	}
	f.sae, f.zeroing = properties.sae, properties.zeroing
	ins.Op = op
	count := 2
	if f.narrow {
		f.source, count = 1, 3
	}
	if len(ins.Args) != count && len(ins.Args) != count+1 {
		return fail()
	}
	if len(ins.Args) == count+1 {
		f.mask = count - 1
		if !amd64NonzeroKOperand(ins.Args[f.mask]) || f.narrow && arch == "386" && ins.x86NamedHalfEncoding == x86RawNamedHalfAbsent {
			return fail()
		}
	} else if f.zeroing {
		return fail()
	}
	source, destination := ins.Args[f.source], ins.Args[f.destination]
	width := amd64VectorByteWidth(destination.Reg)
	if f.narrow {
		width = amd64VectorByteWidth(source.Reg)
	}
	if width != 16 && width != 32 && width != 64 {
		return fail()
	}
	f.lanes = width / 4
	f.inputBytes, f.outputBytes = width/2, width
	f.sourceBytes, f.destinationBytes = 16, width
	if width == 64 {
		f.sourceBytes = 32
	}
	if f.narrow {
		f.inputBytes, f.outputBytes = width, width/2
		f.sourceBytes, f.destinationBytes = width, 16
		if width == 64 {
			f.destinationBytes = 32
		}
		immediate, valid := x86ImmediateShuffleConstant(ins.Args[0], arch,
			ins.x86NamedHalfEncoding != x86RawNamedHalfAbsent)
		if !valid || immediate.Imm < -128 || immediate.Imm > 255 {
			return fail()
		}
		f.immediate = byte(immediate.Imm)
	}
	register := func(arg Operand, bytes int) bool {
		return arg.Kind == OpReg && amd64EVEXVectorRegister(arg, bytes)
	}
	if !register(source, f.sourceBytes) {
		if f.narrow || !isAMD64MemoryOperand(source) || !x86PackedShiftMemoryValid(source, arch) {
			return fail()
		}
		f.memory = f.source
	}
	if !register(destination, f.destinationBytes) {
		if !f.narrow || !isAMD64MemoryOperand(destination) || !x86PackedShiftMemoryValid(destination, arch) {
			return fail()
		}
		f.memory = f.destination
	}
	if f.sae && (width != 64 || f.memory >= 0) {
		return fail() // Go's asmevex rejects SAE on either memory ModRM role.
	}
	f.evex = ins.x86NamedHalfEncoding == x86RawNamedHalfEVEX || width == 64 || f.mask >= 0 || f.sae ||
		amd64HalfConversionHighRegister(source) || amd64HalfConversionHighRegister(destination)
	if f.narrow && f.evex {
		immediate, _ := x86ImmediateShuffleConstant(ins.Args[0], arch,
			ins.x86NamedHalfEncoding != x86RawNamedHalfAbsent)
		if immediate.Imm < 0 {
			return fail()
		}
	}
	if err := x86Mode32VectorRegisterContext(ins, arch); err != nil {
		return f, true, err
	}
	if ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride {
		return f, true, fmt.Errorf("%w: %s needs its original default address mode", ErrProbeNeedsContext, op)
	}
	// Share active lane/carrier input rules, not a namespace or source role.
	f.conversion = x86PackedConversionForm{
		spec: x86PackedConversionSpec{amd64PackedNumericConversionSpec: amd64PackedNumericConversionSpec{
			sourceBits: 16, destinationBits: 32}},
		shape:      amd64PackedNumericShape{sourceBytes: f.sourceBytes, destinationBytes: f.destinationBytes, lanes: f.lanes},
		properties: amd64BinaryFloatingSuffix{zeroing: f.zeroing, sae: f.sae},
		inputBytes: f.inputBytes, destination: f.destination - f.source, mask: -1, memory: -1, evex: f.evex,
	}
	if f.narrow {
		f.conversion.spec.sourceBits, f.conversion.spec.destinationBits = 32, 16
	}
	if f.mask >= 0 {
		f.conversion.mask = f.mask - f.source
	}
	if f.memory == f.source {
		f.conversion.memory, f.conversion.memoryBytes = 0, f.inputBytes
	}
	return f, true, nil
}

func x86TypedNamedHalfByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	f, known, err := x86NamedHalfProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	if f.undefinedOpcode() {
		return x86TypedByteEffect{}, true, fmt.Errorf("%w: half EVEX.z memory encoding has no ordinary byte continuation", ErrProbeNeedsContext)
	}
	effect := x86TypedByteEffect{requiresResultProof: true, operands: []x86TypedByteOperand{
		{index: f.source, operand: ins.Args[f.source], width: int64(f.inputBytes), read: true},
		{index: f.destination, operand: ins.Args[f.destination], width: int64(f.outputBytes),
			read: f.mask >= 0 && !f.zeroing && f.memory != f.destination, write: true},
	}}
	if f.mask >= 0 {
		effect.operands = append(effect.operands, x86TypedByteOperand{index: f.mask, operand: ins.Args[f.mask], width: 8, read: true})
	}
	return effect, true, nil
}

func validateX86NamedHalfFile(file *File, opt Options) error {
	if file == nil || file.Arch != ArchAMD64 {
		return nil
	}
	var pending error
	for _, fn := range file.Funcs {
		for _, ins := range fn.Instrs {
			_, known, err := x86NamedHalfProperties(ins.Op, ins, opt.Goarch)
			if !known {
				continue
			}
			if err != nil && !errors.Is(err, ErrProbeNeedsContext) {
				return fmt.Errorf("%s: %w", fn.Sym, err)
			}
			if err == nil && !x86ScalarFloatIntegerNativeTarget(opt.Goarch, opt.TargetTriple) {
				err = fmt.Errorf("%w: %s needs its matching native x86 MXCSR target", ErrProbeNeedsContext, ins.Op)
			}
			if pending == nil && err != nil {
				pending = fmt.Errorf("%s: %w", fn.Sym, err)
			}
		}
	}
	return pending
}
