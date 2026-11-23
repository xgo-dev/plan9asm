package plan9asm

import "bytes"

// These are the literal ymovtab encodings, before the optional 16-bit
// operand prefix. Only FS and GS have encodings valid in long mode.
var x86SegmentStackOpcodes = map[Reg]struct {
	push, pop byte
	escaped   bool
}{
	ES: {0x06, 0x07, false},
	CS: {0x0e, 0, false},
	SS: {0x16, 0x17, false},
	DS: {0x1e, 0x1f, false},
	FS: {0xa0, 0xa1, true},
	GS: {0xa8, 0xa9, true},
}

// Physical segment operations must remain adjacent to the instructions around
// them. For example POP SS inhibits interrupts until the next instruction,
// and a 32-bit selector push need not write the high half of its stack word.
// A complete frameless leaf can retain those effects without exposing a
// machine stack to LLVM register allocation or to the private value stack.
func x86PhysicalSegmentStackText(fn Func, sig FuncSig, arch, triple string) []byte {
	if len(fn.Instrs) < 4 || len(fn.Instrs[1].Args) != 1 ||
		!x86SegmentRegisterOperand(fn.Instrs[1].Args[0]) {
		return nil
	}
	if sig.Ret != Void || len(sig.Args) != 0 || len(sig.ArgRegs) != 0 ||
		len(sig.Frame.Params) != 0 || len(sig.Frame.Results) != 0 ||
		fn.x86ContinuationFlow != nil ||
		!x86ScalarFloatIntegerNativeTarget(arch, triple) ||
		validateX86AddressSensitiveRawText(fn, arch) != nil {
		return nil
	}
	last := fn.Instrs[len(fn.Instrs)-1]
	if last.Op != OpRET || len(last.Args) != 0 {
		return nil
	}

	var sourceDepth, physicalDepth int
	var accumulatorBytes int
	var text []byte
	for _, ins := range fn.Instrs[1 : len(fn.Instrs)-1] {
		code, sourceBytes, physicalBytes := x86PhysicalSegmentStackInstruction(ins, arch)
		if len(code) == 0 {
			return nil
		}
		if ins.Args[0].Kind == OpReg && ins.Args[0].Reg == AX {
			if physicalBytes > accumulatorBytes {
				return nil // The leaf cannot consume an unbound incoming AX.
			}
			if -physicalBytes > accumulatorBytes {
				accumulatorBytes = -physicalBytes
			}
		}
		if x86ResultNamedPredicateInstruction(ins) {
			sourceDepth += sourceBytes
		} else if fn.x86RawReplay == nil || ins.x86SourceRaw == nil {
			return nil
		}
		physicalDepth += physicalBytes
		if physicalDepth < 0 {
			return nil
		}
		text = append(text, code...)
	}
	if sourceDepth != 0 || physicalDepth != 0 {
		return nil
	}
	text = append(text, 0xc3)
	if replay := fn.x86RawReplay; replay != nil {
		if replay.validate(fn, arch) != nil || !bytes.Equal(text, x86PhysicalSegmentStackOriginalBytes(replay, arch)) {
			return nil
		}
	} else if !x86ResultNamedPredicateInstruction(last) {
		return nil
	}
	return text
}

func x86PhysicalSegmentStackInstruction(ins Instr, arch string) (code []byte, sourceBytes, physicalBytes int) {
	if len(ins.Args) != 1 {
		return nil, 0, 0
	}
	spec, known, err := x86StackWidthProperties(ins, arch)
	if !known || err != nil {
		return nil, 0, 0
	}
	arg := ins.Args[0]
	bits := spec.operandBits(arg, arch)
	if bits == 16 {
		code = append(code, 0x66)
	}
	push := spec.mode == amd64StackPushValue
	if x86SegmentRegisterOperand(arg) {
		encoding := x86SegmentStackOpcodes[arg.Reg]
		if !encoding.escaped && arch == "amd64" {
			return nil, 0, 0
		}
		if encoding.escaped {
			code = append(code, 0x0f)
		}
		if push {
			code = append(code, encoding.push)
		} else {
			code = append(code, encoding.pop)
		}
	} else if arg.Kind == OpReg && arg.Reg == AX {
		// AX is caller-clobbered in both modes. The leaf can discard a
		// selector here or use this scratch copy for a subsequent POP.
		if push {
			code = append(code, 0x50)
		} else {
			code = append(code, 0x58)
		}
	} else {
		return nil, 0, 0
	}
	if push {
		return code, spec.bits / 8, bits / 8
	}
	return code, -spec.bits / 8, -bits / 8
}

// The raw decoder can discard ignored prefixes when printing Go syntax.
// Match the complete original byte stream before using the physical leaf.
func x86PhysicalSegmentStackOriginalBytes(replay *x86RawReplaySource, arch string) []byte {
	var text []byte
	for _, ins := range replay.original[1:] {
		if isX86RawDirective(ins) {
			code, err := x86RawDirectiveBytes(ins)
			if err != nil {
				return nil
			}
			text = append(text, code...)
			continue
		}
		if ins.Op == OpRET && len(ins.Args) == 0 {
			text = append(text, 0xc3)
			continue
		}
		code, _, _ := x86PhysicalSegmentStackInstruction(ins, arch)
		if len(code) == 0 {
			return nil
		}
		text = append(text, code...)
	}
	return text
}
