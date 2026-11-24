package plan9asm

import (
	"fmt"
	"strings"
)

// One grammar for Go's yxcvfl/yxcvfq and _yvcvtsd2si/_yvcvtsd2usil
// rows. Operand acceptance is not a native address or ABI certificate.
type x86ScalarFloatIntegerForm struct {
	spec       amd64ScalarFloatToIntSpec
	outputBits int
	suffix     string
	evex       bool
	memory     bool
}

func x86ScalarFloatIntegerProperties(ins Instr, arch string) (x86ScalarFloatIntegerForm, bool, error) {
	name, suffix, dotted := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	spec, known := amd64ScalarFloatToIntSpecs[Op(name)]
	f := x86ScalarFloatIntegerForm{spec: spec, outputBits: spec.outputBits, suffix: suffix, evex: spec.unsigned || dotted || ins.x86ScalarFloatIntegerEVEX}
	if !known {
		return f, false, nil
	}
	fail := func() (x86ScalarFloatIntegerForm, bool, error) {
		return f, true, fmt.Errorf("%s %s outside Go scalar float-to-integer grammar: %q", arch, ins.Op, ins.Raw)
	}
	if arch != "amd64" && arch != "386" || len(ins.Args) != 2 ||
		ins.Args[1].Kind != OpReg || !isX86YrlRegisterForArch(ins.Args[1].Reg, arch) {
		return fail()
	}
	if !spec.vector {
		if dotted || arch == "386" && spec.outputBits == 64 {
			return fail()
		}
	} else {
		if dotted {
			valid := spec.truncating && suffix == "SAE"
			if !spec.truncating {
				valid = suffix == "RN_SAE" || suffix == "RD_SAE" || suffix == "RU_SAE" || suffix == "RZ_SAE"
			}
			if !valid || ins.Args[0].Kind != OpReg {
				return fail()
			}
		}
		if arch == "386" {
			// VEX.W1 and EVEX.W1 are ignored outside 64-bit mode. Keep the
			// original Q spelling, but all consumers observe a dword write.
			f.outputBits = 32
		}
	}
	source := ins.Args[0]
	if source.Kind == OpReg {
		index, valid := amd64ParseXReg(source.Reg)
		if !valid || !spec.vector && index >= 16 || !spec.vector && arch == "386" && index >= 8 {
			return fail()
		}
		if arch == "386" && index >= 8 {
			return f, true, fmt.Errorf("%w: %s lacks a physical mode32 high-X register identity", ErrProbeNeedsContext, ins.Op)
		}
		f.evex = f.evex || index >= 16
	} else {
		if source.Kind == OpMem {
			if err := x86SymbolIndexedMemoryError(source.Mem, arch); err != nil {
				return f, true, err
			}
			if source.Mem.OffRaw != "" || source.Mem.IndexExt != "" {
				return fail()
			}
			if arch == "386" && strings.HasSuffix(source.Mem.Sym, "(SB)") {
				source.Mem.Base = ""
			}
		}
		if !isAMD64MemoryOperand(source) || !x86PackedShiftMemoryValid(source, arch) {
			return fail()
		}
		f.memory = true
	}
	return f, true, nil
}

func x86TypedScalarFloatIntegerByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	if _, known := amd64ScalarFloatToIntSpecs[Op(base)]; !known {
		return x86TypedByteEffect{}, false, nil
	}
	if ins.Op != "" && !strings.EqualFold(string(op), string(ins.Op)) {
		return x86TypedByteEffect{}, true, fmt.Errorf("scalar conversion effect/source mismatch: %s/%s", op, ins.Op)
	}
	ins.Op = op
	f, known, err := x86ScalarFloatIntegerProperties(ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	return x86TypedByteEffect{
		requiresResultProof: true,
		vector:              x86TypedVectorEffect{x86TypedVectorNoWrite, 1},
		operands: []x86TypedByteOperand{
			{index: 0, operand: ins.Args[0], width: int64(f.spec.inputBits / 8), read: true},
			{index: 1, operand: ins.Args[1], width: int64(f.outputBits / 8), write: true, stackValue: ins.Args[1].Reg == SP},
		},
	}, true, nil // Integer FLAGS are unchanged, independently of MXCSR.
}

func x86ScalarFloatIntegerNativeTarget(arch, triple string) bool {
	parts := strings.Split(triple, "-")
	if len(parts) < 3 {
		return false
	}
	if arch == "amd64" {
		return parts[0] == "x86_64"
	}
	return arch == "386" && (parts[0] == "i386" || parts[0] == "i486" || parts[0] == "i586" || parts[0] == "i686")
}

func validateX86ScalarFloatIntegerFile(file *File, opt Options) error {
	if file == nil || file.Arch != ArchAMD64 {
		return nil
	}
	needed := false
	for _, fn := range file.Funcs {
		for _, ins := range fn.Instrs {
			_, known, err := x86ScalarFloatIntegerProperties(ins, opt.Goarch)
			if known && err != nil {
				return fmt.Errorf("%s: %w", fn.Sym, err)
			}
			needed = needed || known
		}
	}
	if needed && !x86ScalarFloatIntegerNativeTarget(opt.Goarch, opt.TargetTriple) {
		return fmt.Errorf("%w: scalar float-to-integer needs its native x86 MXCSR target, got %q/%q", ErrProbeNeedsContext, opt.Goarch, opt.TargetTriple)
	}
	return nil
}
