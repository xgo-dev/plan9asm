package plan9asm

import (
	"errors"
	"fmt"
	"strings"
)

// Element types, active lanes and physical registers are separate axes. In
// particular X <- X can read 8 or 16 bytes and can write only 8 numeric bytes
// followed by eight architectural zero bytes.
type x86PackedConversionSpec struct {
	amd64PackedNumericConversionSpec
	legacy, vex bool
}

func x86PackedConversionSpecification(op Op) (x86PackedConversionSpec, bool) {
	if spec, ok := amd64PackedNumericConversionSpecs[op]; ok {
		return x86PackedConversionSpec{amd64PackedNumericConversionSpec: spec}, true
	}
	base := string(op)
	legacy := !strings.HasPrefix(base, "V")
	spec := amd64PackedNumericConversionSpec{
		sourceKind: amd64PackedNumericFloat, destinationKind: amd64PackedNumericSigned,
		sourceBits: 32, destinationBits: 32, truncate: strings.HasPrefix(base, "CVTT") || strings.HasPrefix(base, "VCVTT"),
	}
	switch base {
	case "CVTPS2PL", "CVTTPS2PL":
		spec.shapes = amd64PackedNumericSame32[:1]
	case "VCVTPS2DQ", "VCVTTPS2DQ":
		spec.shapes, spec.explicit = amd64PackedNumericSame32, "round"
	case "CVTPD2PL", "CVTTPD2PL", "VCVTPD2DQX", "VCVTTPD2DQX":
		spec.sourceBits = 64
		spec.shapes = []amd64PackedNumericShape{{sourceBytes: 16, destinationBytes: 16, lanes: 2}}
	case "VCVTPD2DQY", "VCVTTPD2DQY":
		spec.sourceBits = 64
		spec.shapes = []amd64PackedNumericShape{{sourceBytes: 32, destinationBytes: 16, lanes: 4}}
	case "VCVTPD2DQ", "VCVTTPD2DQ":
		spec.sourceBits, spec.explicit = 64, "round"
		spec.shapes = []amd64PackedNumericShape{{sourceBytes: 64, destinationBytes: 32, lanes: 8}}
	default:
		return x86PackedConversionSpec{}, false
	}
	if spec.explicit != "" && spec.truncate {
		spec.explicit = "sae"
	}
	return x86PackedConversionSpec{amd64PackedNumericConversionSpec: spec, legacy: legacy, vex: !legacy}, true
}

type x86PackedConversionForm struct {
	spec                      x86PackedConversionSpec
	shape                     amd64PackedNumericShape
	properties                amd64BinaryFloatingSuffix
	inputBytes, memoryBytes   int
	destination, memory, mask int
	mmx, evex                 bool
}

// This grammar supplies widths, not a native frame, caller, pointee or MMX/x87
// certificate. Memory consumers must independently retain those boundaries.
func x86PackedConversionProperties(ins Instr, arch string) (x86PackedConversionForm, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	spec, known := x86PackedConversionSpecification(Op(base))
	if !known {
		return x86PackedConversionForm{}, false, nil
	}
	return x86PackedConversionOperandProperties(ins, arch, spec)
}

// Share operand axes, not a family namespace, source proof or caller registry.
func x86PackedConversionOperandProperties(ins Instr, arch string, spec x86PackedConversionSpec) (x86PackedConversionForm, bool, error) {
	_, suffix, _ := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	f := x86PackedConversionForm{spec: spec, destination: len(ins.Args) - 1, memory: -1, mask: -1}
	fail := func() (x86PackedConversionForm, bool, error) {
		return f, true, fmt.Errorf("%s %s outside packed numeric conversion grammar: %q", arch, ins.Op, ins.Raw)
	}
	var valid bool
	f.properties, valid = parseAMD64BinaryFloatingSuffix(suffix)
	if !valid || arch != "amd64" && arch != "386" || len(ins.Args) != 2 && len(ins.Args) != 3 ||
		spec.legacy && (suffix != "" || len(ins.Args) != 2) ||
		f.properties.rounding != "" && spec.explicit != "round" || f.properties.sae && spec.explicit != "sae" {
		return fail()
	}
	if len(ins.Args) == 3 {
		if !amd64NonzeroKOperand(ins.Args[1]) {
			return fail()
		}
		f.mask = 1
	} else if f.properties.zeroing {
		return fail()
	}
	destination := ins.Args[f.destination]
	_, f.mmx = amd64ParseMReg(destination.Reg)
	if destination.Kind != OpReg || f.mmx && !spec.legacy {
		return fail()
	}
	width := amd64VectorByteWidth(destination.Reg)
	if f.mmx {
		f.shape = amd64PackedNumericShape{sourceBytes: 16, destinationBytes: 8, lanes: 2}
	} else {
		for _, shape := range spec.shapes {
			if shape.destinationBytes == width {
				f.shape = shape
				break
			}
		}
		if f.shape.lanes == 0 || !amd64EVEXVectorRegister(destination, width) ||
			spec.legacy && !amd64VEXVectorRegister(destination, 16) {
			return fail()
		}
	}
	f.inputBytes = f.shape.lanes * spec.sourceBits / 8
	source := ins.Args[0]
	if source.Kind == OpReg {
		if f.properties.broadcast || !amd64EVEXVectorRegister(source, f.shape.sourceBytes) ||
			spec.legacy && !amd64VEXVectorRegister(source, 16) {
			return fail()
		}
	} else if isAMD64MemoryOperand(source) && x86SignedPackedFloatMemoryOperand(source, arch) {
		f.memory, f.memoryBytes = 0, f.inputBytes
		if f.properties.broadcast {
			f.memoryBytes = spec.sourceBits / 8
		}
	} else {
		return fail()
	}
	if (f.properties.rounding != "" || f.properties.sae) &&
		(source.Kind != OpReg || f.shape != spec.shapes[len(spec.shapes)-1]) {
		return fail()
	}
	f.evex = !spec.legacy && (!spec.vex || ins.x86PackedNumericEVEX || f.mask >= 0 ||
		f.properties.broadcast || f.properties.rounding != "" || f.properties.sae ||
		f.shape.sourceBytes == 64 || f.shape.destinationBytes == 64)
	for index, operand := range []Operand{source, destination} {
		if operand.Kind != OpReg || index == 1 && f.mmx {
			continue
		}
		index, _ := amd64VectorRegisterIndex(operand.Reg, amd64VectorByteWidth(operand.Reg))
		if arch == "386" && index >= 8 {
			return f, true, fmt.Errorf("%w: %s register %s has no physical mode32 binding", ErrProbeNeedsContext, ins.Op, operand.Reg)
		}
		f.evex = f.evex || index >= 16
	}
	return f, true, nil
}

func validateX86PackedConversionFile(file *File, opt Options) error {
	if file == nil || file.Arch != ArchAMD64 {
		return nil
	}
	var pending error
	deferContext := func(err error) {
		if pending == nil {
			pending = err
		}
	}
	for _, fn := range file.Funcs {
		for _, ins := range fn.Instrs {
			form, known, err := x86PackedConversionProperties(ins, opt.Goarch)
			if !known {
				continue
			}
			if err != nil {
				// Physical mode32 binding is not a grammar error. Retain its
				// refusal, but still validate every later/dead source format.
				if errors.Is(err, ErrProbeNeedsContext) {
					deferContext(fmt.Errorf("%s: %w", fn.Sym, err))
					continue
				}
				return fmt.Errorf("%s: %w", fn.Sym, err)
			}
			if form.mmx {
				deferContext(fmt.Errorf("%w: %s has no complete physical MMX/x87 caller contract", ErrProbeNeedsContext, ins.Op))
			}
			if !x86ScalarFloatIntegerNativeTarget(opt.Goarch, opt.TargetTriple) {
				deferContext(fmt.Errorf("%w: %s needs its matching native x86 MXCSR target", ErrProbeNeedsContext, ins.Op))
			}
		}
	}
	return pending
}
