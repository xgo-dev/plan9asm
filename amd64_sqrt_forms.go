package plan9asm

import (
	"fmt"
	"strings"
)

type x86SqrtSpec struct {
	bits           int
	legacy, scalar bool
}

// Complete named Go family. Raw-only FP16 has a distinct physical grammar.
var x86SqrtSpecs = map[Op]x86SqrtSpec{
	"SQRTSS": {32, true, true}, "SQRTSD": {64, true, true},
	"SQRTPS": {32, true, false}, "SQRTPD": {64, true, false},
	"VSQRTSS": {32, false, true}, "VSQRTSD": {64, false, true},
	"VSQRTPS": {32, false, false}, "VSQRTPD": {64, false, false},
}

func x86SqrtSpecFor(base Op) (x86SqrtSpec, bool) {
	if base == "VSQRTPH" || base == "VSQRTSH" {
		return x86SqrtSpec{bits: 16, scalar: base == "VSQRTSH"}, true
	}
	spec, known := x86SqrtSpecs[base]
	return spec, known
}

func x86SqrtProperties(ins Instr, arch string) (x86FloatBinaryForm, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	spec, known := x86SqrtSpecFor(Op(base))
	if !known {
		return x86FloatBinaryForm{}, false, nil
	}
	if spec.bits == 16 && !ins.x86Encoded {
		return x86FloatBinaryForm{}, true, fmt.Errorf("%s has no named Go assembler form; raw encoding required", ins.Op)
	}
	f, err := x86FloatOperandProperties(ins, arch, spec.bits, spec.legacy, spec.scalar, false, !spec.scalar, "sqrt")
	if err != nil {
		return f, true, err
	}
	if spec.bits == 16 && ins.Args[0].Kind == OpMem {
		memory := ins.Args[0].Mem
		if err := x86SymbolIndexedMemoryError(memory, arch); err != nil {
			return f, true, err
		}
		if memory.OffRaw != "" || memory.IndexExt != "" {
			return f, true, fmt.Errorf("%s has an unresolved memory displacement or extension", ins.Op)
		}
	}
	// Go's pre-encoding vector names are not physical mode32 registers.
	for _, operand := range ins.Args {
		if operand.Kind == OpReg {
			index, vector := amd64VectorRegisterIndex(operand.Reg, f.byteWidth)
			if vector && arch == "386" && index >= 8 {
				return f, true, fmt.Errorf("%w: %s register %s has no physical mode32 binding", ErrProbeNeedsContext, ins.Op, operand.Reg)
			}
		}
	}
	return f, true, nil
}

func x86SqrtNativeEVEX(ins Instr, form x86FloatBinaryForm) bool {
	if form.legacy {
		return false
	}
	if form.bits == 16 || ins.x86SqrtEVEX || form.byteWidth == 64 || form.mask >= 0 || form.broadcast || form.rounding != "" {
		return true
	}
	for _, operand := range ins.Args {
		if index, valid := amd64VectorRegisterIndex(operand.Reg, form.byteWidth); valid && index >= 16 {
			return true
		}
	}
	return false
}

// Numerical definedness is shared by result and caller analysis. This says
// nothing about the backing or validity of a memory source. The caller must
// establish that separately before supplying its conditional source bytes.
func x86SqrtDefinedBytes(f x86FloatBinaryForm, source, upper, old uint64) (uint64, bool) {
	width := f.byteWidth
	if f.scalar {
		width = f.bits / 8
	}
	required := x86CallerVectorByteMask(int64(width))
	if source&required != required || f.mask >= 0 && !f.zeroing && old&required != required {
		return 0, false
	}
	if f.legacy {
		return old | required, true
	}
	if f.scalar {
		return ^uint64(0xffff) | required | upper&(0xffff&^required), true
	}
	return ^uint64(0), true
}
