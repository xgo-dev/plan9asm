package plan9asm

import (
	"fmt"
	"strings"
)

// The six raw-only FP16 floating conversions share source, mask and control
// axes. Physical carrier widths are distinct from active input/output bytes.
type x86FP16ConversionForm struct {
	spec                                amd64HalfConversionSpec
	controls                            amd64FMA3Suffix
	sae                                 bool
	lanes, inputBytes, outputBytes      int
	sourceBytes, byteWidth, memoryBytes int
	destination, mask, upper            int
}

func x86FP16ConversionProperties(ins Instr, arch string) (x86FP16ConversionForm, bool, error) {
	base, suffix, dotted := strings.Cut(string(ins.Op), ".")
	spec, known := amd64HalfConversionSpecs[base]
	if !known || !spec.rawOnly {
		return x86FP16ConversionForm{}, false, nil
	}
	f := x86FP16ConversionForm{spec: spec, destination: len(ins.Args) - 1, mask: -1, upper: -1}
	fail := func() (x86FP16ConversionForm, bool, error) {
		return f, true, fmt.Errorf("%s %s has invalid raw FP16 conversion operands or controls: %q", arch, ins.Op, ins.Raw)
	}
	if arch != "386" && arch != "amd64" || !ins.x86Encoded || dotted && suffix == "" {
		return fail()
	}
	operands := 2
	f.lanes = ins.x86VectorBytes / 4
	if spec.scalar {
		operands, f.lanes, f.upper = 3, 1, 1
	} else if ins.x86VectorBytes != 16 && ins.x86VectorBytes != 32 && ins.x86VectorBytes != 64 {
		return fail()
	}
	if len(ins.Args) != operands && len(ins.Args) != operands+1 {
		return fail()
	}
	f.sae = suffix == "SAE" || suffix == "SAE.Z"
	if f.sae {
		suffix = strings.TrimPrefix(strings.TrimPrefix(suffix, "SAE"), ".")
	}
	var valid bool
	f.controls, valid = parseAMD64FMA3Suffix(suffix)
	if !valid || spec.inputBits == 16 && f.controls.rounding != "" || spec.outputBits == 16 && f.sae ||
		spec.scalar && f.controls.broadcast {
		return fail()
	}
	if len(ins.Args) == operands+1 {
		f.mask = operands - 1
		if !amd64NonzeroKOperand(ins.Args[f.mask]) {
			return fail()
		}
	} else if f.controls.zeroing {
		return fail()
	}
	f.inputBytes, f.outputBytes = f.lanes*spec.inputBits/8, f.lanes*spec.outputBits/8
	f.sourceBytes, f.byteWidth = f.inputBytes, f.outputBytes
	if f.sourceBytes < 16 {
		f.sourceBytes = 16
	}
	if f.byteWidth < 16 {
		f.byteWidth = 16
	}
	if !amd64GoPackedVectorMoveRegister(ins.Args[f.destination], f.byteWidth, arch) ||
		f.upper >= 0 && !amd64GoPackedVectorMoveRegister(ins.Args[f.upper], 16, arch) {
		return fail()
	}
	source := ins.Args[0]
	if source.Kind == OpReg {
		if !amd64GoPackedVectorMoveRegister(source, f.sourceBytes, arch) || f.controls.broadcast {
			return fail()
		}
	} else if !x86PackedShiftMemoryValid(source, arch) || f.sae || f.controls.rounding != "" {
		return fail()
	}
	if source.Kind == OpMem {
		if err := x86SymbolIndexedMemoryError(source.Mem, arch); err != nil {
			return f, true, err
		}
		if source.Mem.OffRaw != "" || source.Mem.IndexExt != "" {
			return fail()
		}
	}
	if !spec.scalar && (f.sae || f.controls.rounding != "") && ins.x86VectorBytes != 64 {
		return fail()
	}
	f.memoryBytes = f.inputBytes
	if f.controls.broadcast {
		f.memoryBytes = spec.inputBits / 8
	}
	return f, true, x86Mode32VectorRegisterContext(ins, arch)
}
