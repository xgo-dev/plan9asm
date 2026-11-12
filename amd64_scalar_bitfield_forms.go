package plan9asm

import (
	"fmt"
	"strings"
)

type x86ScalarBitFieldKind uint8

const (
	x86BitFieldExtract x86ScalarBitFieldKind = iota
	x86BitFieldZeroHigh
)

type x86ScalarBitFieldSpec struct {
	kind         x86ScalarBitFieldKind
	bits         int
	controlBytes int64
	flagsDefined uint8
}

// BEXTR and BZHI share the complete Go _ybextrl grammar, not their control
// bytes or FLAGS. W selects a qword only in mode64; mode32 keeps the spelling.
var x86ScalarBitFieldSpecs = map[Op]x86ScalarBitFieldSpec{
	"BEXTRL": {x86BitFieldExtract, 32, 2, x86ByteFlagCF | x86ByteFlagOF | x86ByteFlagZF},
	"BEXTRQ": {x86BitFieldExtract, 64, 2, x86ByteFlagCF | x86ByteFlagOF | x86ByteFlagZF},
	"BZHIL":  {x86BitFieldZeroHigh, 32, 1, x86ByteFlagCF | x86ByteFlagOF | x86ByteFlagZF | x86ByteFlagSF},
	"BZHIQ":  {x86BitFieldZeroHigh, 64, 1, x86ByteFlagCF | x86ByteFlagOF | x86ByteFlagZF | x86ByteFlagSF},
}

type x86ScalarBitFieldForm struct {
	bits                         int
	control, source, destination Operand
	spec                         x86ScalarBitFieldSpec
}

func x86ScalarBitFieldProperties(op Op, ins Instr, arch string) (x86ScalarBitFieldForm, bool, error) {
	name, _, dotted := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := x86ScalarBitFieldSpecs[Op(name)]
	form := x86ScalarBitFieldForm{bits: spec.bits, spec: spec}
	if !known {
		return form, false, nil
	}
	if arch == "386" {
		form.bits = 32
	}
	fail := func() (x86ScalarBitFieldForm, bool, error) {
		return form, true, fmt.Errorf("%s %s outside complete Go scalar bit-field grammar: %q", arch, op, ins.Raw)
	}
	if arch != "386" && arch != "amd64" || dotted || len(ins.Args) != 3 ||
		ins.Op != "" && !strings.EqualFold(string(ins.Op), name) {
		return fail()
	}
	form.control, form.source, form.destination = ins.Args[0], ins.Args[1], ins.Args[2]
	for _, operand := range []Operand{form.control, form.destination} {
		if operand.Kind != OpReg || !isX86YrlRegisterForArch(operand.Reg, arch) {
			return fail()
		}
	}
	if form.source.Kind == OpReg {
		if !isX86YrlRegisterForArch(form.source.Reg, arch) {
			return fail()
		}
	} else if !isAMD64MemoryOperand(form.source) || !x86PackedShiftMemoryValid(form.source, arch) ||
		x86NamedMultiplyMemoryError(form.source, arch) != nil {
		return fail()
	}
	return form, true, nil
}

func x86ScalarBitFieldFamilyProperties(op Op, ins Instr, arch string, kind x86ScalarBitFieldKind) (x86ScalarBitFieldForm, bool, error) {
	form, known, err := x86ScalarBitFieldProperties(op, ins, arch)
	if !known || form.spec.kind != kind {
		return form, false, nil
	}
	return form, true, err
}
