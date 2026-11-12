package plan9asm

import (
	"fmt"
	"strings"
)

// Go's complete scalar non-temporal family shares one yrl_ml/Zr_m row.
// Its Yml compatibility closure includes register destinations whose physical
// ModRM form faults; those forms never consume a source value or an address.
var x86MOVNTIWidths = map[Op]int{
	"MOVNTIL": 32,
	"MOVNTIQ": 64,
}

type x86MOVNTIForm struct {
	bits                int
	source, destination Operand
	trap                bool
}

func x86MOVNTIProperties(op Op, ins Instr, arch string) (x86MOVNTIForm, bool, error) {
	name, _, dotted := strings.Cut(strings.ToUpper(string(op)), ".")
	bits, known := x86MOVNTIWidths[Op(name)]
	form := x86MOVNTIForm{bits: bits}
	if !known {
		return form, false, nil
	}
	fail := func() (x86MOVNTIForm, bool, error) {
		return form, true, fmt.Errorf("%s %s outside Go yrl_ml scalar non-temporal grammar: %q", arch, op, ins.Raw)
	}
	if arch != "amd64" && arch != "386" || arch == "386" && bits == 64 || dotted ||
		len(ins.Args) != 2 || ins.Op != "" && !strings.EqualFold(string(ins.Op), name) {
		return fail()
	}
	form.source, form.destination = ins.Args[0], ins.Args[1]
	if form.source.Kind != OpReg || !isX86YrlRegisterForArch(form.source.Reg, arch) {
		return fail()
	}
	if form.destination.Kind == OpReg {
		if !isX86YrlRegisterForArch(form.destination.Reg, arch) {
			return fail()
		}
		form.trap = true
		return form, true, nil
	}
	if !isAMD64MemoryOperand(form.destination) {
		return fail()
	}
	memory := form.destination
	if projected, segment, err := x86NamedSegmentMemorySource(ins, memory, arch); segment {
		if err != nil {
			return form, true, err
		}
		memory, form.destination = projected, projected
	}
	if memory.Kind == OpMem {
		if err := x86SymbolIndexedMemoryError(memory.Mem, arch); err != nil {
			return form, true, err
		}
		if memory.Mem.OffRaw != "" || memory.Mem.IndexExt != "" {
			return fail()
		}
		if arch == "386" && strings.HasSuffix(memory.Mem.Sym, "(SB)") {
			memory.Mem.Base = "" // Go discards this named annotation, not Index.
		}
	}
	if !x86ScalarCompareMemoryValid(memory, arch) {
		return fail()
	}
	return form, true, nil
}
