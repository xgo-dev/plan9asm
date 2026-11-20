package plan9asm

import (
	"fmt"
	"strings"
)

// Complete scalar GP move operand roles, independent of native storage,
// frame or numerical-input authority. GP/XMM rows use their existing form.
type x86ScalarPhysicalMoveForm struct {
	source, destination Operand
	bits                int
	address             bool
}

func x86ScalarPhysicalMoveProperties(ins Instr, arch string) (x86ScalarPhysicalMoveForm, bool, error) {
	width := x86RawReturnScalarMoveBytes(ins.Op)
	f := x86ScalarPhysicalMoveForm{bits: int(width * 8)}
	if width == 0 {
		return f, false, nil
	}
	fail := func() (x86ScalarPhysicalMoveForm, bool, error) {
		return f, true, fmt.Errorf("%s scalar GP move shape: %q", arch, ins.Raw)
	}
	if len(ins.Args) != 2 ||
		arch != "amd64" && arch != "386" || arch == "386" && width == 8 {
		return fail()
	}
	f.source, f.destination = ins.Args[0], ins.Args[1]
	gp := func(o Operand) bool {
		if o.Kind != OpReg {
			return false
		}
		if width == 1 {
			return isGoYmbRegisterForArch(o.Reg, arch)
		}
		return isX86YrlRegisterForArch(o.Reg, arch)
	}
	mem := func(o Operand) bool { return x86ScalarCompareMemoryValid(o, arch) }
	if f.source.Kind == OpSym && strings.HasPrefix(f.source.Sym, "$") {
		address := f.source
		address.Sym = strings.TrimPrefix(address.Sym, "$")
		_, _, valid := x86ScalarCompareSBAddress(address, arch)
		if width == 1 || !valid || !gp(f.destination) {
			return fail()
		}
		f.address = true
		return f, true, nil
	}
	if !gp(f.destination) && !mem(f.destination) ||
		!gp(f.source) && !mem(f.source) && f.source.Kind != OpImm ||
		!gp(f.destination) && !gp(f.source) && f.source.Kind != OpImm {
		return fail()
	}
	if f.source.Kind == OpImm {
		value := f.source.Imm
		if f.source.ImmRaw != "" || f.source.ImmIsFloat ||
			(width != 8 || !gp(f.destination)) && (value < -2147483648 || value > 4294967295) {
			return fail()
		}
		if width != 8 || !gp(f.destination) {
			f.source.Imm = amd64ScalarAddSubImmediateInt64(value, f.bits)
		}
	}
	if width == 1 && x86CompareExchangeHasREXByteView(x86CompareExchangeForm{source: f.source, destination: f.destination}) {
		for _, o := range []*Operand{&f.source, &f.destination} {
			if o.Kind == OpReg && (o.Reg == AH || o.Reg == CH || o.Reg == DH || o.Reg == BH) {
				o.Reg = amd64YmbEffectiveRegister(o.Reg, 16)
			}
		}
	}
	return f, true, nil
}
