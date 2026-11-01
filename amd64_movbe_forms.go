package plan9asm

import (
	"fmt"
	"strings"
)

var x86MOVBEWidths = map[Op]int{
	"MOVBEW": 16, "MOVBEWW": 16,
	"MOVBEL": 32, "MOVBELL": 32,
	"MOVBEQ": 64, "MOVBEQQ": 64,
}

type x86MOVBEForm struct {
	bits                int
	source, destination Operand
	store               bool
}

func x86MOVBEProperties(op Op, ins Instr, arch string) (x86MOVBEForm, bool, error) {
	name, _, dotted := strings.Cut(strings.ToUpper(string(op)), ".")
	bits, known := x86MOVBEWidths[Op(name)]
	form := x86MOVBEForm{bits: bits}
	if !known {
		return form, false, nil
	}
	if arch == "" {
		arch = "amd64"
	}
	fail := func() (x86MOVBEForm, bool, error) {
		return form, true, fmt.Errorf("%s %s outside Go ymovbe grammar: %q", arch, op, ins.Raw)
	}
	if arch != "386" && arch != "amd64" || arch == "386" && bits == 64 || dotted || len(ins.Args) != 2 ||
		ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return fail()
	}
	form.source, form.destination = ins.Args[0], ins.Args[1]
	register, memory := form.destination, form.source
	if form.source.Kind == OpReg {
		form.store, register, memory = true, form.source, form.destination
	}
	if register.Kind != OpReg || !isX86YrlRegisterForArch(register.Reg, arch) ||
		!x86ScalarCompareMemoryValid(memory, arch) {
		return fail()
	}
	return form, true, nil
}

func x86TypedMOVBEByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	if !x86ResultNamedPredicateInstruction(ins) {
		return x86TypedByteEffect{}, false, nil
	}
	form, known, err := x86MOVBEProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	width := int64(form.bits / 8)
	return x86TypedByteEffect{requiresResultProof: true, operands: []x86TypedByteOperand{
		{index: 0, operand: form.source, width: width, read: true},
		{index: 1, operand: form.destination, width: width, write: true},
	}}, true, nil
}

func x86RawMOVBESource(ins Instr, arch string) bool {
	_, known, err := x86MOVBEProperties(ins.Op, ins, arch)
	return known && err == nil && x86RawOrdinaryVectorSource(ins, arch)
}

func x86LoweredMOVBEResultStep(ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) (bool, bool) {
	form, known, err := x86MOVBEProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	local := ins
	if !x86ResultNamedPredicateInstruction(ins) {
		if !x86RawMOVBESource(ins, arch) {
			return false, true
		}
		local.x86Encoded, local.x86SourceRaw = false, nil
	}
	width := int64(form.bits / 8)
	if form.store && x86OrdinaryNativeMemoryOperand(form.destination, arch) {
		return x86ResultIncomingPointerAddressIdentity(form.destination, state, arch) &&
			x86ResultRead(form.source, width, state, owned, arch), true
	}
	if !form.store && x86OrdinaryNativeMemoryOperand(form.source, arch) {
		if !x86ResultReadWithNativeContinuation(local, form.source, width, state, owned, arch, true) {
			return false, true
		}
		return x86ResultStore(form.destination, width, state, owned, resultOffset, arch), true
	}
	if x86ResultNamedPredicateInstruction(ins) {
		return false, false // Logical storage remains in the ordinary strict transfer.
	}
	return x86ResultTransfer(local, state, owned, resultOffset, arch), true
}
