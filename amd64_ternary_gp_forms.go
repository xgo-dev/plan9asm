package plan9asm

import (
	"fmt"
	"strings"
)

type x86TernaryGPOperation uint8

const (
	x86TernaryANDN x86TernaryGPOperation = iota
	x86TernaryPDEP
	x86TernaryPEXT
)

type x86TernaryGPSpec struct {
	bits      int
	operation x86TernaryGPOperation
	prefix    int
}

// These families share Go's complete _yandnl operand grammar, not their
// operation or FLAGS effects. MULX has a different read/write role.
var x86TernaryGPSpecs = map[Op]x86TernaryGPSpec{
	"ANDNL": {bits: 32, operation: x86TernaryANDN},
	"ANDNQ": {bits: 64, operation: x86TernaryANDN},
	"PDEPL": {bits: 32, operation: x86TernaryPDEP, prefix: 3},
	"PDEPQ": {bits: 64, operation: x86TernaryPDEP, prefix: 3},
	"PEXTL": {bits: 32, operation: x86TernaryPEXT, prefix: 2},
	"PEXTQ": {bits: 64, operation: x86TernaryPEXT, prefix: 2},
}

type x86TernaryGPForm struct {
	spec                       x86TernaryGPSpec
	first, second, destination Operand
}

func x86TernaryGPProperties(op Op, ins Instr, arch string) (x86TernaryGPForm, bool, error) {
	name, _, dotted := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := x86TernaryGPSpecs[Op(name)]
	form := x86TernaryGPForm{spec: spec}
	if !known {
		return form, false, nil
	}
	if arch == "" {
		arch = "amd64"
	}
	if arch == "386" {
		form.spec.bits = 32 // VEX.W is ignored, including the Q source spelling.
	}
	fail := func() (x86TernaryGPForm, bool, error) {
		return form, true, fmt.Errorf("%s %s outside Go _yandnl grammar: %q", arch, op, ins.Raw)
	}
	if arch != "386" && arch != "amd64" || dotted || len(ins.Args) != 3 ||
		ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return fail()
	}
	form.first, form.second, form.destination = ins.Args[0], ins.Args[1], ins.Args[2]
	for _, operand := range []Operand{form.second, form.destination} {
		if operand.Kind != OpReg || !isX86YrlRegisterForArch(operand.Reg, arch) {
			return fail()
		}
	}
	if form.first.Kind == OpReg {
		if !isX86YrlRegisterForArch(form.first.Reg, arch) {
			return fail()
		}
	} else if !x86ScalarCompareMemoryValid(form.first, arch) {
		return fail()
	}
	return form, true, nil
}

func x86TypedTernaryGPByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	if !x86ResultNamedPredicateInstruction(ins) {
		return x86TypedByteEffect{}, false, nil
	}
	form, known, err := x86TernaryGPProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	width := int64(form.spec.bits / 8)
	effect := x86TypedByteEffect{requiresResultProof: true, operands: []x86TypedByteOperand{
		{index: 0, operand: form.first, width: width, read: true},
		{index: 1, operand: form.second, width: width, read: true},
		{index: 2, operand: form.destination, width: width, write: true},
	}}
	if form.spec.operation == x86TernaryANDN {
		effect.flagsKilled = x86ByteFlagsAll
		effect.flagsDefined = x86ByteFlagCF | x86ByteFlagOF | x86ByteFlagZF | x86ByteFlagSF
	}
	return effect, true, nil
}

func x86RawTernaryGPSource(ins Instr, arch string) bool {
	_, known, err := x86TernaryGPProperties(ins.Op, ins, arch)
	return known && err == nil && x86RawOrdinaryVectorSource(ins, arch)
}

func x86LoweredTernaryGPResultStep(ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) (bool, bool) {
	form, known, err := x86TernaryGPProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	if x86ResultNamedPredicateInstruction(ins) && !x86OrdinaryNativeMemoryOperand(form.first, arch) {
		return false, false // Ordinary named register/logical storage uses the strict transfer.
	}
	local := ins
	if !x86ResultNamedPredicateInstruction(ins) {
		if !x86RawTernaryGPSource(ins, arch) {
			return false, true
		}
		local.x86Encoded, local.x86SourceRaw = false, nil
	}
	if !x86OrdinaryNativeMemoryOperand(form.first, arch) {
		return x86ResultTransfer(local, state, owned, resultOffset, arch), true
	}
	effect, _, _ := x86TypedTernaryGPByteEffect(local.Op, local, arch)
	for _, input := range effect.operands {
		if input.read && !x86ResultReadWithNativeContinuation(local, input.operand, input.width, state, owned, arch, true) {
			return false, true
		}
	}
	if !x86ResultStore(form.destination, int64(form.spec.bits/8), state, owned, resultOffset, arch) {
		return false, true
	}
	state.flags = state.flags&^effect.flagsKilled | effect.flagsDefined
	return true, true
}
