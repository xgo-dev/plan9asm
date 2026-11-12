package plan9asm

import (
	"fmt"
	"strings"
)

type x86CompareExchangeSpec struct {
	bits int
	pair bool
}

// Complete original yrb_mb, yrl_ml and yscond rows. Syntax acceptance is
// distinct from a physical encoder-view or native-memory permission.
var x86CompareExchangeSpecs = map[Op]x86CompareExchangeSpec{
	"CMPXCHGB":   {bits: 8},
	"CMPXCHGW":   {bits: 16},
	"CMPXCHGL":   {bits: 32},
	"CMPXCHGQ":   {bits: 64},
	"CMPXCHG8B":  {bits: 64, pair: true},
	"CMPXCHG16B": {bits: 128, pair: true},
}

type x86CompareExchangeForm struct {
	spec        x86CompareExchangeSpec
	source      Operand
	destination Operand
}

func x86CompareExchangeProperties(op Op, ins Instr, arch string) (x86CompareExchangeForm, bool, error) {
	name := strings.ToUpper(string(op))
	base := strings.SplitN(name, ".", 2)[0]
	spec, recognized := x86CompareExchangeSpecs[Op(base)]
	if !recognized {
		return x86CompareExchangeForm{}, false, nil
	}
	invalid := func(reason string) (x86CompareExchangeForm, bool, error) {
		return x86CompareExchangeForm{}, true, fmt.Errorf("%s %s %s: %q", arch, op, reason, ins.Raw)
	}
	context := func(reason string) (x86CompareExchangeForm, bool, error) {
		return x86CompareExchangeForm{}, true, fmt.Errorf("%w: %s %s %s: %q", ErrProbeNeedsContext, arch, op, reason, ins.Raw)
	}
	if name != base || ins.Op != "" && !strings.EqualFold(string(ins.Op), name) {
		return invalid("does not accept suffixes or a contradictory source identity")
	}
	if arch != "amd64" && arch != "386" {
		return invalid("requires a registered x86 mode")
	}
	if arch == "386" && (spec.bits == 128 || spec.bits == 64 && !spec.pair) {
		return invalid("is illegal in 32-bit mode")
	}
	count := 2
	if spec.pair {
		count = 1
	}
	if len(ins.Args) != count {
		return invalid("does not have its complete ordered operand count")
	}
	form := x86CompareExchangeForm{spec: spec, destination: ins.Args[count-1]}
	if !spec.pair {
		if projected, segment, err := x86NamedSegmentMemorySource(ins, form.destination, arch); segment {
			if err != nil {
				return form, true, err
			}
			form.destination = projected
		}
	}
	registerAllowed := func(reg Reg) bool {
		if spec.pair || spec.bits == 8 {
			return isGoYmbRegisterForArch(reg, arch)
		}
		return isX86YrlRegisterForArch(reg, arch)
	}
	if !spec.pair {
		form.source = ins.Args[0]
		if form.source.Kind != OpReg || !registerAllowed(form.source.Reg) {
			return invalid("source is outside its original Yrb/Yrl class")
		}
	}
	destination := form.destination
	if destination.Kind == OpReg {
		if !registerAllowed(destination.Reg) {
			return invalid("destination is outside its original Ymb/Yml class")
		}
	} else if !isAMD64MemoryOperand(destination) ||
		destination.Kind == OpSym && strings.HasPrefix(strings.TrimSpace(destination.Sym), "$") {
		return invalid("destination is not its original register/memory operand")
	} else if destination.Kind == OpMem && !x86MemoryRegistersValidForArch(destination.Mem, arch) {
		return invalid("memory uses an out-of-range address register")
	}
	if spec.pair && destination.Kind == OpReg {
		return context("Go emits a non-memory pair operand with native #UD, not a numerical CAS")
	}
	if spec.bits == 8 {
		if arch == "386" {
			for _, operand := range []Operand{form.source, destination} {
				if operand.Kind == OpReg && (operand.Reg == BP || operand.Reg == SI || operand.Reg == DI) {
					return context("Go's byte-register expansion changes the implicit accumulator before CMPXCHG")
				}
			}
		} else if x86CompareExchangeHasREXByteView(form) {
			for _, operand := range []Operand{form.source, destination} {
				if operand.Kind == OpReg && (operand.Reg == AH || operand.Reg == BH || operand.Reg == CH || operand.Reg == DH) {
					return context("Go's REX encoding changes a high-byte spelling to an unbound low-byte physical view")
				}
			}
		}
	}
	return form, true, nil
}

func x86CompareExchangeHasREXByteView(form x86CompareExchangeForm) bool {
	requiresREX := func(reg Reg) bool {
		switch reg {
		case SP, BP, SI, DI, BPB, SIB, DIB:
			return true
		}
		base, _, alias := amd64ByteAlias(reg)
		if alias {
			reg = base
		}
		return strings.HasPrefix(string(reg), "R")
	}
	for _, operand := range []Operand{form.source, form.destination} {
		if operand.Kind == OpReg && requiresREX(operand.Reg) {
			return true
		}
		if operand.Kind == OpMem {
			for _, reg := range []Reg{operand.Mem.Base, operand.Mem.Index} {
				if strings.HasPrefix(string(reg), "R") {
					return true
				}
			}
		}
	}
	return false
}
