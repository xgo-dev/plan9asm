package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
)

type x86ADXForm struct {
	spec                amd64ADXSpec
	source, destination Operand
}

// All four yml_rl rows share one complete grammar. Their independent CF/OF
// chains are effects, not source-memory, native-entry or numerical authority.
func x86ADXProperties(op Op, ins Instr, arch string) (x86ADXForm, bool, error) {
	name, _, suffix := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := amd64ADXSpecs[Op(name)]
	form := x86ADXForm{spec: spec}
	if !known {
		return form, false, nil
	}
	if arch == "" {
		arch = "amd64"
	}
	fail := func() (x86ADXForm, bool, error) {
		return form, true, fmt.Errorf("%s %s outside Go ADX yml_rl grammar: %q", arch, op, ins.Raw)
	}
	if arch != "amd64" && arch != "386" || arch == "386" && spec.bits == 64 || suffix || len(ins.Args) != 2 ||
		ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return fail()
	}
	form.source, form.destination = ins.Args[0], ins.Args[1]
	if form.destination.Kind != OpReg || !isX86YrlRegisterForArch(form.destination.Reg, arch) {
		return fail()
	}
	if form.source.Kind == OpReg {
		if !isX86YrlRegisterForArch(form.source.Reg, arch) {
			return fail()
		}
	} else if !x86ScalarCompareMemoryValid(form.source, arch) {
		if ins.x86Encoded && ins.x86RIPLiteral && form.source.Kind == OpImm {
			return form, true, fmt.Errorf("%w: physical ADX literal needs its original native-read role", ErrProbeNeedsContext)
		}
		return fail()
	}
	return form, true, nil
}

func (form x86ADXForm) carryFlag() uint8 {
	if form.spec.carry == amd64ADXCarryOF {
		return x86ByteFlagOF
	}
	return x86ByteFlagCF
}

func x86TypedADXByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	if !x86ResultNamedPredicateInstruction(ins) {
		return x86TypedByteEffect{}, false, nil
	}
	form, known, err := x86ADXProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	width := int64(form.spec.bits / 8)
	flag := form.carryFlag()
	return x86TypedByteEffect{requiresResultProof: true, flagsRead: flag, flagsDefined: flag, flagsKilled: flag,
		operands: []x86TypedByteOperand{
			{index: 0, operand: form.source, width: width, read: true},
			{index: 1, operand: form.destination, width: width, read: true, write: true},
		}}, true, nil
}

func x86RawADXSource(ins Instr, arch string) bool {
	_, known, err := x86ADXProperties(ins.Op, ins, arch)
	origin := ins.x86SourceRaw
	if !known || err != nil || origin == nil || origin.op != ins.Op || !reflect.DeepEqual(origin.args, ins.Args) ||
		origin.vectorBytes != ins.x86VectorBytes || origin.addressBits != ins.x86AddressBits ||
		ins.x86AddressBits != goWordSize(arch)*8 || ins.x86UnboundAddressOverride || ins.x86SegmentPrefix != 0 ||
		ins.x86RawNearReturn != nil || ins.x86RIPLiteral || ins.x86NumericalRead != nil {
		return false
	}
	source := ins.Args[0]
	return source.Kind == OpReg || source.Kind == OpMem && x86OrdinaryNativeMemoryOperand(source, arch)
}

func x86LoweredADXResultStep(ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) (bool, bool) {
	form, known, err := x86ADXProperties(ins.Op, ins, arch)
	if !known {
		return false, false
	}
	if err != nil {
		return false, true
	}
	local := ins
	if !x86ResultNamedPredicateInstruction(ins) {
		if !x86RawADXSource(ins, arch) {
			return false, true
		}
		local.x86Encoded, local.x86SourceRaw, local.x86AddressBits = false, nil, 0
	}
	if !x86OrdinaryNativeMemoryOperand(form.source, arch) {
		return x86ResultTransfer(local, state, owned, resultOffset, arch), true
	}
	effect, _, err := x86TypedADXByteEffect(local.Op, local, arch)
	if err != nil || state.flags&effect.flagsRead != effect.flagsRead {
		return false, true
	}
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
