package plan9asm

import (
	"fmt"
	"strings"
)

type x86ImplicitMultiplyForm struct {
	bits   int
	signed bool
	source Operand
}

// The implicit row is ydivb/Ymb for B and ydivl/Yml (yimul's first
// row for IMUL) for W/L/Q. Explicit IMUL and division retain their consumers.
func x86ImplicitMultiplyProperties(op Op, ins Instr, arch string) (x86ImplicitMultiplyForm, bool, error) {
	name := strings.ToUpper(string(op))
	stem, bits, three, known := x86ScalarMultiplyDivideProperties(name)
	if !known || three || stem != "MUL" && stem != "IMUL" || stem == "IMUL" && bits != 8 && len(ins.Args) != 1 {
		return x86ImplicitMultiplyForm{}, false, nil
	}
	fail := func(reason string) (x86ImplicitMultiplyForm, bool, error) {
		return x86ImplicitMultiplyForm{}, true, fmt.Errorf("%s %s %s: %q", arch, op, reason, ins.Raw)
	}
	if arch != "386" && arch != "amd64" || arch == "386" && bits == 64 ||
		ins.Op != "" && !strings.EqualFold(string(ins.Op), name) || len(ins.Args) != 1 ||
		!isX86ScalarMultiplyDivideSource(ins.Args[0], bits, arch) {
		return fail("requires its complete implicit GP/memory source row")
	}
	if err := x86NamedMultiplyMemoryError(ins.Args[0], arch); err != nil {
		return fail(err.Error())
	}
	return x86ImplicitMultiplyForm{bits: bits, signed: stem == "IMUL", source: ins.Args[0]}, true, nil
}

func x86NamedMultiplyMemoryError(operand Operand, arch string) error {
	if operand.Kind != OpMem {
		return nil
	}
	memory := operand.Mem
	if err := x86SymbolIndexedMemoryError(memory, arch); err != nil {
		return err
	}
	if arch == "386" && strings.HasSuffix(memory.Sym, "(SB)") {
		memory.Base = "" // The Go named-memory row discards Reg, not Index.
	}
	if !x86MemoryRegistersValidForArch(memory, arch) || memory.OffRaw != "" ||
		memory.Index == SP || memory.Index != "" && memory.Scale != 1 && memory.Scale != 2 && memory.Scale != 4 && memory.Scale != 8 ||
		memory.Off != int64(int32(memory.Off)) && !(arch == "386" && memory.Off == int64(uint32(memory.Off))) {
		return fmt.Errorf("has an unencodable or unresolved memory source")
	}
	return nil
}

// This is a numerical dependency only, not registration in the independent
// raw-return/source-stack/caller grammars or a paired native-memory read.
func x86TypedImplicitMultiplyByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	if !x86ResultNamedPredicateInstruction(ins) {
		return x86TypedByteEffect{}, false, nil
	}
	form, known, err := x86ImplicitMultiplyProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	width := int64(form.bits / 8)
	effect := x86TypedByteEffect{requiresResultProof: true, flagsDefined: x86ByteFlagCF | x86ByteFlagOF, flagsKilled: x86ByteFlagsAll,
		operands: []x86TypedByteOperand{
			{index: 0, operand: form.source, width: width, read: true},
			{index: -1, operand: Operand{Kind: OpReg, Reg: AX}, width: width, read: true},
		}}
	if form.bits == 8 {
		effect.operands = append(effect.operands, x86TypedByteOperand{
			index: -1, operand: Operand{Kind: OpReg, Reg: AX}, width: 2, write: true})
	} else {
		for _, register := range []Reg{AX, DX} {
			effect.operands = append(effect.operands, x86TypedByteOperand{
				index: -1, operand: Operand{Kind: OpReg, Reg: register}, width: width, write: true})
		}
	}
	return effect, true, nil
}

// Only ordinary named lowering pairs this conditional numerical result with
// the exact volatile source load. Reuse the complete implicit effect, not a
// second opcode, accumulator-width or FLAGS table. Standalone queries and
// caller/frame/raw registries keep their independent storage obligations.
func x86LoweredImplicitMultiplyNativeRead(ins Instr, state *x86ResultState, owned []bool,
	resultOffset int64, arch string) (bool, bool) {
	form, known, err := x86ImplicitMultiplyProperties(ins.Op, ins, arch)
	if !known || form.source.Kind != OpMem || form.source.Mem.Sym != "" {
		return false, false // Existing register, FP/AUTO and static roles remain separate.
	}
	if err != nil || !x86ResultNamedPredicateInstruction(ins) || ins.x86NumericalRead != nil ||
		form.source.Mem.Segment != "" || !x86RegisterAddressedNativeMemoryOperand(form.source, arch) {
		return false, true
	}
	effect, known, err := x86TypedImplicitMultiplyByteEffect(ins.Op, ins, arch)
	if !known || err != nil {
		return false, true
	}
	// Read the original address and accumulator before either AX or DX is
	// overwritten. In particular a DX address is not a numerical DX input.
	for _, operand := range effect.operands {
		if operand.read && !x86ResultReadWithNativeContinuation(ins, operand.operand, operand.width, state, owned, arch, true) {
			return false, true
		}
	}
	for _, operand := range effect.operands {
		if operand.write && !x86ResultStore(operand.operand, operand.width, state, owned, resultOffset, arch) {
			return false, true
		}
	}
	state.flags = state.flags&^effect.flagsKilled | effect.flagsDefined
	return true, true
}
