package plan9asm

import "reflect"

// A short-lived observation join, never a public native-memory capability.
// The map key is the original normalized instruction ordinal, not a mutable
// Instr pointer or an opcode-only lookup. Public/direct transfers cannot make it.
type x86ScalarFPCallerRead struct {
	op   Op
	raw  string
	args []Operand
}

func x86ScalarFPCallerReads(fn Func, sig FuncSig, arch string) map[int]x86ScalarFPCallerRead {
	if arch != "amd64" || sig.Ret != Void || len(sig.Frame.Results) != 0 ||
		!x86CallerNormalizedSourceMatches(fn, sig) {
		return nil
	}
	reads := make(map[int]x86ScalarFPCallerRead)
	for ordinal, ins := range fn.Instrs {
		form, known, err := x86LegacyPackedMoveProperties(ins.Op, ins, arch)
		if !known || err != nil || form.memory != 0 || form.memoryWrite || form.aligned ||
			form.source.Kind != OpMem || !x86CallerMemoryCertified(ins, 0) {
			continue
		}
		access := ins.x86CallerMemory[0]
		if access.write || access.width != 16 {
			continue
		}
		// Whole source, signature and private caller identity were matched
		// above. Freeze the operand bytes locally; JSON or a copied instruction
		// certificate cannot recreate this whole-function entry context.
		args := append([]Operand(nil), ins.Args...)
		for index := range args {
			args[index].RegList = append([]Reg(nil), ins.Args[index].RegList...)
		}
		reads[ordinal] = x86ScalarFPCallerRead{
			op: ins.Op, raw: ins.Raw, args: args,
		}
	}
	return reads
}

func (read x86ScalarFPCallerRead) transfer(ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) bool {
	if arch != "amd64" || read.op != ins.Op || read.raw != ins.Raw ||
		!reflect.DeepEqual(read.args, ins.Args) || !x86CallerMemoryCertified(ins, 0) {
		return false
	}
	form, known, err := x86LegacyPackedMoveProperties(ins.Op, ins, arch)
	if !known || err != nil || form.memory != 0 || form.memoryWrite || form.aligned ||
		!x86ResultIncomingPointerAddressIdentity(form.source, state, arch) {
		return false
	}
	effect, known, err := x86TypedLegacyPackedMoveByteEffect(ins.Op, ins, arch)
	if !known || err != nil || effect.dynamicMemory || effect.flagsRead != 0 ||
		effect.flagsDefined != 0 || effect.flagsKilled != 0 {
		return false
	}
	for _, operand := range effect.operands {
		if !operand.read {
			continue
		}
		if operand.index == 0 && operand.width == 16 && !operand.write &&
			reflect.DeepEqual(operand.operand, read.args[0]) {
			// Defined numerical bytes come only from the existing exact caller
			// read. Opaque GP identity/index checks above add no pointee grant.
			continue
		}
		if !x86ResultRead(operand.operand, operand.width, state, owned, arch) {
			return false
		}
	}
	for _, operand := range effect.operands {
		if operand.write && !x86ResultStore(operand.operand, operand.width, state, owned, resultOffset, arch) {
			return false
		}
	}
	return true // The legacy descriptor preserves all numerical FLAGS.
}
