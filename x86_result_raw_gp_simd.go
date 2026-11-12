package plan9asm

import "reflect"

// VMOVW is absent from Go's named table. Only its exact decoder-bound
// register/m16 form may share the ordinary GP/X numerical transfer. This
// observation grants no physical entry, raw return, frame or caller memory.
func x86RawVMOVWResultForm(ins Instr, arch string) (x86GPSIMDTransferForm, bool) {
	if ins.Op != "VMOVW" || !ins.x86Encoded || ins.x86SourceRaw == nil ||
		ins.x86RawNearReturn != nil || ins.x86AddressBits != 0 ||
		ins.x86UnboundAddressOverride || ins.x86SegmentPrefix != 0 ||
		ins.x86RIPLiteral || ins.x86NumericalRead != nil ||
		ins.x86SourceRaw.op != ins.Op || !reflect.DeepEqual(ins.x86SourceRaw.args, ins.Args) {
		return x86GPSIMDTransferForm{}, false
	}
	form, known, err := x86GPSIMDTransferProperties(ins, arch)
	if !known || err != nil || !form.spec.rawOnly || form.bits != 16 || form.mmx {
		return form, false
	}
	for _, operand := range ins.Args {
		if operand.Kind != OpReg && (operand.Kind != OpMem ||
			operand.Mem.Sym != "" || operand.Mem.Segment != "" || !x86OrdinaryNativeMemoryOperand(operand, arch)) {
			return form, false
		}
	}
	return form, true
}

// The paired lowerer retains exact volatile i16 accesses. Continuing past a
// read supplies only those two numerical bytes; it does not assert validity,
// alignment, extent, aliasing or a reusable memory fact. Unknown register
// inputs remain required even when the instruction's result is dead.
func x86LoweredRawVMOVWResultStep(ins Instr, state *x86ResultState,
	owned []bool, resultOffset int64, arch string) (bool, bool) {
	if ins.Op != "VMOVW" {
		return false, false
	}
	form, valid := x86RawVMOVWResultForm(ins, arch)
	if !valid {
		return false, true
	}
	if form.sourceX {
		index, _ := amd64ParseXReg(ins.Args[0].Reg)
		if state.xmm[index]&3 != 3 {
			return false, true
		}
	} else if ins.Args[0].Kind == OpReg && !x86ResultRead(ins.Args[0], 2, state, owned, arch) {
		return false, true
	}
	// Project only this already-validated effect into the shared byte rule.
	// The actual source, raw identity and lowerer's ISA attributes stay intact.
	local := ins
	local.x86Encoded, local.x86SourceRaw = false, nil
	form.spec.rawOnly = false
	return x86ResultGPSIMDTransferWithNativeMemory(local, form, state, owned, resultOffset, arch, true), true
}
