package plan9asm

import (
	"fmt"
	"strings"
)

// Go's entire XLAT family is one ynone/Px/D7 row in both x86 modes.
// AL's unsigned-byte index is not an ordinary full-register SIB operand.
func x86XLATProperties(op Op, ins Instr, arch string) (bool, error) {
	name, _, dotted := strings.Cut(strings.ToUpper(string(op)), ".")
	if name != "XLAT" {
		return false, nil
	}
	if arch != "amd64" && arch != "386" || dotted || len(ins.Args) != 0 ||
		ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return true, fmt.Errorf("%s %s requires its original zero-operand Go XLAT row: %q", arch, op, ins.Raw)
	}
	if !x86ResultNamedPredicateInstruction(ins) {
		return true, fmt.Errorf("%w: XLAT needs its original default native address mode", ErrProbeNeedsContext)
	}
	return true, nil
}

func x86TypedXLATByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	known, err := x86XLATProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	// The register footprint is complete. The dynamically selected single
	// native byte is owned only by the dedicated paired reader, never by a
	// fabricated ordinary SIB, caller extent or contiguous logical FP slot.
	return x86TypedByteEffect{requiresResultProof: true, dynamicMemory: true, operands: []x86TypedByteOperand{
		{index: -1, operand: Operand{Kind: OpReg, Reg: AL}, width: 1, read: true, write: true},
		{index: -1, operand: Operand{Kind: OpReg, Reg: BX}, width: x86ResultPointerWord(arch), read: true},
	}}, true, nil
}

func x86ResultXLATStep(ins Instr, state *x86ResultState, owned []bool, arch string, native bool) (bool, bool) {
	known, err := x86XLATProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	if !native || !x86ResultRead(Operand{Kind: OpReg, Reg: AL}, 1, state, owned, arch) {
		return false, true
	}
	// Check only the real BX pointer here. The separately checked AL byte is
	// zero-extended by the emitter; unknown AX high bytes are not index inputs.
	base := Operand{Kind: OpMem, Mem: MemRef{Base: BX}}
	if !x86ResultReadWithNativeContinuation(ins, base, 1, state, owned, arch, true) {
		return false, true
	}
	state.gp[0] |= 1
	state.canonicalGP[0] &^= 1
	state.pointerGP[0], state.callerAddressGP[0], state.callerAddressOrigin[0] = false, false, 0
	state.resultAddressGP[0] = x86ResultSlotAddress{}
	return true, true // Only AL changes. AX's other bytes, FLAGS, DF and BX survive.
}
