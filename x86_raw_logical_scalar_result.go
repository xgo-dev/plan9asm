package plan9asm

import "fmt"

// A decoded native-width, zero-cleanup RET may compose with the existing
// mode32 logical AX result. This lowering-only consumer checks the complete
// original replay and a stack-unobserving register-only leaf first. It does
// not give declaration queries, other raw instructions or memory a new role.
func (c *amd64Ctx) checkRawLogicalScalarResult() (bool, error) {
	fn, sig, arch := c.fpScalarSource, c.sig, c.goarch
	selected := false
	for _, ins := range fn.Instrs {
		selected = selected || ins.x86RawNearReturn != nil
	}
	if !selected || !x86LogicalScalarResultNeedsProof(sig, arch) {
		return false, nil
	}
	fail := func() (bool, error) {
		return true, fmt.Errorf("%w: logical scalar raw return needs its complete register-only source and independent return contract", ErrProbeNeedsContext)
	}
	if fn.x86RawReplay == nil || fn.x86ContinuationFlow != nil ||
		!x86RawReturnLeafStackUnobserved(fn) {
		return fail()
	}
	if err := fn.x86RawReplay.validate(fn, arch); err != nil {
		return true, err
	}
	view := fn
	view.Instrs = append([]Instr(nil), fn.Instrs...)
	for index, ins := range fn.Instrs {
		if form := ins.x86RawNearReturn; form != nil {
			if ins.Op != OpRET || len(ins.Args) != 0 || !form.nativeWidth || form.cleanup != 0 ||
				ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride || ins.x86SegmentPrefix != 0 {
				return fail()
			}
			// Local numerical dispatch only: neither sealed source snapshot
			// is changed, and the independent native return guard still runs.
			view.Instrs[index].x86Encoded = false
			view.Instrs[index].x86SourceRaw = nil
			view.Instrs[index].x86RawNearReturn = nil
			continue
		}
		if !x86ResultNamedPredicateInstruction(ins) || isX86RawDirective(ins) {
			return fail()
		}
		for _, operand := range ins.Args {
			switch operand.Kind {
			case OpMem, OpFP, OpFPAddr:
				return fail()
			case OpSym:
				if ins.Op != OpTEXT && ins.Op != OpLABEL {
					return fail()
				}
			}
		}
	}
	transfer := func(_ int, ins Instr, state *x86ResultState, owned []bool, offset int64, arch string) bool {
		return x86ScalarFPResultTransfer(ins, state, owned, offset, arch)
	}
	return true, checkX86LogicalRegisterResultInitialization(view, sig, arch, transfer, false, false)
}
