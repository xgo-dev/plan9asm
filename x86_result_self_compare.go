package plan9asm

// Integer CMP of exactly the same physical GP byte view is independent of
// that input's value. Reuse the complete comparison grammar, including Go's
// effective REX aliases; neither a mnemonic nor equal textual names suffice.
// This defines status flags only, never numerical input bytes or memory roles.
func x86TypedSelfCompareByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	if !x86ResultNamedPredicateInstruction(ins) {
		return x86TypedByteEffect{}, false, nil
	}
	form, known, err := x86ScalarCompareProperties(op, ins, arch)
	if !known || err != nil || form.test || form.memory != -1 ||
		form.args[0].Kind != OpReg || form.args[1].Kind != OpReg {
		return x86TypedByteEffect{}, false, nil
	}
	width := int64(form.bits / 8)
	left, leftMask, leftValid := x86ResultGP(form.args[0].Reg, width, arch)
	right, rightMask, rightValid := x86ResultGP(form.args[1].Reg, width, arch)
	if !leftValid || !rightValid || left != right || leftMask != rightMask {
		return x86TypedByteEffect{}, false, nil
	}
	return x86TypedByteEffect{
		flagsDefined: x86ByteFlagsAll, flagsKilled: x86ByteFlagsAll,
		requiresResultProof: true,
	}, true, nil
}
