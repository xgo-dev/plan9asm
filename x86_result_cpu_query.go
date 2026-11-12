package plan9asm

// Only the two architectural maximum-leaf selectors have an unconditional
// EAX-only dependency. This must-fact supplies no numerical bytes or address
// role. Unknown selectors, including unsupported leaves that may alias a
// structured leaf, still consume ECX. Every CFG predecessor must agree.
func x86ResultCPUIDRootLeafAfter(ins Instr, before bool, arch string) bool {
	if !x86ResultNamedPredicateInstruction(ins) {
		return false
	}
	ins = x86SourceMoveInstruction(ins, arch)
	if width := x86RawReturnScalarMoveBytes(ins.Op); width != 0 && len(ins.Args) == 2 {
		destination := ins.Args[1]
		if destination.Kind != OpReg {
			return before
		}
		index, _, valid := x86ResultGP(destination.Reg, width, arch)
		if !valid || index != 0 {
			return valid && before
		}
		source := ins.Args[0]
		return width >= 4 && source.Kind == OpImm && source.ImmRaw == "" && !source.ImmIsFloat &&
			(uint32(source.Imm) == 0 || uint32(source.Imm) == 0x80000000)
	}
	if form, known, err := x86LockScalarRMWProperties(ins.Op, ins, arch); known && err == nil &&
		form.spec.bits >= 32 && form.destination.Kind == OpReg && x86ScalarXORZeroRegister(form, int64(form.spec.bits/8)) {
		index, _, valid := x86ResultGP(form.destination.Reg, int64(form.spec.bits/8), arch)
		if valid && index == 0 {
			return true
		}
	}
	if !before {
		return false
	}
	if effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch); known {
		if err != nil {
			return false
		}
		for _, operand := range effect.operands {
			if operand.write && operand.operand.Kind == OpReg {
				index, _, valid := x86ResultGP(operand.operand.Reg, operand.width, arch)
				if !valid || index == 0 {
					return false
				}
			}
		}
		return true
	}
	if _, known, err := x86ScalarCompareProperties(ins.Op, ins, arch); known && err == nil {
		return true
	}
	return ins.Op == OpJMP || isAMD64ConditionalBranch(ins.Op) || ins.Op == "NOP"
}
