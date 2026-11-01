package plan9asm

// A family must independently validate its complete zero-operand grammar.
// This identity check alone establishes neither an effect nor an input role.
func x86RawOperandFreeSource(ins Instr) bool {
	origin := ins.x86SourceRaw
	return len(ins.Args) == 0 && origin != nil && origin.op == ins.Op && len(origin.args) == 0 &&
		origin.vectorBytes == ins.x86VectorBytes && ins.x86RawNearReturn == nil &&
		ins.x86AddressBits == 0 && !ins.x86UnboundAddressOverride && ins.x86SegmentPrefix == 0 &&
		!ins.x86RIPLiteral && ins.x86NumericalRead == nil
}
