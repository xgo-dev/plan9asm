package plan9asm

// TEST and CMP's register/immediate read-only rows observe actual incoming
// caller addresses. CMP requires caller provenance for every register operand;
// a numerical register is not a second address participant. The same physical
// typed byte view and original immediate
// encoding are used by lowering. This does not initialize GP bytes, prove a
// pointee, or authorize a numerical/address result, store or native entry.
func x86ResultCallerAddressTest(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	form, known, err := x86ScalarCompareProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, false
	}
	address, valid := false, true
	for _, operand := range form.args {
		if operand.Kind == OpReg {
			root, _, physical := x86ResultGP(operand.Reg, int64(form.bits/8), arch)
			// Source-wide shape validation sees all registered numerical
			// registers together. It supplies no reaching caller provenance;
			// the same operands must pass this gate again with shapeOnly=false.
			if physical && (state.callerAddressGP[root] || !form.test && state.shapeOnly) {
				address = true
				continue
			}
		}
		if form.test {
			valid = valid && (operand.Kind == OpReg || operand.Kind == OpImm) &&
				x86ResultRead(operand, int64(form.bits/8), state, owned, arch)
		} else {
			valid = valid && operand.Kind == OpImm && x86ResultRead(operand, int64(form.bits/8), state, owned, arch)
		}
	}
	if !address {
		return false, false
	}
	if !valid || ins.x86Encoded || ins.x86SourceRaw != nil || ins.x86RawNearReturn != nil ||
		ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride || ins.x86SegmentPrefix != 0 {
		return false, true
	}
	state.flags = x86ByteFlagsAll
	if form.test {
		state.flags &^= x86ByteFlagAF
	}
	return true, true
}

// A source-bound string instruction or LOCK prefix has already passed its
// complete paired transfer. Intersect with the prior must-domain: an untouched
// register may retain its identity, but this post-consumer cannot introduce
// one. Standalone LOCK still has no accepted numerical transfer or GP effect.
func x86ResultCallerAddressesAfterTransfer(ins Instr, before, transferred [16]bool,
	entryFP map[int64]bool, arch string) [16]bool {
	_, stringMemory, err := x86StringInstructionProperties(ins, arch)
	boundPrefix := ins.Op == "LOCK" && len(ins.Args) == 0
	if (boundPrefix || stringMemory && err == nil) && x86ResultNamedPredicateInstruction(ins) {
		for index := range before {
			before[index] = before[index] && transferred[index]
		}
		return before
	}
	return x86ResultCallerAddressesAfter(ins, before, entryFP, arch)
}

// This post-transfer must-domain runs through the shared complete source CFG,
// including dead effects and joins. A partial/full GP overwrite revokes its
// old provenance independently of initialized bytes or opaque pointerGP.
// Unknown effects conservatively revoke all caller addresses, never seed one.
func x86ResultCallerAddressesAfter(ins Instr, before [16]bool, entryFP map[int64]bool, arch string) [16]bool {
	if x86RawScalarFloatIntegerSource(ins, arch) {
		form, _, _ := x86ScalarFloatIntegerProperties(ins, arch)
		if destination, _, valid := x86ResultGP(ins.Args[1].Reg, int64(form.outputBits/8), arch); valid {
			before[destination] = false
		}
		return before // Only the native GP result loses its old caller-address identity.
	}
	if x86RawCOMISource(ins, arch) {
		return before // The exact scalar comparison has no GP output or new address role.
	}
	if x86RawMULXSource(ins, arch) {
		form, _, _ := x86MULXProperties(ins.Op, ins, arch)
		for _, output := range []Operand{form.low, form.high} {
			if index, _, valid := x86ResultGP(output.Reg, int64(form.bits/8), arch); valid {
				before[index] = false
			}
		}
		return before // Retain unrelated identities, never a pointer from either product.
	}
	if x86RawZeroExtendSource(ins, arch) {
		return before // Preserve existing GP identities without creating one.
	}
	if x86RawImmediateBlendSource(ins, arch) {
		return before // Exact vector selection has no GP output or new caller-address role.
	}
	if x86RawPermute128Source(ins, arch) {
		return before // Retain existing identities without creating a GP/pointee fact.
	}
	if x86RawScalarPrecisionSource(ins, arch) || x86RawPackedPrecisionSource(ins, arch) {
		return before // The exact conversion writes X/MXCSR, never a new GP identity.
	}
	if x86RawExplicitMaskMoveSource(ins, arch) {
		return before // Existing GP identities survive; no new address is created.
	}
	if x86RawUnalignedLoadSource(ins, arch) {
		return before
	}
	if x86RawIntegerMinMaxSource(ins, arch) {
		return before // Preserves existing identities, never creates a GP address.
	}
	if x86RawTernaryLogicSource(ins, arch) {
		return before // Exact vector/mask inputs and writes have no GP destination.
	}
	if x86RawLegacyFloatCompareSource(ins, arch) {
		return before // Exact legacy comparisons write X, not an existing GP identity.
	}
	if x86FloatMinMaxPreservesSourceState(ins, arch) {
		return before // No GP destination; this creates no address or backing fact.
	}
	if x86PreservesNumericalSourceState(ins) {
		return before
	}
	if x86WaitPackagePreservesStorage(ins) {
		return before // No GP overwrite; this supplies no new address or memory fact.
	}
	if _, valid := x86EnqueueSourceForm(ins, arch); valid {
		return before // Both GP addresses are read-only; submission supplies no memory fact.
	}
	if x86MaskLogicalPreservesStorage(ins) {
		return before // Exact named/raw K-only forms never overwrite a GP identity.
	}
	if x86RawPackedConversionSource(ins, arch) || x86RawPackedReductionSource(ins, arch) {
		return before // Exact physical conversions write no GP or caller-address identity.
	}
	if x86RawPackedDotSource(ins, arch) {
		return before // Preserve only existing identities; no dot-product GP output exists.
	}
	if effect, known, err := x86TypedRegisterQueryByteEffect(ins.Op, ins, arch); known && err == nil {
		for _, output := range effect.operands {
			if index, _, valid := x86ResultGP(output.operand.Reg, output.width, arch); valid && output.write {
				before[index] = false
			}
		}
		return before // Exact query GP footprint; FLAGS stay in the independent descriptor.
	}
	if ins.x86Encoded || ins.x86SourceRaw != nil || ins.x86RawNearReturn != nil ||
		ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride || ins.x86SegmentPrefix != 0 {
		return [16]bool{}
	}
	ins = x86SourceMoveInstruction(ins, arch) // Original source/certificates stay unchanged.
	if _, known, err := x86DuplicateMoveProperties(ins.Op, ins, arch); known && err == nil {
		return before // A validated vector-only write preserves, but never creates, a GP identity.
	}
	if _, known, err := x86InLanePermuteProperties(ins.Op, ins, arch); known && err == nil {
		return before // Named vector selection has no GP output or new address authority.
	}
	if _, known, err := x86MXCSRProperties(ins, arch); known && err == nil {
		return before // All four original m32 opcodes preserve GP identities.
	}
	if form, known, err := x86X87WordProperties(ins, arch); known {
		if err != nil {
			return [16]bool{}
		}
		if form.kind == x86X87StoreStatus && form.operand.Kind == OpReg {
			if index, _, valid := x86ResultGP(form.operand.Reg, 2, arch); valid {
				before[index] = false
			}
		}
		return before // Only FSTSW AX writes a GP; no unrelated identity changes.
	}
	if _, known, err := x86X87ValueProperties(ins, arch); known {
		if err != nil {
			return [16]bool{}
		}
		return before // Typed x87 value forms write no unrelated GP identity.
	}
	if form, known, err := x86ScalarNativeLoadProperties(ins.Op, ins, arch); known && err == nil {
		// The paired typed emitter uses the effective REX byte register,
		// which may be SI/DI rather than the textual DH/BH. This is only
		// its write footprint, not permission to read the native source.
		if destination, _, valid := x86ResultGP(form.destination, form.bytes, arch); valid {
			before[destination] = false
		}
		return before
	}
	if (ins.Op == "REP" || ins.Op == "REPN") && len(ins.Args) == 0 {
		return before // Only an independently accepted source-bound prefix reaches this post-consumer.
	}
	if form, known, err := x86StringInstructionProperties(ins, arch); known && err == nil {
		before[1] = false // A possibly repeated native CX write.
		if form.kind != "lods" {
			before[7] = false
		}
		if form.kind == "cmps" || form.kind == "movs" || form.kind == "lods" {
			before[6] = false
		}
		if form.kind == "lods" {
			before[0] = false
		}
		return before // No implicit GP writes outside this typed footprint.
	}
	if destination, _, _, known := x86LogicalFPLEAWriteShape(ins, arch); known {
		before[destination] = false
		return before // Pure address calculation writes no unrelated GP or FLAGS.
	}
	if destination, _, _, _, known := x86SBLEAWriteShape(ins, arch); known {
		before[destination] = false
		return before // Only this validated destination loses its old address identity.
	}
	if _, known, err := x86SignedIntegerFloatProperties(ins, arch); known && err == nil {
		return before // Signed conversion writes only its typed scalar/vector view.
	}
	if _, known, err := x86DirectionControlProperties(ins.Op, ins, arch); known && err == nil {
		return before // Only DF changes; no GP, pointer or six-status writes.
	}
	if _, known := x86CallerPointerAdvanceProperties(ins, arch); known {
		return before // Only a separately accepted full-word affine transfer preserves it.
	}
	if spec, known, err := amd64PackedStringCompareProperties(ins.Op, ins, arch); known && err == nil {
		output, width, _ := spec.resultEffect()
		if !spec.maskResult {
			if index, _, valid := x86ResultGP(output, int64(width), arch); valid {
				before[index] = false
			}
		}
		return before // Neither the X0 result nor FLAGS write any other GP.
	}
	word := x86ResultPointerWord(arch)
	if form, width, known, err := x86SwapProperties(ins, arch); known {
		if err != nil {
			return [16]bool{}
		}
		if form.nop {
			return before
		}
		first, _, valid := x86ResultGP(form.register.Reg, width, arch)
		if !valid {
			return [16]bool{}
		}
		if form.other.Kind == OpReg {
			last, _, valid := x86ResultGP(form.other.Reg, width, arch)
			if !valid {
				return [16]bool{}
			}
			if width == word {
				before[first], before[last] = before[last], before[first]
				return before
			}
			before[last] = false
		}
		before[first] = false
		return before // A partial or memory overwrite never imports a caller identity.
	}
	move, lea, add, sub := Op("MOVQ"), Op("LEAQ"), Op("ADDQ"), Op("SUBQ")
	if arch == "386" {
		move, lea, add, sub = "MOVL", "LEAL", "ADDL", "SUBL"
	}
	if len(ins.Args) == 2 && ins.Args[1].Kind == OpReg {
		destination, _, valid := x86ResultGP(ins.Args[1].Reg, word, arch)
		if valid {
			first := ins.Args[0]
			switch ins.Op {
			case move:
				before[destination] = x86ResultPointerOperand(first, before, entryFP, arch)
				return before
			case lea:
				base, _, valid := x86ResultGP(first.Mem.Base, word, arch)
				before[destination] = first.Kind == OpMem && first.Mem.Sym == "" && valid && before[base]
				return before // Numerical index/complete address checked by the original transfer.
			case add, sub:
				if ins.Op == add && !before[destination] {
					before[destination] = x86ResultPointerOperand(first, before, entryFP, arch)
				}
				if ins.Op == sub && first.Kind == OpFP && entryFP[first.FPOffset] {
					before[destination] = false // Canceling an actual input pointer consumes its address role.
				}
				if ins.Op == sub && first.Kind == OpReg {
					if source, _, valid := x86ResultGP(first.Reg, word, arch); valid && before[source] {
						before[destination] = false // A proved same-origin difference is numerical.
					}
				}
				return before // Only the separately validated full-word address transform preserves it.
			}
		}
	}
	kill := func(operand Operand, width int64) {
		if operand.Kind == OpReg {
			if root, _, valid := x86ResultGP(operand.Reg, width, arch); valid {
				before[root] = false
			}
		}
	}
	if form, known, err := x86StackWidthProperties(ins, arch); known {
		if err != nil {
			return [16]bool{}
		}
		if form.mode == amd64StackPopValue {
			kill(ins.Args[0], int64(form.bits/8))
		}
		// This post-transfer observes only the GP write footprint. PUSH and
		// FLAGS transport do not overwrite unrelated GP identities; POP's
		// explicit destination does. The independent private-stack proof must
		// still close every input, depth, memory and FLAGS effect first.
		return before
	}
	if form, known, err := x86ImplicitDivideProperties(ins.Op, ins, arch); known && err == nil {
		for _, output := range x86ImplicitDivideWrites(form) {
			kill(output.operand, output.width)
		}
		return before // A native continuation changes only the implicit GP output footprint.
	}
	if effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch); known && err == nil {
		for _, operand := range effect.operands {
			if operand.write {
				kill(operand.operand, operand.width)
			}
		}
		return before
	}
	if form, known, err := x86MoveMaskProperties(ins.Op, ins, arch); known {
		if err != nil || form.byteWidth == 8 {
			return [16]bool{} // Unbound physical MMX is not a caller effect.
		}
		index, valid := amd64VectorRegisterIndex(ins.Args[0].Reg, form.byteWidth)
		destination, _, physical := x86ResultGP(ins.Args[1].Reg, 4, arch)
		if !valid || arch == "386" && index >= 8 || !physical {
			return [16]bool{}
		}
		before[destination] = false // Complete typed r32 output, no other GP writes.
		return before
	}
	if _, known, err := x86BroadcastProperties(ins.Op, ins, arch); known && err == nil {
		return before // Scalar/block/mask inputs never give this vector output a GP write.
	}
	if _, known, err := x86VectorTestProperties(ins.Op, ins, arch); known && err == nil {
		return before // Only FLAGS change; source/memory definedness is checked independently.
	}
	if form, known, err := x86ScalarBitScanProperties(ins.Op, ins, arch); known && err == nil {
		kill(ins.Args[1], int64(form.bits/8))
		return before // Conditional numerical definedness does not widen the write footprint.
	}
	if form, known, err := x86ConditionalSetProperties(ins.Op, ins, arch); known && err == nil {
		kill(form.destination, 1)
		return before
	}
	if _, known, err := x86ScalarCompareProperties(ins.Op, ins, arch); known && err == nil {
		return before
	}
	if width := x86RawReturnScalarMoveBytes(ins.Op); width != 0 && len(ins.Args) == 2 {
		kill(ins.Args[1], width)
		return before
	}
	if form, known, err := x86GPSIMDTransferProperties(ins, arch); known && err == nil && !form.mmx {
		if !form.destinationX {
			kill(ins.Args[1], int64(form.bits/8))
		}
		return before
	}
	if form, known, err := x86ScalarLaneProperties(ins, arch); known && err == nil {
		if !form.insert {
			kill(Operand{Kind: OpReg, Reg: form.transferReg}, int64(form.gpBits/8))
		}
		return before
	}
	if x86CallerVectorMoveKnown(ins) {
		for _, operand := range ins.Args {
			if operand.Kind == OpReg {
				_, vector := amd64VectorRegisterIndex(operand.Reg, amd64VectorByteWidth(operand.Reg))
				_, mask := amd64ParseKReg(operand.Reg)
				if !vector && !mask {
					return [16]bool{} // GP/alias/native banks need their own exact effect.
				}
			}
		}
		return before // Complete shared typed vector-only form, no GP output.
	}
	if ins.Op == OpJMP || isAMD64ConditionalBranch(ins.Op) || ins.Op == OpTEXT || ins.Op == OpLABEL || ins.Op == "NOP" {
		return before
	}
	if _, known, err := x86DirectiveProperties(ins); known && err == nil {
		return before
	}
	return [16]bool{}
}
