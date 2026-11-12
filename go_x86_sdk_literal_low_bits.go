package plan9asm

import "strings"

type x86SDKLiteralLowBits struct {
	Operation   Op
	Mask, Value uint64
	Bytes       int64
	Symbol      string
}

// Minima are supplied only by the independent original-linked layout binder.
// This private proof itself creates no source, storage or LLVM authority.
func proveX86SDKLiteralAccessesWithMinima(fn Func, sig FuncSig, arch string, literals map[string]int64, minima map[string]uint32) ([]x86SDKLiteralAccess, error) {
	for symbol, floor := range minima {
		if floor == 0 || floor&(floor-1) != 0 || literals[symbol] <= 0 ||
			uint64(floor) > uint64(goAssemblyDataAlignment(Arch(arch), literals[symbol])) {
			return nil, numericalSBContext("private literal minimum exceeds its registered emitted floor")
		}
	}
	return proveX86SDKLiteralAccessesAtMinimum(fn, sig, arch, literals, minima)
}

func x86SDKLiteralLowBitStep(ins Instr, state *x86SDKLiteralState, fn Func, sig FuncSig, arch string) (*x86SDKLiteralLowBits, bool, error) {
	word := x86ResultPointerWord(arch)
	if form, known, err := x86ConditionalSetProperties(ins.Op, ins, arch); known && err == nil &&
		form.destination.Kind == OpFP && arch == "386" && x86SDKLiteralBoolPredicateRole(fn, sig, arch) && form.destination.FPOffset == 0 {
		return nil, true, nil // No literal GP/FLAGS effect; the separate typed bool-byte role owns this result.
	}
	if form, known, err := x86ConditionalSetProperties(ins.Op, ins, arch); known && err == nil && form.destination.Kind == OpReg {
		root, mask, valid := x86ResultGP(form.destination.Reg, 1, arch)
		if valid && state.gp[root].symbol != "" {
			value := state.gp[root]
			value.bad, value.bitsOnly = true, false
			value.lowMask, value.lowValue = 0, 0
			value.hasMinimum = false
			value.lowIndependent = value.lowIndependent || mask&1 != 0
			state.gp[root] = value
			return nil, true, nil // Canonicality/FLAGS are proved independently.
		}
	}
	read := func(operand Operand) (int, x86SDKLiteralValue, bool) {
		if operand.Kind != OpReg {
			return 0, x86SDKLiteralValue{}, false
		}
		root, _, valid := x86ResultGP(operand.Reg, word, arch)
		return root, state.gp[root], valid
	}
	if form, known, err := x86LockScalarRMWProperties(ins.Op, ins, arch); known && err == nil && form.spec.stem == "OR" {
		_, first, validSource := read(form.source)
		destination, previous, validDestination := read(form.destination)
		if first.symbol == "" && previous.symbol == "" {
			return nil, false, nil
		}
		if !x86SDKLiteralBoolPredicateRole(fn, sig, arch) ||
			int64(form.spec.bits/8) != word || !validSource || !validDestination || first.symbol == "" || previous.symbol == "" ||
			!first.hasMinimum || !previous.hasMinimum || first.bad && !first.bitsOnly || previous.bad && !previous.bitsOnly {
			return nil, true, numericalSBContext("private literal OR needs two sealed minimum-floor bool-predicate carriers")
		}
		mask := first.lowMask & previous.lowMask
		value := (first.lowValue | previous.lowValue) & mask
		previous.lowMask, previous.lowValue, previous.bitsOnly, previous.bad, previous.lowIndependent = mask, value, true, true, false
		state.gp[destination], state.compared = previous, false
		// Register OR proves CF=OF=0 independently of any address. Z/S/P
		// still depend on uncovered full-address bits; AF is undefined and
		// remains rejected by the separate typed initialization domain.
		state.opaqueFlags = x86ByteFlagZF | x86ByteFlagSF | x86ByteFlagPF
		return &x86SDKLiteralLowBits{Operation: ins.Op, Mask: mask, Value: value, Bytes: word, Symbol: previous.symbol}, true, nil
	}
	if form, known, err := x86ScalarCompareProperties(ins.Op, ins, arch); known && err == nil && form.test {
		root, _, valid := x86ResultGP(form.args[1].Reg, int64(form.bits/8), arch)
		if form.args[1].Kind != OpReg || !valid {
			return nil, false, nil
		}
		previous := state.gp[root]
		if previous.symbol == "" {
			return nil, false, nil
		}
		if !x86SDKLiteralBoolPredicateRole(fn, sig, arch) || form.args[0].Kind != OpImm ||
			!previous.hasMinimum || previous.bad && !previous.bitsOnly {
			return nil, true, numericalSBContext("private literal TEST needs its complete sealed minimum-floor bool predicate")
		}
		mask := uint64(form.args[0].Imm)
		if form.bits < 64 {
			mask &= (uint64(1) << uint(form.bits)) - 1
		}
		shift := uint(8 * fixedLocalBooleanShift(form.args[1].Reg))
		if mask&^(previous.lowMask>>shift) != 0 {
			return nil, true, numericalSBContext("private literal TEST observes bits outside its guaranteed minimum")
		}
		state.compared = false
		state.opaqueFlags = 0 // Only a completely covered mask clears its address taint.
		return &x86SDKLiteralLowBits{Operation: ins.Op, Mask: mask, Value: previous.lowValue >> shift & mask, Bytes: int64(form.bits / 8), Symbol: previous.symbol}, true, nil
	}
	return nil, false, nil
}

// Every typed reader shares this orthogonal provenance query. This does not
// initialize FLAGS or numerical bytes; ordinary source/result transfer remains
// responsible for the complete instruction and its defined input effects.
func x86SDKLiteralFlagReads(ins Instr, arch string) uint8 {
	if form, known, err := x86ConditionalSetProperties(ins.Op, ins, arch); known && err == nil {
		return x86ByteConditionFlags(form.condition)
	}
	if isAMD64ConditionalBranch(ins.Op) {
		return x86ByteBranchFlags(ins.Op)
	}
	if effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch); known && err == nil {
		return effect.flagsRead
	}
	if len(ins.Args) == 0 {
		switch strings.ToUpper(string(ins.Op)) {
		case "LAHF":
			return x86ByteFlagCF | x86ByteFlagPF | x86ByteFlagAF | x86ByteFlagZF | x86ByteFlagSF
		case "PUSHF", "PUSHFL", "PUSHFQ":
			return x86ByteFlagsAll
		case "CMC":
			return x86ByteFlagCF
		}
	}
	return 0
}

func x86SDKLiteralIndependentFlagWrites(ins Instr, state *x86SDKLiteralState, arch string) {
	if _, known, err := x86ScalarCompareProperties(ins.Op, ins, arch); known && err == nil {
		state.opaqueFlags = 0 // Its numerical operands were independently checked.
		return
	}
	if effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch); known && err == nil {
		state.opaqueFlags &^= effect.flagsDefined | effect.flagsKilled
	}
}
