package plan9asm

import "fmt"

type arm64AtomicPairKind uint8

const (
	arm64AtomicPairCAS arm64AtomicPairKind = iota
	arm64AtomicPairLoad
	arm64AtomicPairStore
)

type arm64AtomicPairSpec struct {
	kind arm64AtomicPairKind
	bits int
}

// Complete Go asm7 rows 106, 58 and 59, including their oprangeset aliases.
// Acquire/release spellings currently use the lowerer's conservative seq_cst
// semantics; they do not change register banks or source memory footprint.
var arm64AtomicPairSpecs = map[Op]arm64AtomicPairSpec{
	"CASPW":  {arm64AtomicPairCAS, 32},
	"CASPD":  {arm64AtomicPairCAS, 64},
	"LDXPW":  {arm64AtomicPairLoad, 32},
	"LDXP":   {arm64AtomicPairLoad, 64},
	"LDAXPW": {arm64AtomicPairLoad, 32},
	"LDAXP":  {arm64AtomicPairLoad, 64},
	"STXPW":  {arm64AtomicPairStore, 32},
	"STXP":   {arm64AtomicPairStore, 64},
	"STLXPW": {arm64AtomicPairStore, 32},
	"STLXP":  {arm64AtomicPairStore, 64},
}

type arm64AtomicPairForm struct {
	spec     arm64AtomicPairSpec
	memory   MemRef
	expected []Reg
	data     []Reg
	status   Reg
}

// Go asm7 classifies NAME_AUTO after adding autosize - extrasize. obj7's
// logical size is TEXT frame + 8 whenever it creates a frame; its additional
// alignment/FP space cancels in this address rule. Resolve C_ZAUTO before CFG
// effects and lowering, so both see the same physical zero-offset SP address.
func normalizeARM64AtomicPairNamedMemory(fn Func) (Func, error) {
	logicalFrame := int64(0)
	if arm64SourceGoFrame(fn).present {
		if fn.FrameSize < 0 || fn.FrameSize > 1<<63-1-8 {
			return fn, fmt.Errorf("invalid ARM64 paired atomic source frame size %d", fn.FrameSize)
		}
		logicalFrame = fn.FrameSize + 8
	}
	copied := false
	for i, ins := range fn.Instrs {
		spec, ok := arm64AtomicPairSpecs[arm64ControlOp(ins)]
		if !ok || spec.kind != arm64AtomicPairCAS || len(ins.Args) != 3 || ins.Args[1].Kind != OpMem {
			continue
		}
		mem := ins.Args[1].Mem
		if mem.Base != SP || mem.OffRaw == "" {
			continue
		}
		if !arm64NamedStackOffset(mem) {
			return fn, fmt.Errorf("%w: ARM64 CASP named SP displacement is unresolved: %q", ErrProbeNeedsContext, ins.Raw)
		}
		if mem.Off != -logicalFrame {
			return fn, fmt.Errorf("ARM64 CASP named SP displacement %d plus logical Go frame %d is not zero: %q", mem.Off, logicalFrame, ins.Raw)
		}
		if !copied {
			fn.Instrs = append([]Instr(nil), fn.Instrs...)
			copied = true
		}
		args := append([]Operand(nil), ins.Args...)
		args[1].Mem.Base, args[1].Mem.Off, args[1].Mem.OffRaw = "RSP", 0, ""
		fn.Instrs[i].Args = args
	}
	return fn, nil
}

func parseARM64AtomicPairForm(op Op, ins Instr) (arm64AtomicPairForm, bool, error) {
	spec, handled := arm64AtomicPairSpecs[op]
	if !handled {
		return arm64AtomicPairForm{}, false, nil
	}
	form, err := parseARM64AtomicPairOperands(spec, ins)
	if err != nil {
		return arm64AtomicPairForm{}, true, fmt.Errorf("arm64 %s: %w: %q", op, err, ins.Raw)
	}
	return form, true, nil
}

func parseARM64AtomicPairOperands(spec arm64AtomicPairSpec, ins Instr) (arm64AtomicPairForm, error) {
	form := arm64AtomicPairForm{spec: spec}
	if arm64AtomicOpcodeHasSuffix(ins.Op) {
		return form, fmt.Errorf("paired atomic opcode has no suffix")
	}
	switch spec.kind {
	case arm64AtomicPairCAS:
		if len(ins.Args) != 3 || !arm64AtomicRegisterPair(ins.Args[0]) || ins.Args[1].Kind != OpMem || !arm64AtomicRegisterPair(ins.Args[2]) {
			return form, fmt.Errorf("expects register-pair, zero-offset memory, register-pair")
		}
		form.expected, form.memory, form.data = ins.Args[0].RegList, ins.Args[1].Mem, ins.Args[2].RegList
		if err := validateARM64CASPRegisterPair("source", form.expected); err != nil {
			return form, err
		}
		if err := validateARM64CASPRegisterPair("destination", form.data); err != nil {
			return form, err
		}
	case arm64AtomicPairLoad:
		if len(ins.Args) != 2 || ins.Args[0].Kind != OpMem || !arm64AtomicRegisterPair(ins.Args[1]) {
			return form, fmt.Errorf("expects zero-offset memory, register-pair")
		}
		form.memory, form.data = ins.Args[0].Mem, ins.Args[1].RegList
		if err := validateARM64ExclusiveLoadPair(form.data); err != nil {
			return form, err
		}
	case arm64AtomicPairStore:
		if len(ins.Args) != 3 || !arm64AtomicRegisterPair(ins.Args[0]) || ins.Args[1].Kind != OpMem || ins.Args[2].Kind != OpReg {
			return form, fmt.Errorf("expects register-pair, zero-offset memory, status-register")
		}
		form.data, form.memory, form.status = ins.Args[0].RegList, ins.Args[1].Mem, ins.Args[2].Reg
		if err := validateARM64ExclusiveStorePair(form.data, form.memory.Base, form.status); err != nil {
			return form, err
		}
	default:
		return form, fmt.Errorf("unrecognized paired atomic grammar")
	}
	return form, validateARM64AtomicPairMemory(form.memory, spec.kind == arm64AtomicPairCAS)
}

func (form arm64AtomicPairForm) outputRegs() []Reg {
	switch form.spec.kind {
	case arm64AtomicPairCAS:
		return form.expected // CASP writes the expected pair, not the new value.
	case arm64AtomicPairLoad:
		return form.data
	case arm64AtomicPairStore:
		return []Reg{form.status}
	}
	return nil
}

func (state *arm64ControlState) transferAtomicPair(form arm64AtomicPairForm) {
	memory := Operand{Kind: OpMem, Mem: form.memory}
	var observed [2]arm64ControlValue
	if form.spec.kind != arm64AtomicPairStore {
		for i := range observed {
			observed[i] = state.source(arm64ControlElement(memory, int64(i*form.spec.bits/8)), false)
			if form.spec.bits == 32 {
				// Truncating a code address cannot establish an ordinary return.
				observed[i] = arm64ControlUnion(observed[i], arm64ControlExternal())
			}
		}
	}
	if form.spec.kind != arm64AtomicPairLoad {
		value := arm64ControlExternal()
		for _, reg := range form.data {
			if reg != ZR && reg != "RSP" {
				value = arm64ControlUnion(value, arm64ControlRead(state.regs, reg))
			}
		}
		if key := state.memoryKey(memory, false); key != "" {
			state.invalidateOverlappingControlCells(key, int64(2*form.spec.bits/8))
			state.memory[key] = value
		} else {
			state.invalidateUnknownStore(memory, value)
		}
	}
	for i, reg := range form.outputRegs() {
		// Encoding 31 in a data/status bank is ZR, not address-bank SP.
		if reg == ZR || reg == "RSP" {
			continue
		}
		value := arm64ControlExternal()
		if form.spec.kind != arm64AtomicPairStore {
			value = observed[i]
		}
		state.write(Operand{Kind: OpReg, Reg: reg}, value, false)
	}
}
