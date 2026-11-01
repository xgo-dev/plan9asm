package plan9asm

import (
	"fmt"
	"strings"
)

type x86CounterControlSpec struct {
	halfAddress, decrement bool
	condition              string
}

// One complete yloop family owns spelling, count-width and FLAGS roles.
// These descriptors carry no branch-target, caller, raw or storage authority.
func x86CounterControlPropertiesForOpcode(op Op) (x86CounterControlSpec, bool) {
	switch Op(strings.ToUpper(string(op))) {
	case "JCXZW", "JCXZQ":
		return x86CounterControlSpec{}, true
	case "JCXZL":
		return x86CounterControlSpec{halfAddress: true}, true
	case "LOOP":
		return x86CounterControlSpec{decrement: true}, true
	case "LOOPEQ":
		return x86CounterControlSpec{decrement: true, condition: "EQ"}, true
	case "LOOPNE":
		return x86CounterControlSpec{decrement: true, condition: "NE"}, true
	default:
		return x86CounterControlSpec{}, false
	}
}

type x86CounterControlForm struct {
	x86CounterControlSpec
	bits int
}

func x86CounterControlProperties(op Op, ins Instr, arch string) (x86CounterControlForm, bool, error) {
	name := strings.ToUpper(string(op))
	base, _, _ := strings.Cut(name, ".")
	spec, known := x86CounterControlPropertiesForOpcode(Op(base))
	form := x86CounterControlForm{x86CounterControlSpec: spec}
	if !known {
		return form, false, nil
	}
	fail := func(reason string) (x86CounterControlForm, bool, error) {
		return form, true, fmt.Errorf("%s %s %s: %q", arch, op, reason, ins.Raw)
	}
	if arch == "" {
		arch = "amd64" // Preserve the existing x86 source-mode default.
	}
	if name != base || arch != "amd64" && arch != "386" || len(ins.Args) != 1 ||
		ins.Op != "" && !strings.EqualFold(string(ins.Op), name) {
		return fail("requires its complete mode, identity and one branch target")
	}
	target := ins.Args[0]
	valid := target.Kind == OpLabel && target.Sym != "" || target.Kind == OpIdent && target.Ident != ""
	if target.Kind == OpMem {
		memory := target.Mem
		valid = memory.Base == PC && memory.Sym == "" && memory.OffRaw == "" &&
			memory.Index == "" && memory.Scale == 0 && memory.IndexExt == "" && memory.Segment == ""
	}
	if !valid {
		return fail("requires an original local label or instruction-relative PC target")
	}
	if !x86ResultNamedPredicateInstruction(ins) {
		return form, true, fmt.Errorf("%w: counter control needs its original named address-size and source identity", ErrProbeNeedsContext)
	}
	form.bits = int(8 * x86ResultPointerWord(arch))
	if spec.halfAddress {
		form.bits /= 2
	}
	return form, true, nil
}

func x86TypedCounterControlByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	form, known, err := x86CounterControlProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	effect := x86TypedByteEffect{requiresResultProof: true,
		operands: []x86TypedByteOperand{{index: -1, operand: Operand{Kind: OpReg, Reg: CX},
			width: int64(form.bits / 8), read: true, write: form.decrement}}}
	if form.condition != "" {
		effect.flagsRead = x86ByteFlagZF
	}
	return effect, true, nil
}

func x86ResultCounterControlStep(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	effect, known, err := x86TypedCounterControlByteEffect(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	count := effect.operands[0]
	index, mask, valid := x86ResultGP(CX, count.width, arch)
	if !valid || !state.shapeOnly && state.pointerGP[index] || state.flags&effect.flagsRead != effect.flagsRead ||
		!x86ResultRead(count.operand, count.width, state, owned, arch) {
		return false, true
	}
	if count.write {
		if !x86ResultStore(count.operand, count.width, state, owned, 0, arch) {
			return false, true
		}
		state.canonicalGP[index] &^= mask
		if count.width == 4 {
			state.canonicalGP[index] |= 0xf0 // The emitted dword write zeros its upper alias.
		}
		state.callerAddressGP[index], state.callerAddressOrigin[index] = false, 0
		state.resultAddressGP[index] = x86ResultSlotAddress{}
		if state.boolFrameGP != nil {
			state.boolFrameGP[index] = x86ResultSlotAddress{}
		}
	}
	return true, true // All FLAGS and DF survive; no count value or target fact is invented.
}

func (c *amd64Ctx) counterControlCondition(form x86CounterControlForm) (string, error) {
	typ := amd64IntegerTypeForBits(form.bits)
	value, err := c.evalIntSized(Operand{Kind: OpReg, Reg: CX}, typ)
	if err != nil {
		return "", err
	}
	comparison := "eq"
	if form.decrement {
		next := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub %s %s, 1\n", next, typ, value)
		value, comparison = "%"+next, "ne"
		if err := c.storeRegSized(CX, typ, value); err != nil {
			return "", err
		}
	}
	condition := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp %s %s %s, 0\n", condition, comparison, typ, value)
	if form.condition == "" {
		return "%" + condition, nil
	}
	flags, err := c.x86Condition(form.condition)
	if err != nil {
		return "", err
	}
	combined := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %s\n", combined, condition, flags)
	return "%" + combined, nil // The decrement never writes machine FLAGS.
}
