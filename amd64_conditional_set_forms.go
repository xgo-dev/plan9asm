package plan9asm

import (
	"fmt"
	"strings"
)

// Both reviewed Go encoders use yscond: one Ymb destination, one byte
// written, no input data operand and no flags output. This grammar establishes
// neither initialized flags nor any authority for the destination address.
var x86ConditionalSetConditions = map[Op]string{
	"SETCC": "CC", "SETCS": "CS", "SETEQ": "EQ", "SETGE": "GE",
	"SETGT": "GT", "SETHI": "HI", "SETLE": "LE", "SETLS": "LS",
	"SETLT": "LT", "SETMI": "MI", "SETNE": "NE", "SETOC": "OC",
	"SETOS": "OS", "SETPC": "PC", "SETPL": "PL", "SETPS": "PS",
}

type x86ConditionalSetForm struct {
	condition   string
	destination Operand
}

func x86ConditionalSetProperties(op Op, ins Instr, arch string) (x86ConditionalSetForm, bool, error) {
	var form x86ConditionalSetForm
	name := strings.ToUpper(string(op))
	base := strings.SplitN(name, ".", 2)[0]
	condition, recognized := x86ConditionalSetConditions[Op(base)]
	if !recognized {
		return form, false, nil
	}
	fail := func(reason string) (x86ConditionalSetForm, bool, error) {
		return form, true, fmt.Errorf("%s %s %s: %q", arch, op, reason, ins.Raw)
	}
	if arch != "amd64" && arch != "386" || name != base ||
		ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return fail("has an unbound mode, suffix or dispatch identity")
	}
	if len(ins.Args) != 1 {
		return fail("expects one Ymb destination")
	}
	dst := ins.Args[0]
	if dst.Kind == OpReg {
		if !isGoYmbRegisterForArch(dst.Reg, arch) {
			return fail("register is outside the Go Ymb class")
		}
	} else if !isAMD64MemoryOperand(dst) {
		return fail("expects a Ymb register or memory destination")
	}
	if dst.Kind == OpMem {
		memory := dst.Mem
		if err := x86SymbolIndexedMemoryError(memory, arch); err != nil {
			return form, true, err
		}
		if arch == "386" && strings.HasSuffix(memory.Sym, "(SB)") {
			memory.Base = "" // The named-memory encoder discards this annotation.
		}
		if !x86MemoryRegistersValidForArch(memory, arch) || memory.Index == SP ||
			memory.Index != "" && memory.Scale != 1 && memory.Scale != 2 && memory.Scale != 4 && memory.Scale != 8 ||
			memory.Off != int64(int32(memory.Off)) && !(arch == "386" && memory.Off == int64(uint32(memory.Off))) {
			return fail("has an unencodable memory address")
		}
	}
	form.condition, form.destination = condition, dst
	return form, true, nil
}

func x86CallerConditionalSetStep(ins *Instr, state *x86SourceStackState, proof *x86GoCallerRegionProof) (bool, bool) {
	form, recognized, err := x86ConditionalSetProperties(ins.Op, *ins, "amd64")
	if !recognized || err != nil || !x86SourceStackNumericFlagsRead(state, x86ByteConditionFlags(form.condition)) {
		return recognized, false
	}
	if form.destination.Kind == OpReg {
		return true, x86CallerNumericWrite(form.destination.Reg, 1, state)
	}
	return true, x86CallerOrdinaryMemoryStep(ins, 0, state, proof, 1, true)
}

// Only the paired lowering may continue an actual volatile native-byte store.
// FLAGS and incoming address identity must already exist; no logical memory,
// canonical result, caller envelope or pointer bound is produced here.
func x86LoweredNativeConditionalSet(ins Instr, state *x86ResultState, arch string) (bool, bool) {
	form, known, err := x86ConditionalSetProperties(ins.Op, ins, arch)
	if !known || err != nil || form.destination.Kind != OpMem || !x86OrdinaryNativeMemoryOperand(form.destination, arch) {
		return false, false
	}
	required := x86ByteConditionFlags(form.condition)
	return x86ResultNamedPredicateInstruction(ins) && ins.x86NumericalRead == nil &&
		required != 0 && state.flags&required == required &&
		x86ResultIncomingPointerAddressIdentity(form.destination, state, arch), true
}
