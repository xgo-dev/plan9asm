package plan9asm

import (
	"fmt"
	"strings"
)

type x86ConditionalMoveSpec struct {
	bits      int
	condition string
}

// Each entry is a Go yml_rl row, not a conditional memory-access permission.
// W preserves the other GP bytes. L clears the upper half even on a false
// predicate. Both the source and the old destination are potential inputs.
var x86ConditionalMoveSpecs = map[Op]x86ConditionalMoveSpec{
	"CMOVWCC": {16, "CC"}, "CMOVWCS": {16, "CS"}, "CMOVWEQ": {16, "EQ"}, "CMOVWGE": {16, "GE"},
	"CMOVWGT": {16, "GT"}, "CMOVWHI": {16, "HI"}, "CMOVWLE": {16, "LE"}, "CMOVWLS": {16, "LS"},
	"CMOVWLT": {16, "LT"}, "CMOVWMI": {16, "MI"}, "CMOVWNE": {16, "NE"}, "CMOVWOC": {16, "OC"},
	"CMOVWOS": {16, "OS"}, "CMOVWPC": {16, "PC"}, "CMOVWPL": {16, "PL"}, "CMOVWPS": {16, "PS"},
	"CMOVLCC": {32, "CC"}, "CMOVLCS": {32, "CS"}, "CMOVLEQ": {32, "EQ"}, "CMOVLGE": {32, "GE"},
	"CMOVLGT": {32, "GT"}, "CMOVLHI": {32, "HI"}, "CMOVLLE": {32, "LE"}, "CMOVLLS": {32, "LS"},
	"CMOVLLT": {32, "LT"}, "CMOVLMI": {32, "MI"}, "CMOVLNE": {32, "NE"}, "CMOVLOC": {32, "OC"},
	"CMOVLOS": {32, "OS"}, "CMOVLPC": {32, "PC"}, "CMOVLPL": {32, "PL"}, "CMOVLPS": {32, "PS"},
	"CMOVQCC": {64, "CC"}, "CMOVQCS": {64, "CS"}, "CMOVQEQ": {64, "EQ"}, "CMOVQGE": {64, "GE"},
	"CMOVQGT": {64, "GT"}, "CMOVQHI": {64, "HI"}, "CMOVQLE": {64, "LE"}, "CMOVQLS": {64, "LS"},
	"CMOVQLT": {64, "LT"}, "CMOVQMI": {64, "MI"}, "CMOVQNE": {64, "NE"}, "CMOVQOC": {64, "OC"},
	"CMOVQOS": {64, "OS"}, "CMOVQPC": {64, "PC"}, "CMOVQPL": {64, "PL"}, "CMOVQPS": {64, "PS"},
}

type x86ConditionalMoveForm struct {
	x86ConditionalMoveSpec
	source, destination Operand
}

func x86ConditionalMoveProperties(op Op, ins Instr, arch string) (x86ConditionalMoveForm, bool, error) {
	name := strings.ToUpper(string(op))
	base, _, suffixed := strings.Cut(name, ".")
	spec, known := x86ConditionalMoveSpecs[Op(base)]
	if !known {
		return x86ConditionalMoveForm{}, false, nil
	}
	fail := func(reason string) (x86ConditionalMoveForm, bool, error) {
		return x86ConditionalMoveForm{}, true, fmt.Errorf("%s %s %s: %q", arch, op, reason, ins.Raw)
	}
	if arch != "amd64" && arch != "386" || arch == "386" && spec.bits == 64 || suffixed ||
		ins.Op != "" && !strings.EqualFold(string(ins.Op), name) || len(ins.Args) != 2 {
		return fail("has an unbound mode, suffix, dispatch identity or operand count")
	}
	source, destination := ins.Args[0], ins.Args[1]
	if destination.Kind != OpReg || !isX86YrlRegisterForArch(destination.Reg, arch) {
		return fail("expects a Yrl destination")
	}
	if source.Kind == OpReg {
		if !isX86YrlRegisterForArch(source.Reg, arch) {
			return fail("register source is outside the Go Yml class")
		}
	} else if source.Kind == OpMem {
		if !x86ConditionalMoveOffsetKnown(source.Mem) || source.Mem.IndexExt != "" ||
			source.Mem.Segment != "" && source.Mem.Segment != FS && source.Mem.Segment != GS {
			return fail("has an unresolved or unencodable memory source")
		}
		if err := x86SymbolIndexedMemoryError(source.Mem, arch); err != nil {
			return x86ConditionalMoveForm{}, true, err
		}
		validation := source
		if arch == "386" && strings.HasSuffix(source.Mem.Sym, "(SB)") {
			validation.Mem.Base = "" // Go ignores Reg, not Index, for named memory.
		}
		if !x86PackedShiftMemoryValid(validation, arch) {
			return fail("has an unencodable source address")
		}
	} else if !x86PackedShiftMemoryValid(source, arch) {
		return fail("expects a Yml register or memory source")
	}
	if source.Kind == OpSym {
		if address, err := parseInt(strings.TrimSpace(source.Sym)); err == nil &&
			address != int64(int32(address)) && !(arch == "386" && address == int64(uint32(address))) {
			return fail("absolute source address is outside Go's physical disp32 extent")
		}
	}
	return x86ConditionalMoveForm{spec, source, destination}, true, nil
}

func x86TypedConditionalMoveByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	form, known, err := x86ConditionalMoveProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	width := int64(form.bits / 8)
	return x86TypedByteEffect{operands: []x86TypedByteOperand{
		{index: 0, operand: form.source, width: width, read: true},
		{index: 1, operand: form.destination, width: width, read: true, write: true},
	}, flagsRead: x86ByteConditionFlags(form.condition), requiresResultProof: true}, true, nil
}

func x86CallerConditionalMoveStep(ins *Instr, state *x86SourceStackState, proof *x86GoCallerRegionProof) (bool, bool) {
	form, known, err := x86ConditionalMoveProperties(ins.Op, *ins, "amd64")
	if !known || err != nil || !x86SourceStackNumericFlagsRead(state, x86ByteConditionFlags(form.condition)) {
		return known, false
	}
	width := int64(form.bits / 8)
	if !x86CallerNumericRead(form.destination, width, state) {
		return true, false // Neither possible old pointer bits nor missing bytes are washed away.
	}
	if form.source.Kind == OpMem {
		if !x86CallerOrdinaryMemoryStep(ins, 0, state, proof, width, false) {
			return true, false
		}
	} else if !x86CallerNumericRead(form.source, width, state) {
		return true, false // FP pointer slots are imports only, never CMOV inputs.
	}
	return true, x86CallerNumericWrite(form.destination.Reg, width, state)
}
