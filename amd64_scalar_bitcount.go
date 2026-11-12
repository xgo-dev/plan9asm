package plan9asm

import (
	"fmt"
	"strings"
)

type x86ScalarBitCountKind uint8

const (
	x86PopulationCount x86ScalarBitCountKind = iota
	x86LeadingZeroCount
	x86TrailingZeroCount
)

type x86ScalarBitCountSpec struct {
	bits int
	kind x86ScalarBitCountKind
}

// Complete Go yml_rl/ycrc32l scalar count rows. Shape, lowering and numerical
// byte effects share this table; it grants no native memory/caller permission.
var x86ScalarBitCountSpecs = map[Op]x86ScalarBitCountSpec{
	"POPCNTW": {16, x86PopulationCount}, "POPCNTL": {32, x86PopulationCount}, "POPCNTQ": {64, x86PopulationCount},
	"LZCNTW": {16, x86LeadingZeroCount}, "LZCNTL": {32, x86LeadingZeroCount}, "LZCNTQ": {64, x86LeadingZeroCount},
	"TZCNTW": {16, x86TrailingZeroCount}, "TZCNTL": {32, x86TrailingZeroCount}, "TZCNTQ": {64, x86TrailingZeroCount},
}

func x86ScalarBitCountProperties(op Op, ins Instr, arch string) (x86ScalarBitCountSpec, bool, error) {
	name, _, dotted := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := x86ScalarBitCountSpecs[Op(name)]
	if !known {
		return spec, false, nil
	}
	fail := func() (x86ScalarBitCountSpec, bool, error) {
		return spec, true, fmt.Errorf("%s %s outside Go scalar bit-count grammar: %q", arch, op, ins.Raw)
	}
	if arch != "amd64" && arch != "386" || arch == "386" && spec.bits == 64 || dotted ||
		len(ins.Args) != 2 || ins.Op != "" && !strings.EqualFold(string(ins.Op), name) {
		return fail()
	}
	source, destination := ins.Args[0], ins.Args[1]
	if destination.Kind != OpReg || !isX86YrlRegisterForArch(destination.Reg, arch) {
		return fail()
	}
	if source.Kind == OpReg {
		if !isX86YrlRegisterForArch(source.Reg, arch) {
			return fail()
		}
	} else if !isAMD64MemoryOperand(source) ||
		source.Kind == OpSym && strings.HasPrefix(strings.TrimSpace(source.Sym), "$") {
		return fail()
	}
	if source.Kind == OpMem && !x86MemoryRegistersValidForArch(source.Mem, arch) {
		return fail()
	}
	return spec, true, nil
}

func x86TypedScalarBitCountByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	spec, known, err := x86ScalarBitCountProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	defined := x86ByteFlagCF | x86ByteFlagZF
	if spec.kind == x86PopulationCount {
		defined = x86ByteFlagsAll
	}
	width := int64(spec.bits / 8)
	return x86TypedByteEffect{
		operands: []x86TypedByteOperand{
			{index: 0, operand: ins.Args[0], width: width, read: true},
			{index: 1, operand: ins.Args[1], width: width, write: true},
		},
		flagsDefined: defined,
		flagsKilled:  x86ByteFlagsAll,
	}, true, nil
}

func (c *amd64Ctx) lowerScalarBitCount(op Op, ins Instr) (bool, bool, error) {
	spec, known, err := x86ScalarBitCountProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	typ := amd64IntegerTypeForBits(spec.bits)
	var value string
	if isAMD64MemoryOperand(ins.Args[0]) {
		bytes, readErr := c.loadX86PackedShiftBytes(ins.Args[0], spec.bits/8, true)
		err = readErr
		if err == nil {
			integer := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to %s\n", integer, spec.bits/8, bytes, typ)
			value = "%" + integer
		}
	} else {
		value, err = c.evalIntSized(ins.Args[0], typ)
	}
	if err != nil {
		return true, false, err
	}
	count := c.newTmp()
	if spec.kind == x86PopulationCount {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.ctpop.%s(%s %s)\n", count, typ, typ, typ, value)
	} else {
		intrinsic := "cttz"
		if spec.kind == x86LeadingZeroCount {
			intrinsic = "ctlz"
		}
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.%s.%s(%s %s, i1 false)\n", count, typ, intrinsic, typ, typ, value)
	}
	inputZero := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, 0\n", inputZero, typ, value)
	if spec.kind == x86PopulationCount {
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", inputZero, c.flagsZSlot)
		c.clearX86StatusFlags(x86StatusAll &^ x86StatusZF)
	} else {
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", inputZero, c.flagsCFSlot)
		zero := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq %s %%%s, 0\n", zero, typ, count)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zero, c.flagsZSlot)
	}
	return true, false, c.storeRegSized(ins.Args[1].Reg, typ, "%"+count)
}

// Only the paired exact volatile emitter supplies native numerical bytes.
// Widths, writes and defined/killed FLAGS remain the complete typed effect;
// standalone queries and callers acquire no pointer or memory permission.
func x86LoweredScalarBitCountNativeRead(ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) (bool, bool) {
	effect, known, err := x86TypedScalarBitCountByteEffect(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	if ins.Args[0].Kind != OpMem || ins.Args[0].Mem.Sym != "" {
		return false, false
	}
	for _, operand := range effect.operands {
		if operand.read && !x86ResultReadWithNativeContinuation(ins, operand.operand, operand.width, state, owned, arch, true) {
			return false, true
		}
	}
	for _, operand := range effect.operands {
		if operand.write && !x86ResultStore(operand.operand, operand.width, state, owned, resultOffset, arch) {
			return false, true
		}
	}
	state.flags = state.flags&^effect.flagsKilled | effect.flagsDefined
	return true, true
}
