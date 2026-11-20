package plan9asm

import (
	"reflect"
	"strconv"
	"strings"
)

// A complete mode32 rounding leaf can keep two private control words below
// its unchanged SP, within one 386 word. This is not a TEXT/AUTO frame or
// caller-memory authority; a larger negative offset gains no storage rights.
// The closed grammar preserves the saved word, changes only rounding-control
// bits in the second word, and restores control before its sole return.
// Initialization still comes from the paired FNSTCW/result-byte observer.
func x86X87ScopedControlScratchExtent(fn Func, arch string) (int, bool) {
	if arch != "386" || fn.FrameSize != 0 || strings.Contains(fn.Sym, "<") ||
		len(fn.Instrs) < 11 || len(fn.Instrs) > 12 || len(fn.X86RawText) != 0 ||
		fn.x86RawReplay != nil || fn.x86SourceStack != nil || fn.x86FixedLocal != nil ||
		fn.x86DirectTailRoot != nil || fn.x86ContinuationFlow != nil || fn.x86BoolCalls != nil {
		return 0, false
	}
	instructions := fn.Instrs
	if instructions[0].Op != OpTEXT {
		return 0, false
	}
	text := splitTopLevelCSV(strings.TrimSpace(strings.TrimPrefix(instructions[0].Raw, "TEXT")))
	if len(text) != 3 || strings.TrimSpace(text[1]) != "NOSPLIT" && strings.TrimSpace(text[1]) != "4" {
		return 0, false
	}
	// Replay every original instruction, not a rewritten positive TEXT or a
	// projection that hides physical SP, raw instructions, labels or calls.
	var source strings.Builder
	for _, ins := range instructions {
		if !x86ResultNamedPredicateInstruction(ins) || ins.Raw == "" || len(ins.Raw) > (1<<20)-source.Len()-1 {
			return 0, false
		}
		source.WriteString(ins.Raw)
		source.WriteByte('\n')
	}
	parsed, err := Parse(ArchAMD64, source.String())
	if err != nil || len(parsed.Funcs) != 1 || len(parsed.Data) != 0 || len(parsed.Globl) != 0 || len(parsed.UnlinkedPrelude) != 0 {
		return 0, false
	}
	original := parsed.Funcs[0]
	if original.Sym != fn.Sym || original.FrameSize != fn.FrameSize || original.ArgSize != fn.ArgSize ||
		!reflect.DeepEqual(original.Instrs, instructions) {
		return 0, false
	}
	load, save, copy := instructions[1], instructions[2], instructions[3]
	if load.Op != "FMOVD" || len(load.Args) != 2 || load.Args[0].Kind != OpFP || !isX87F0(load.Args[1]) ||
		save.Op != "FSTCW" || len(save.Args) != 1 ||
		copy.Op != "MOVW" || len(copy.Args) != 2 || copy.Args[0].Kind != OpMem || copy.Args[0].Mem != save.Args[0].Mem ||
		copy.Args[1].Kind != OpReg {
		return 0, false
	}
	saved, valid := x86X87ScopedControlCell(save, 0)
	register := copy.Args[1]
	if _, _, gp := x86ResultGP(register.Reg, 2, arch); !valid || !gp || register.Reg == SP {
		return 0, false
	}
	index := 4
	cleared := false
	if instructions[index].Op == "ANDW" {
		ins := instructions[index]
		if len(ins.Args) != 2 || ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" || ins.Args[0].ImmIsFloat ||
			ins.Args[0].Imm != 0xf3ff || ins.Args[1].Kind != OpReg || ins.Args[1].Reg != register.Reg {
			return 0, false
		}
		cleared = true
		index++
	}
	selectMode := instructions[index]
	if selectMode.Op != "ORW" || len(selectMode.Args) != 2 || selectMode.Args[0].Kind != OpImm ||
		selectMode.Args[0].ImmRaw != "" || selectMode.Args[0].ImmIsFloat ||
		selectMode.Args[1].Kind != OpReg || selectMode.Args[1].Reg != register.Reg || selectMode.Args[0].Imm&^0x0c00 != 0 ||
		!cleared && selectMode.Args[0].Imm != 0x0c00 || len(instructions) != index+7 {
		return 0, false
	}
	store, change := instructions[index+1], instructions[index+2]
	round, restore := instructions[index+3], instructions[index+4]
	result, ret := instructions[index+5], instructions[index+6]
	if store.Op != "MOVW" || len(store.Args) != 2 || store.Args[0].Kind != OpReg || store.Args[0].Reg != register.Reg ||
		change.Op != "FLDCW" || len(change.Args) != 1 || change.Args[0].Kind != OpMem || change.Args[0].Mem != store.Args[1].Mem ||
		round.Op != "FRNDINT" || len(round.Args) != 0 ||
		restore.Op != "FLDCW" || len(restore.Args) != 1 || restore.Args[0].Kind != OpMem || restore.Args[0].Mem != save.Args[0].Mem ||
		result.Op != "FMOVDP" || len(result.Args) != 2 || !isX87F0(result.Args[0]) || result.Args[1].Kind != OpFP ||
		ret.Op != OpRET || len(ret.Args) != 0 {
		return 0, false
	}
	temporary, valid := x86X87ScopedControlCell(store, 1)
	if !valid || saved < temporary+2 && temporary < saved+2 {
		return 0, false
	}
	for _, consumer := range []struct {
		instruction Instr
		offset      int64
	}{{copy, saved}, {change, temporary}, {restore, saved}} {
		if offset, valid := x86X87ScopedControlCell(consumer.instruction, 0); !valid || offset != consumer.offset {
			return 0, false
		}
	}
	for _, instruction := range []Instr{save, change, restore} {
		if _, known, err := x86X87WordProperties(instruction, arch); !known || err != nil {
			return 0, false
		}
	}
	if temporary < saved {
		saved = temporary
	}
	return int(-saved), true
}

func x86X87ScopedControlCell(ins Instr, index int) (int64, bool) {
	arg := ins.Args[index]
	if arg.Kind != OpMem || arg.Mem.Base != SP || arg.Mem.Off < -4 || arg.Mem.Off > -2 ||
		arg.Mem.Sym != "" || arg.Mem.OffRaw != "" || arg.Mem.Index != "" || arg.Mem.IndexExt != "" ||
		arg.Mem.Segment != "" || arg.Mem.Scale != 0 {
		return 0, false
	}
	fields := strings.Fields(ins.Raw)
	if len(fields) < 2 {
		return 0, false
	}
	operands := splitTopLevelCSV(strings.TrimSpace(ins.Raw[len(fields[0]):]))
	if len(operands) != len(ins.Args) {
		return 0, false
	}
	literal := x86ResultAUTOLiteral.FindStringSubmatch(operands[index])
	if literal == nil {
		return 0, false
	}
	offset, err := strconv.ParseInt(strings.TrimSpace(literal[1]), 0, 64)
	return offset, err == nil && offset == arg.Mem.Off
}
