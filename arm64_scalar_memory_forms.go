package plan9asm

import (
	"fmt"
	"math"
	"strings"
)

// The seven GP moves share Go asm7's 20/21, 30/31, 22/23,
// 98/99 and 64/65 rows. A long named move is an ordered expansion:
// materialize R27, then read the transfer register. A decoded architectural
// instruction never acquires that source-encoder effect.
type arm64ScalarMemoryForm struct {
	memory         Operand
	data           Reg
	bits           int
	signed, store  bool
	pre, post      bool
	scratch        bool
	scratchKnown   bool
	scratchAddress bool
	scratchBase    Reg
	scratchOffset  int64
}

func arm64ScalarMemoryBits(op Op) (int, bool) {
	switch op {
	case "MOVB", "MOVBU":
		return 8, op == "MOVB"
	case "MOVH", "MOVHU":
		return 16, op == "MOVH"
	case "MOVW", "MOVWU":
		return 32, op == "MOVW"
	case "MOVD":
		return 64, false
	}
	return 0, false
}

func arm64ScalarMoveOperandClassError(op Op, ins Instr) error {
	if bits, _ := arm64ScalarMemoryBits(op); bits == 0 {
		return nil
	}
	// TYPE_FCONST is Go's distinct C_FCON class, not an integer zero or
	// bit-pattern constant. Every scalar move consumer uses this same rule;
	// FMOV retains its separate floating-point grammar.
	for _, operand := range ins.Args {
		if operand.Kind == OpImm && operand.ImmIsFloat {
			return fmt.Errorf("arm64 %s cannot use a floating immediate: %q", op, ins.Raw)
		}
	}
	return nil
}

func parseARM64ScalarMemoryForm(op Op, ins Instr) (f arm64ScalarMemoryForm, handled bool, err error) {
	f.bits, f.signed = arm64ScalarMemoryBits(op)
	if f.bits == 0 || len(ins.Args) != 2 {
		return f, false, nil
	}
	isMemory := func(a Operand) bool {
		return a.Kind == OpMem || a.Kind == OpFP || a.Kind == OpSym &&
			!strings.HasPrefix(strings.TrimSpace(a.Sym), "$")
	}
	f.memory, f.store = ins.Args[0], false
	data := ins.Args[1]
	if isMemory(ins.Args[1]) {
		f.memory, data, f.store = ins.Args[1], ins.Args[0], true
	}
	if !isMemory(f.memory) {
		return f, false, nil
	}
	if err := arm64ScalarMoveOperandClassError(op, ins); err != nil {
		return f, true, err
	}
	invalid := func() (arm64ScalarMemoryForm, bool, error) {
		return f, true, fmt.Errorf("arm64 %s memory operands are outside its Go scalar rows: %q", op, ins.Raw)
	}
	if f.store && data.Kind == OpImm && data.Imm == 0 && data.ImmRaw == "" && !data.ImmIsFloat {
		data = Operand{Kind: OpReg, Reg: ZR}
	}
	if data.Kind != OpReg || !isARM64GeneralOrZeroReg(data.Reg) {
		return invalid()
	}
	if !ins.arm64Encoded && !arm64ScalarMemoryGoRegisterSpelling(ins) {
		return invalid()
	}
	f.data = data.Reg
	suffix := strings.TrimPrefix(string(ins.Op), string(op))
	f.pre, f.post = suffix == ".W", suffix == ".P"
	if suffix != "" && !f.pre && !f.post {
		return invalid()
	}
	if f.memory.Kind == OpSym {
		if strings.ContainsAny(f.memory.Sym, "()") && !strings.HasSuffix(f.memory.Sym, "(SB)") {
			return invalid() // An invalid register memory is not a bare SB alias.
		}
		if f.pre || f.post || f.store && f.data == "R27" {
			return invalid()
		}
		if _, _, ok := parseSBRef(f.memory.Sym); !ok {
			if sourceSymbolOffsetNeedsContext(f.memory.Sym) {
				return f, true, fmt.Errorf("%w: arm64 %s symbol displacement requires generated assembler constants: %q", ErrProbeNeedsContext, op, ins.Raw)
			}
			return invalid()
		}
		// Native ADRP's page identity depends on the actual linked layout.
		// LLVM globals alone do not supply that physical page contract.
		f.scratch, f.scratchAddress = !ins.arm64Encoded, true
		return f, true, nil
	}
	offset := f.memory.FPOffset
	if f.memory.Kind == OpFP {
		if f.pre || f.post {
			return invalid()
		}
		if ins.arm64ScalarMemoryFrameOffset == nil {
			f.scratch, f.scratchAddress = true, true
			return f, true, nil // No guessed physical FP offset/backing identity.
		}
		offset = *ins.arm64ScalarMemoryFrameOffset
	} else {
		mem := f.memory.Mem
		if mem.Sym != "" || mem.Segment != "" || mem.OffRaw != "" ||
			!arm64AddressReg(mem.Base) && mem.Base != ZR {
			return invalid()
		}
		if mem.Base == ZR || mem.Base == "RSP" {
			f.memory.Mem.Base = SP // Encoding 31 is SP in the address bank.
		}
		offset = mem.Off
		if f.pre || f.post {
			// Go regoff narrows to int32 before matching the signed-nine-bit
			// field. This is a source encoding rule, not a wide update.
			offset = int64(int32(offset))
			if mem.Index != "" || offset < -256 || offset > 255 {
				return invalid()
			}
			if !arm64StackReg(f.memory.Mem.Base) && mem.Base == f.data {
				return f, true, fmt.Errorf("arm64 %s writeback has base/data register overlap: %q", op, ins.Raw)
			}
			f.memory.Mem.Off = offset
			return f, true, nil
		}
		if mem.Index != "" {
			if offset != 0 || !isARM64GeneralOrZeroReg(mem.Index) ||
				mem.Scale != 0 && mem.Scale != 1 && mem.Scale != int64(f.bits/8) {
				return invalid()
			}
			switch mem.IndexExt {
			case "", ExtendUXTW, ExtendSXTW, ExtendSXTX:
			case ExtendUXTX:
				if !ins.arm64Encoded { // Go textual UXTX is not its LSL row.
					return invalid()
				}
			default:
				return invalid()
			}
			return f, true, nil
		}
		f.scratchBase = f.memory.Mem.Base
	}
	if ins.arm64Encoded || arm64ScalarMemoryDirectOffset(offset, f.bits) {
		return f, true, nil
	}
	if offset < math.MinInt32 || offset > math.MaxInt32 {
		return f, true, fmt.Errorf("%w: arm64 %s long offset requires its original narrowed Go encoder", ErrProbeNeedsContext, op)
	}
	f.scratch = true
	currentBase, current := arm64ScalarMemoryCurrentScratch(offset, f.bits)
	legacyBase, legacy := arm64ScalarMemoryLegacyScratch(offset, f.bits)
	f.scratchAddress = currentBase || legacyBase
	f.scratchOffset = current
	f.scratchKnown = currentBase == legacyBase && current == legacy
	// FP shadow slots are not the native caller frame's physical SP.
	if f.memory.Kind == OpFP && f.scratchAddress {
		f.scratchKnown = false
	}
	if (!currentBase || !legacyBase) && f.memory.Kind == OpMem &&
		(f.scratchBase == "R27" || f.store && f.data == "R27") {
		return invalid() // Both Go pool paths forbid their REGTMP inputs.
	}
	if !currentBase && !legacyBase && !f.store && f.data == "R27" {
		return f, true, fmt.Errorf("%w: arm64 pool load to R27 differs between original Go encoders", ErrProbeNeedsContext)
	}
	if !f.scratchKnown && f.store && f.data == "R27" {
		return f, true, fmt.Errorf("%w: arm64 store consumes an unproved original Go R27 materialization", ErrProbeNeedsContext)
	}
	return f, true, nil
}

// The public parser keeps historical W aliases for other consumers. In an
// original named Go memory instruction they are not in the asm register map.
// This is only a rejection check, never authority to set decoder/source proof.
func arm64ScalarMemoryGoRegisterSpelling(ins Instr) bool {
	op, rest := splitOpcode(ins.Raw)
	if op != string(ins.Op) {
		return true // A structured public instruction has no raw spelling proof.
	}
	wRegister := func(text string) bool {
		text = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(text), "*"))
		_, register := parseReg(text)
		return register && strings.HasPrefix(strings.ToUpper(text), "W")
	}
	for _, operand := range splitTopLevelCSV(rest) {
		if wRegister(operand) {
			return false
		}
		for remaining := operand; ; {
			start := strings.IndexByte(remaining, '(')
			if start < 0 {
				break
			}
			remaining = remaining[start+1:]
			end := strings.IndexByte(remaining, ')')
			if end < 0 {
				break
			}
			terminal := strings.TrimSpace(remaining[:end])
			if separator := strings.IndexAny(terminal, ".<*"); separator >= 0 {
				terminal = terminal[:separator]
			}
			if wRegister(terminal) {
				return false
			}
			remaining = remaining[end+1:]
		}
	}
	return true
}

func arm64ScalarMemoryDirectOffset(offset int64, bits int) bool {
	width := int64(bits / 8)
	return offset >= -256 && offset <= 255 || offset >= 0 && offset%width == 0 && offset/width <= 4095
}

func arm64ScalarMemoryCurrentScratch(offset int64, bits int) (address bool, value int64) {
	if offset >= -4095 && offset <= 4095 {
		return true, offset
	}
	width := int64(bits / 8)
	if offset < 0 || offset > 0xfff000+0xfff*width {
		return false, offset
	}
	hi := offset - 0xfff*width
	if remainder := offset & (width - 1); remainder > hi {
		hi = remainder
	}
	if hi <= 0xfff {
		return true, hi
	}
	hi = offset - (offset/width&0xfff)*width
	if hi > 0xfff000 {
		hi = 0xfff000
	}
	if hi&^int64(0xfff000) == 0 && (offset-hi)%width == 0 {
		return true, hi
	}
	return false, offset
}

func arm64ScalarMemoryLegacyScratch(offset int64, bits int) (address bool, value int64) {
	width := int64(bits / 8)
	if offset < 0 || offset&(width-1) != 0 {
		return false, offset
	}
	hi := offset - (offset/width&0xfff)*width
	if hi&^int64(0xfff000) != 0 {
		return false, offset
	}
	return true, hi
}

// Resolve Go's AUTO/FP class offsets before any source-frame/CFG proof.
// Keep ordinary typed FP operands intact: their LLVM shadow storage is still
// distinct from a physical native SP. No public input can assert this marker.
func normalizeARM64ScalarMemoryFrame(fn Func) (Func, error) {
	frame := arm64SourceGoFrame(fn)
	frameKnown := arm64SourceFrameFlagsKnown(fn) && fn.FrameSize >= -8 &&
		fn.FrameSize <= math.MaxInt32-24 && fn.FrameSize&7 == 0
	logical, autosize := int64(0), int64(0)
	if frameKnown && frame.present {
		if fn.FrameSize < 0 || fn.FrameSize > math.MaxInt64-32 {
			return fn, fmt.Errorf("invalid ARM64 scalar source frame size %d", fn.FrameSize)
		}
		logical, autosize = fn.FrameSize+8, arm64SourceFrameAutosize(fn.FrameSize)
	}
	copied := false
	for i, ins := range fn.Instrs {
		if !frameKnown {
			for _, operand := range ins.Args {
				if bits, _ := arm64ScalarMemoryBits(arm64ControlOp(ins)); bits == 0 || ins.arm64Encoded {
					break
				}
				if operand.Kind == OpMem && arm64NamedStackOffset(operand.Mem) {
					return fn, fmt.Errorf("%w: ARM64 scalar AUTO needs the original source-frame identity", ErrProbeNeedsContext)
				}
			}
			// An old private marker cannot authorize a changed source frame.
			if ins.arm64ScalarMemoryFrameOffset != nil {
				if !copied {
					fn.Instrs = append([]Instr(nil), fn.Instrs...)
					copied = true
				}
				fn.Instrs[i].arm64ScalarMemoryFrameOffset = nil
			}
			continue
		}
		normalized, changed, err := normalizeARM64ScalarMemoryInstruction(ins, logical, autosize)
		if err != nil {
			return fn, err
		}
		if changed {
			if !copied {
				fn.Instrs = append([]Instr(nil), fn.Instrs...)
				copied = true
			}
			fn.Instrs[i] = normalized
		}
	}
	return fn, nil
}

func normalizeARM64ScalarMemoryInstruction(ins Instr, logical, autosize int64) (Instr, bool, error) {
	if bits, _ := arm64ScalarMemoryBits(arm64ControlOp(ins)); bits == 0 || ins.arm64Encoded || len(ins.Args) != 2 {
		return ins, false, nil
	}
	changed := false
	for j, arg := range ins.Args {
		switch {
		case arg.Kind == OpFP:
			if arg.FPOffset > math.MaxInt64-autosize-8 {
				return ins, false, fmt.Errorf("ARM64 FP source offset overflows")
			}
			offset := arg.FPOffset + autosize + 8
			ins.arm64ScalarMemoryFrameOffset = &offset
			changed = true
		case arg.Kind == OpMem && arm64NamedStackOffset(arg.Mem):
			if string(ins.Op) != string(arm64ControlOp(ins)) || arg.Mem.Index != "" {
				return ins, false, fmt.Errorf("ARM64 scalar AUTO memory has no indexed/writeback Go row: %q", ins.Raw)
			}
			if arg.Mem.Off > math.MaxInt64-logical {
				return ins, false, fmt.Errorf("ARM64 AUTO source offset overflows")
			}
			ins.Args = append([]Operand(nil), ins.Args...)
			ins.Args[j].Mem.Off += logical
			ins.Args[j].Mem.OffRaw = ""
			changed = true
		}
	}
	return ins, changed, nil
}
