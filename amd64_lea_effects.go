package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
)

// Go 1.27's ALEAW/ALEAL/ALEAQ rows all use ym_rl (Ym, Yrl). Address
// calculation and destination width are independent: W preserves the upper
// register, L zero-extends, and Q is available only in 64-bit mode.
func x86LEAWidth(op Op, arch string) int64 {
	switch op {
	case "LEAW":
		return 2
	case "LEAL":
		return 4
	case "LEAQ":
		if arch != "386" {
			return 8
		}
	}
	return 0
}

func x86LEAOperandWidth(ins Instr, arch string) (int64, error) {
	ins = x86LEASourceInstruction(ins)
	width := x86LEAWidth(ins.Op, arch)
	if width == 0 {
		return 0, fmt.Errorf("%s %s has no Go LEA width: %q", arch, ins.Op, ins.Raw)
	}
	if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg || !isX86YrlRegisterForArch(ins.Args[1].Reg, arch) {
		return 0, fmt.Errorf("%s %s expects Ym address and Yrl destination: %q", arch, ins.Op, ins.Raw)
	}
	if bits := ins.x86AddressBits; bits != 0 && (ins.Args[0].Kind != OpMem ||
		!(arch == "386" && bits == 16 || arch != "386" && bits == 32)) {
		return 0, fmt.Errorf("%w: %s %s has an unbound physical address size %d", ErrProbeNeedsContext, arch, ins.Op, bits)
	}
	switch ins.Args[0].Kind {
	case OpMem:
		memory := ins.Args[0].Mem
		if err := x86SymbolIndexedMemoryError(memory, arch); err != nil {
			return 0, err
		}
		if arch == "386" && strings.HasSuffix(memory.Sym, "(SB)") {
			memory.Base = "" // Go's named-memory encoder discards Reg.
		}
		if !x86MemoryRegistersValidForArch(memory, arch) {
			return 0, fmt.Errorf("%s %s source uses an out-of-range address register: %q", arch, ins.Op, ins.Raw)
		}
		if memory.Index != "" && (memory.Index == SP ||
			memory.Scale != 1 && memory.Scale != 2 && memory.Scale != 4 && memory.Scale != 8) {
			return 0, fmt.Errorf("%s %s source has an unencodable SIB index/scale: %q", arch, ins.Op, ins.Raw)
		}
		// asm6.go:asmandsz truncates an AMD64 LEAL displacement to int32.
		// Other AMD64 widths require signed int32; 386 also accepts uint32.
		signed32 := memory.Off == int64(int32(memory.Off))
		unsigned32 := memory.Off == int64(uint32(memory.Off))
		if !(arch != "386" && width == 4) && !signed32 && !(arch == "386" && unsigned32) {
			return 0, fmt.Errorf("%s %s displacement is outside Go's encoded address range: %q", arch, ins.Op, ins.Raw)
		}
	case OpSym:
		if !strings.HasSuffix(strings.TrimSpace(ins.Args[0].Sym), "(SB)") || strings.HasPrefix(strings.TrimSpace(ins.Args[0].Sym), "$") {
			return 0, fmt.Errorf("%s %s source is not a Go SB memory expression: %q", arch, ins.Op, ins.Raw)
		}
		fallthrough
	case OpFP:
		// Bound FP storage and symbol identity remain the actual lowerer's
		// responsibility; this row does not establish pointer provenance.
	default:
		return 0, fmt.Errorf("%s %s expects Ym address and Yrl destination: %q", arch, ins.Op, ins.Raw)
	}
	return width, nil
}

// A bare integer expression is Go's TYPE_MEM/NAME_NONE displacement, not a
// symbol or a dereference for LEA. Normalize only this local operand copy;
// the original opcode, Raw and source/certificate identity remain unchanged.
// Unknown expressions, address immediates and physical decoder roles retain
// their separate grammar instead of acquiring a guessed zero displacement.
func x86LEASourceInstruction(ins Instr) Instr {
	if len(ins.Args) != 2 || ins.Args[0].Kind != OpSym || ins.x86Encoded || ins.x86SourceRaw != nil ||
		ins.x86RawNearReturn != nil || ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride || ins.x86SegmentPrefix != 0 {
		return ins
	}
	if ins.Op != "LEAW" && ins.Op != "LEAL" && ins.Op != "LEAQ" {
		return ins
	}
	value, resolved := parseImmExpr(strings.TrimSpace(ins.Args[0].Sym))
	if !resolved {
		return ins
	}
	ins.Args = append([]Operand(nil), ins.Args...)
	ins.Args[0] = Operand{Kind: OpMem, Mem: MemRef{Off: int64(value)}}
	return ins
}

// Named TYPE_ADDR PARAM/AUTO moves form addresses, never DATA reads. Go's
// progedit rewrites L/Q before table selection; W's Zaut_r emits word LEA.
// This local view keeps the actual Op/Raw untouched for source replay. It
// supplies syntax/width only, not a frame, initialized data or numerical bits.
func x86NamedFrameMoveAddressInstruction(ins Instr, arch string) (Instr, bool, error) {
	if len(ins.Args) != 2 || ins.Args[0].Kind != OpFPAddr && ins.Args[0].Kind != OpSym {
		return ins, false, nil
	}
	op := x86SourceMoveInstruction(ins, arch).Op
	if (op != "MOVW" && op != "MOVL" && op != "MOVQ") || !x86ResultNamedPredicateInstruction(ins) {
		return ins, false, nil
	}
	var address Operand
	switch source := ins.Args[0]; source.Kind {
	case OpFPAddr:
		if !validPPIdentifier(source.FPName) || x86SymbolGoRegisterName(source.FPName) ||
			source.FPName == "FP" || source.FPName == "SB" || source.FPName == "PC" || arch == "amd64" && source.FPName == "g" {
			return ins, true, fmt.Errorf("%w: named MOV FP address requires an original Go symbol", ErrProbeNeedsContext)
		}
		address = source
		address.Kind = OpFP
	case OpSym:
		body := strings.TrimSpace(source.Sym)
		if !strings.HasPrefix(body, "$") {
			return ins, false, nil
		}
		body = strings.TrimSpace(strings.TrimPrefix(body, "$"))
		literal := x86ResultAUTOLiteral.FindStringSubmatch(body)
		if literal == nil {
			return ins, false, nil // SB and unnamed addresses retain their own consumers.
		}
		prefix := strings.TrimSpace(literal[1])
		_, named := parseNamedStackConstantOffset(prefix)
		if validPPIdentifier(prefix) {
			named = true
		}
		if !named {
			return ins, false, nil // MOVW NAME_NONE falls through to TYPE_CONST, not Zaut_r.
		}
		var err error
		address, err = parseOperandForArch(ArchAMD64, body)
		if err != nil || address.Kind != OpMem || address.Mem.Base != SP {
			return ins, true, fmt.Errorf("named MOV frame address has no complete AUTO operand")
		}
	default:
		return ins, false, nil
	}
	// A local opcode view cannot repair stale parsed operands or discard the
	// descriptive Go name. Replay the complete original two-operand spelling.
	rawOp, rest := splitOpcode(ins.Raw)
	literals := splitTopLevelCSV(rest)
	if !strings.EqualFold(rawOp, string(ins.Op)) || len(literals) != len(ins.Args) {
		return ins, true, fmt.Errorf("%w: named MOV frame address lacks its original spelling", ErrProbeNeedsContext)
	}
	for index, literal := range literals {
		parsed, err := parseOperandForArch(Arch(arch), literal)
		if err != nil || !reflect.DeepEqual(parsed, ins.Args[index]) {
			return ins, true, fmt.Errorf("%w: named MOV frame address differs from its original operands", ErrProbeNeedsContext)
		}
	}
	view := ins
	view.Op = Op("LEA" + string(op)[3:])
	view.Args = append([]Operand(nil), ins.Args...)
	view.Args[0] = address
	_, err := x86LEAOperandWidth(view, arch)
	return view, true, err
}

func x86CallerLEAStep(ins *Instr, state *x86SourceStackState) bool {
	form := x86LEASourceInstruction(*ins)
	width, err := x86LEAOperandWidth(form, "amd64")
	if err != nil || form.Args[0].Kind != OpMem || ins.x86AddressBits != 0 {
		return false
	}
	memory := form.Args[0].Mem
	destination, full := x86CallerGP(ins.Args[1].Reg)
	if !full || destination != ins.Args[1].Reg || destination == SP || destination == BP ||
		memory.Sym != "" || memory.Segment != "" {
		return false
	}
	base, _ := x86CallerGP(memory.Base)
	if pointer, present := state.callers[base]; present {
		// Only the full, independently bound caller address survives. A
		// narrowed address must not become numerical initialization; a
		// variable offset cannot borrow this constant-offset certificate.
		if width != 8 || memory.Base != base || memory.Index != "" ||
			memory.Off < -x86SourceStackLimit || memory.Off > x86SourceStackLimit {
			return false
		}
		var valid bool
		pointer, valid = x86CallerPointerShift(pointer, memory.Off)
		if !valid {
			return false
		}
		state.callers[destination] = pointer
		delete(state.known, destination)
		return true
	}
	// Arithmetic modulo the result width depends only on those low input
	// bytes. Multiplication/addition carry cannot invent any higher input
	// dependency. NumericRead still rejects *all* pointer-derived inputs,
	// including an index or a source/destination alias.
	for _, register := range []Reg{memory.Base, memory.Index} {
		if register != "" && !x86CallerNumericRead(Operand{Kind: OpReg, Reg: register}, width, state) {
			return false
		}
	}
	return x86CallerNumericWrite(destination, width, state)
}
