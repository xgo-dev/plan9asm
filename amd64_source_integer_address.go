package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
)

// Go's TYPE_ADDR/NAME_NONE is not uniformly an effective address. obj6.progedit
// rewrites MOVL/Q to LEAL/Q before asm6.oclass falls through to TYPE_CONST for
// other opcodes. This source adapter covers the finite scalar integer rows
// below; it is not a memory, caller, raw-encoder or source-authentication proof.
// Named SB/AUTO/FP operands retain their existing independent consumers.
func x86UnnamedSourceAddress(operand Operand) (memory MemRef, matched bool, err error) {
	if operand.Kind != OpSym || !strings.HasPrefix(strings.TrimSpace(operand.Sym), "$") {
		return MemRef{}, false, nil
	}
	body := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(operand.Sym), "$"))
	memory, matched, err = parseX86SourceRegisterMemory(body)
	if err != nil || !matched {
		return memory, matched, err
	}
	if x86SourceMemoryHasSegment(memory) {
		return MemRef{}, true, fmt.Errorf("%w: unnamed x86 address has an unbound segment/TLS producer: %q", ErrProbeNeedsContext, operand.Sym)
	}
	return memory, true, nil
}

func x86UnnamedSourceAddressInMode(operand Operand, arch string) (MemRef, bool, error) {
	if operand.Kind != OpSym || !strings.HasPrefix(strings.TrimSpace(operand.Sym), "$") {
		return x86UnnamedSourceAddress(operand)
	}
	normalized := operand
	normalized.Sym = normalizeGoGRegister(ArchAMD64, operand.Sym)
	memory, matched, err := x86UnnamedSourceAddress(normalized)
	if err != nil || !matched || normalized.Sym == operand.Sym {
		return memory, matched, err
	}
	if arch != "amd64" {
		return MemRef{}, true, fmt.Errorf("x86 source g register annotation is not registered in %s mode: %q", arch, operand.Sym)
	}
	return memory, true, nil
}

// registerIndirect leaves a missing second-group multiplier at zero. This is
// valid parser metadata, not an encodable SIB scale. TYPE_CONST may ignore it;
// physical memory and MOVL/Q's derived LEA must validate it independently.
func parseX86SourceRegisterMemory(body string) (memory MemRef, matched bool, err error) {
	return parseX86SourceRegisterMemorySyntax(body, false)
}

// Inventories retain a valid unresolved displacement without inventing its
// numerical value. TYPE_ADDR consumers still use the strict wrapper above;
// every translation API separately rejects OffRaw before raw normalization.
func parseX86SourceRegisterMemorySyntax(body string, retainUnresolved bool) (memory MemRef, matched bool, err error) {
	if group := x86SymbolPseudoGroup.FindStringSubmatchIndex(body); group != nil {
		prefix := strings.TrimSpace(body[:group[0]])
		if _, constant := parseImmExpr(prefix); prefix != "" && !constant {
			// SP in the second physical group is an Index, not an AUTO
			// role. The prefix before the first pseudo spelling contains
			// no pseudo group, so this check cannot recursively nest.
			_, physical, prefixErr := parseX86SourceRegisterMemorySyntax(prefix, retainUnresolved)
			if !physical {
				return MemRef{}, false, nil // Complete named SB/AUTO/FP role, including indexes.
			}
			if prefixErr != nil {
				return MemRef{}, true, prefixErr
			}
		}
	}
	for open := 0; open < len(body); open++ {
		if body[open] != '(' {
			continue
		}
		prefix := strings.TrimSpace(body[:open])
		value, constant := parseImmExpr(prefix)
		if prefix == "" {
			constant = true
		}
		if !constant {
			// Named AUTO and SB/FP roles belong to their own consumers. An
			// ordinary unresolved displacement remains syntax only: validate
			// every register group below and retain the original expression.
			if register, _, _, _, groupErr := parseX86SymbolRegisterGroup(body[open:]); groupErr == nil && register != SP {
				if !retainUnresolved || !x86SourceDisplacementNeedsContext(prefix) {
					return MemRef{}, true, fmt.Errorf("%w: unresolved x86 source address displacement: %q", ErrProbeNeedsContext, body)
				}
				memory.OffRaw = prefix
			} else {
				continue // An expression parenthesis or a named address.
			}
		}
		register, scale, scaled, rest, parseErr := parseX86SymbolRegisterGroup(body[open:])
		if parseErr != nil {
			// A parenthesized displacement expression precedes, rather than
			// supplies, the register groups (for example $(1<<4)(AX)).
			if prefix == "" {
				depth, end := 0, -1
				for offset, character := range body[open:] {
					if character == '(' {
						depth++
					} else if character == ')' {
						depth--
						if depth == 0 {
							end = open + offset + 1
							break
						}
					}
				}
				if end > open {
					if _, expression := parseImmExpr(body[open:end]); expression ||
						x86SourceDisplacementNeedsContext(body[open:end]) {
						continue
					}
				}
			}
			return MemRef{}, true, parseErr
		}
		memory.Off = int64(value)
		if scaled {
			memory.Index, memory.Scale = register, scale
		} else {
			memory.Base = register
			if rest != "" {
				register, scale, _, rest, parseErr = parseX86SymbolRegisterGroup(rest)
				if parseErr != nil {
					return MemRef{}, true, parseErr
				}
				memory.Index, memory.Scale = register, scale
			}
		}
		if rest != "" {
			return MemRef{}, true, fmt.Errorf("unnamed x86 address has extra register groups: %q", body)
		}
		return memory, true, nil
	}
	return MemRef{}, false, nil
}

func x86SourceDisplacementNeedsContext(displacement string) bool {
	// go_tls.h's function-like g(r) macro has not been expanded in a raw
	// source inventory. It is not the amd64 g register in this position.
	return strings.TrimSpace(displacement) == "g" || memoryOffsetExpressionNeedsContext(displacement)
}

func unresolvedX86MemoryOffsetError(memory MemRef) error {
	if memory.OffRaw == "" {
		return nil
	}
	if memory.Base == SP {
		if validPPIdentifier(memory.OffRaw) && memory.Off == 0 {
			return nil // Bare NAME_AUTO supplies its descriptive name and offset zero.
		}
		if offset, named := parseNamedStackConstantOffset(memory.OffRaw); named && offset == memory.Off {
			return nil // Resolved descriptive C_AUTO offset, not a missing constant.
		}
	}
	return fmt.Errorf("%w: unresolved x86 memory offset %q", ErrProbeNeedsContext, memory.OffRaw)
}

func x86SourceMemoryHasSegment(memory MemRef) bool {
	for _, register := range []Reg{memory.Base, memory.Index} {
		switch register {
		case CS, DS, ES, SS, FS, GS, "TLS":
			return true
		}
	}
	return false
}

func validateX86SourceMemoryScale(ins Instr) error {
	if ins.x86Encoded || ins.x86SourceRaw != nil {
		return nil // A decoded instruction retains its separate physical contract.
	}
	for _, operand := range ins.Args {
		if operand.Kind != OpMem || operand.Mem.Sym != "" || operand.Mem.Segment != "" || x86SourceMemoryHasSegment(operand.Mem) {
			continue // Not an ordinary NAME_NONE SIB memory operand.
		}
		memory := operand.Mem
		if memory.Index != "" && (memory.Index == SP || memory.Scale != 1 && memory.Scale != 2 && memory.Scale != 4 && memory.Scale != 8) {
			return fmt.Errorf("x86 source memory has an unencodable SIB index/scale: %q", ins.Raw)
		}
	}
	return nil
}

func normalizeX86SourceIntegerAddress(ins Instr, arch string) (Instr, bool, error) {
	var index = -1
	var memory MemRef
	for position, operand := range ins.Args {
		address, matched, err := x86UnnamedSourceAddressInMode(operand, arch)
		if err != nil {
			return ins, false, err
		}
		if !matched {
			continue
		}
		if index >= 0 {
			return ins, false, fmt.Errorf("x86 integer source row cannot contain multiple TYPE_ADDR constants: %q", ins.Raw)
		}
		index, memory = position, address
	}
	if index < 0 {
		return ins, false, nil
	}
	if ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride {
		return ins, false, fmt.Errorf("%w: source TYPE_ADDR has an unbound physical address-size override", ErrProbeNeedsContext)
	}
	if ins.x86Encoded || ins.x86SourceRaw != nil {
		return ins, false, fmt.Errorf("%w: a source TYPE_ADDR adapter cannot replace a decoded physical instruction", ErrProbeNeedsContext)
	}
	if arch != "amd64" && arch != "386" {
		return ins, false, fmt.Errorf("unsupported x86 source mode %q", arch)
	}
	derived := ins
	derived.Args = append([]Operand(nil), ins.Args...)
	op := strings.ToUpper(string(x86SourceMoveInstruction(ins, arch).Op))
	if op == "MOVL" || op == "MOVQ" {
		if len(ins.Args) != 2 || index != 0 {
			return ins, false, fmt.Errorf("x86 MOV address rewrite requires source and GP destination: %q", ins.Raw)
		}
		derived.Op = Op("LEA" + op[3:])
		derived.Args[index] = Operand{Kind: OpMem, Mem: memory}
		if _, err := x86LEAOperandWidth(derived, arch); err != nil {
			return ins, false, err
		}
		return derived, true, nil
	}
	value := memory.Off
	if arch == "386" {
		value = int64(int32(value)) // asm6.oclass applies this before class selection.
	}
	derived.Args[index] = Operand{Kind: OpImm, Imm: value}
	if err := validateX86SourceIntegerImmediateRow(derived, arch, index); err != nil {
		return ins, false, err
	}
	// All audited Q-width arithmetic/TEST/CMP/IMUL/PUSH rows encode imm32
	// and the processor sign-extends it. Shift/bit counts remain imm8.
	if strings.HasSuffix(op, "Q") {
		switch strings.TrimSuffix(op, "Q") {
		case "ADD", "SUB", "ADC", "SBB", "AND", "OR", "XOR", "CMP", "TEST", "IMUL", "IMUL3", "PUSH":
			derived.Args[index].Imm = int64(int32(value))
		}
	}
	return derived, true, nil
}

// Validate the source role before changing Kind. In particular an x87 or SSE
// memory-only row must never inherit a permissive FLOAT-immediate lowerer.
func validateX86SourceIntegerImmediateRow(ins Instr, arch string, index int) error {
	op := strings.ToUpper(string(ins.Op))
	fail := func(reason string) error {
		return fmt.Errorf("%w: %s unnamed TYPE_ADDR integer row: %s: %q", ErrProbeNeedsContext, op, reason, ins.Raw)
	}
	if len(op) < 2 || strings.Contains(op, ".") {
		return fail("opcode/suffix is outside the audited scalar class")
	}
	bits := map[byte]int{'B': 8, 'W': 16, 'L': 32, 'Q': 64}[op[len(op)-1]]
	stem := op[:len(op)-1]
	if bits == 0 || bits == 64 && arch == "386" {
		return fail("operand width has no physical source-mode row")
	}
	integer32 := func(value int64) bool {
		return arch == "386" || value >= -2147483648 && value <= 4294967295
	}
	registerOrMemory := func(operand Operand) bool {
		if operand.Kind == OpReg {
			if bits == 8 {
				return isGoYmbRegisterForArch(operand.Reg, arch)
			}
			return isX86YrlRegisterForArch(operand.Reg, arch)
		}
		return isAMD64MemoryOperand(operand)
	}
	value := ins.Args[index].Imm
	switch stem {
	case "MOV", "ADD", "SUB", "ADC", "SBB", "AND", "OR", "XOR", "TEST":
		if len(ins.Args) != 2 || index != 0 || !registerOrMemory(ins.Args[1]) || !integer32(value) {
			return fail("does not match Yi32 → Ymb/Yml")
		}
		if stem == "MOV" && bits != 8 && bits != 16 {
			return fail("MOVL/Q require their distinct source address rewrite")
		}
		if stem == "ADD" || stem == "SUB" || stem == "ADC" || stem == "SBB" {
			return validateAMD64ScalarAddSubOperands(arch, op, bits, ins.Args[0], ins.Args[1], ins)
		}
	case "CMP":
		if len(ins.Args) != 2 || index != 1 || !registerOrMemory(ins.Args[0]) || !integer32(value) {
			return fail("does not match Ymb/Yml → Yi32")
		}
	case "PUSH":
		if bits == 8 || bits == 32 && arch != "386" || bits == 64 && arch != "amd64" ||
			len(ins.Args) != 1 || index != 0 || !integer32(value) {
			return fail("does not match source-mode PUSHW/L/Q Yi8/Yi32")
		}
	case "BT", "BTC", "BTR", "BTS":
		if bits == 8 || len(ins.Args) != 2 || index != 0 || value < -128 || value > 127 || !registerOrMemory(ins.Args[1]) {
			return fail("does not match signed Yi8 → Yml")
		}
	case "SAL", "SHL", "SHR", "SAR", "ROL", "ROR", "RCL", "RCR":
		if index != 0 || value < 0 || value > 255 {
			return fail("count is not Yu8")
		}
		// asm6.movDoubleShift requires From.Type == TYPE_CONST even when
		// oclass covers this TYPE_ADDR as Yi8. Do not wash that identity away.
		if len(ins.Args) != 2 || !registerOrMemory(ins.Args[1]) {
			return fail("does not match Yu8 → Ymb/Yml")
		}
	case "IMUL", "IMUL3":
		three := stem == "IMUL3"
		if bits == 8 || index != 0 || len(ins.Args) != 2 && !three || len(ins.Args) != 3 && three {
			return fail("does not match the complete immediate IMUL row")
		}
		return validateX86ExplicitIMUL(arch, op, bits, ins, three)
	default:
		return fail("opcode has no independently audited integer-immediate source role")
	}
	return nil
}

// This runs only after the original raw/caller/frame proofs. It supplies an
// immutable lowering view, never a repaired certificate. Only the separately
// checked, stack-unobserving raw-RET leaf below permits MOVL/Q's numerical LEA
// rewrite. LOCK/caller/physical-frame proofs retain their original source.
func normalizeX86SourceIntegerAddresses(file *File, options Options) (*File, error) {
	if file.Arch != ArchAMD64 {
		return file, nil
	}
	if options.Goarch == "" {
		options.Goarch = "amd64" // Preserve the existing public default mode.
	}
	result := *file
	result.Funcs = append([]Func(nil), file.Funcs...)
	for function, source := range file.Funcs {
		instructions := append([]Instr(nil), source.Instrs...)
		changed, protected := false, source.x86SourceStack != nil || source.x86FixedLocal != nil || source.X86RawText != nil
		for _, ins := range source.Instrs {
			if strings.EqualFold(string(ins.Op), "LOCK") || ins.x86RawNearReturn != nil {
				protected = true
			}
		}
		for index, ins := range source.Instrs {
			if err := validateX86SourceMemoryScale(ins); err != nil {
				return nil, fmt.Errorf("%s: %w", source.Sym, err)
			}
			derived, different, err := normalizeX86SourceIntegerAddress(ins, options.Goarch)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", source.Sym, err)
			}
			instructions[index], changed = derived, changed || different
		}
		if changed {
			derived := source
			derived.Instrs = instructions
			if protected && !x86RawReturnNumericalAddressAdapter(source, derived, file, options) {
				return nil, fmt.Errorf("%w: %s source address adapter cannot inherit a LOCK/raw/frame certificate", ErrProbeNeedsContext, source.Sym)
			}
			result.Funcs[function].Instrs = instructions
		}
	}
	return &result, nil
}

// A decoded native-width near RET is a return constraint, not permission to
// address native memory. Recheck both complete views without transferring any
// stack, caller, frame or other decoded-instruction certificate. This adapter
// handles only Go's MOVL/Q -> LEAL/Q progedit rule, never TYPE_CONST arithmetic.
func x86RawReturnNumericalAddressAdapter(source, derived Func, file *File, options Options) bool {
	if len(source.Instrs) != len(derived.Instrs) || source.FrameSize != 0 || source.x86SourceStack != nil || source.x86FixedLocal != nil ||
		source.X86RawText != nil || len(source.x86ContinuationAddresses) != 0 || len(source.x86IndirectLabels) != 0 {
		return false
	}
	name := source.Sym
	if options.ResolveSym != nil {
		name = options.ResolveSym(name)
	}
	sig := options.Sigs[name]
	if sig.x86CallerRegions != nil || sig.x86FixedLocal != nil {
		return false
	}
	hasReturn := false
	for index, ins := range source.Instrs {
		if strings.EqualFold(string(ins.Op), "LOCK") ||
			ins.x86CallerMemory != nil || ins.x86SourceStackFP != nil || ins.x86FixedLocalMemory != nil {
			return false
		}
		if ins.x86RawNearReturn != nil {
			hasReturn = true
		} else if ins.x86Encoded || ins.x86SourceRaw != nil {
			return false // Another decoder's contract needs its own adapter.
		}
		if derived.Instrs[index].Op != ins.Op {
			op := strings.ToUpper(string(x86SourceMoveInstruction(ins, options.Goarch).Op))
			if (op != "MOVL" && op != "MOVQ") || string(derived.Instrs[index].Op) != "LEA"+op[3:] {
				return false
			}
		} else if !reflect.DeepEqual(ins.Args, derived.Instrs[index].Args) {
			return false // A TYPE_CONST rewrite is a different semantic rule.
		}
	}
	return hasReturn && x86RawReturnLeafStackUnobserved(source) && x86RawReturnLeafStackUnobserved(derived) &&
		validateX86RawNearReturns(source, file, options, true) == nil &&
		validateX86RawNearReturns(derived, file, options, true) == nil
}
