package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
)

// A source continuation has no callable helper ABI. Its complete zero-frame
// body shares only its actual ABIInternal root's typed machine state. Keep an
// independent snapshot: copying a prepared Func and editing its source cannot
// retain this admission. Neither JSON nor a manual FuncSig constructs it.
type arm64PrivateTailSource struct {
	original Func
	helpers  []Func
	prepared Func
}

func arm64PrivateTailSnapshot(fn Func) Func {
	fn.arm64PrivateTailSource = nil
	fn.arm64ABI0TailSource = nil
	fn.arm64PrivateCallSource = nil
	fn.Instrs = append([]Instr(nil), fn.Instrs...)
	for i := range fn.Instrs {
		if offset := fn.Instrs[i].arm64ScalarMemoryFrameOffset; offset != nil {
			copyOffset := *offset
			fn.Instrs[i].arm64ScalarMemoryFrameOffset = &copyOffset
		}
		fn.Instrs[i].Args = append([]Operand(nil), fn.Instrs[i].Args...)
		for j := range fn.Instrs[i].Args {
			a := &fn.Instrs[i].Args[j]
			a.RegList = append([]Reg(nil), a.RegList...)
		}
	}
	return fn
}

func validateARM64PrivateTailSource(fn Func, sig FuncSig) error {
	if fn.arm64PrivateTailSource == nil {
		return nil
	}
	if !reflect.DeepEqual(arm64PrivateTailSnapshot(fn), fn.arm64PrivateTailSource.prepared) ||
		!strings.HasSuffix(fn.Sym, "<ABIInternal>") || sig.ARM64GoRegisterABI == nil ||
		fn.FrameSize != 0 || arm64SourceGoFrame(fn).present {
		return arm64GoABIContext("private tail root lost its complete zero-frame source/register identity")
	}
	if err := arm64PrivateTailZeroFrame(fn.arm64PrivateTailSource.original, true); err != nil {
		return err
	}
	for _, helper := range fn.arm64PrivateTailSource.helpers {
		if err := arm64PrivateTailBody(helper); err != nil {
			return err
		}
	}
	return arm64ValidateGoRegisterABI(sig)
}

// A continuation does not give ordinary pointer inputs a noalias promise
// against an immutable closure carrier. Keep the original root's complete
// carrier gate unchanged; only sealed helper loads may join its prepared CFG.
// Registered data-base pre/post updates change registers, never carrier memory.
func validateARM64PrivateTailClosureSource(fn Func, sig FuncSig) error {
	if err := validateARM64PrivateTailSource(fn, sig); err != nil {
		return err
	}
	proof := fn.arm64PrivateTailSource
	if err := validateARM64ClosureSource(proof.original, sig); err != nil {
		return err
	}
	for _, helper := range proof.helpers {
		for _, ins := range helper.Instrs[1:] {
			memory := false
			for _, arg := range ins.Args {
				memory = memory || arg.Kind == OpMem
			}
			if !memory {
				continue // Complete typed purity was independently rechecked above.
			}
			if form, valid := arm64RawPrivateMemory(ins); valid &&
				form.memory.Kind == OpMem && !form.store && form.scratch == nil {
				continue
			}
			if form, handled, err := parseARM64StructureMemory(ins); handled && err == nil &&
				form.memory.Kind == OpMem && form.load {
				continue
			}
			return arm64GoABIContext("%q private closure continuation has an unproved carrier-alias memory effect", sig.Name)
		}
	}
	return nil
}

func arm64PrivateTailTarget(ins Instr) (string, bool) {
	if ins.Op != "B" && ins.Op != "JMP" && ins.Op != OpRET || len(ins.Args) != 1 ||
		ins.Args[0].Kind != OpSym || !strings.HasSuffix(ins.Args[0].Sym, "(SB)") {
		return "", false
	}
	base, off, ok := arm64PrivateSymbolRef(ins.Args[0].Sym)
	return base, ok && off == 0 && arm64PrivateTailSymbol(ins.Args[0].Sym)
}

func arm64PrivateTailZeroFrame(fn Func, root bool) error {
	if fn.arm64PrivateRegisterEntry || fn.arm64PrivateTailSource != nil ||
		fn.FrameSize != 0 || arm64SourceGoFrame(fn).present || !arm64SourceFrameFlagsKnown(fn) ||
		len(fn.Instrs) < 2 || fn.Instrs[0].Op != OpTEXT {
		return arm64GoABIContext("private tail %q needs a complete zero physical frame", fn.Sym)
	}
	_, rest := splitOpcode(fn.Instrs[0].Raw)
	parts := strings.Split(rest, ",")
	if len(parts) < 2 || len(parts) > 3 {
		return arm64GoABIContext("private tail %q has incomplete TEXT", fn.Sym)
	}
	name, off, ok := parseSBRef(strings.TrimSpace(parts[0]))
	frame, args, err := parseTEXTFrame(parts)
	if !ok || off != 0 || name != fn.Sym || err != nil || frame != fn.FrameSize || args != fn.ArgSize ||
		!root && args != 0 {
		return arm64GoABIContext("private tail %q changed its original TEXT identity", fn.Sym)
	}
	// An omitted helper args suffix is intentionally retained as unknown. It
	// describes a continuation, not an inferred zero-argument function ABI.
	if root && (!strings.HasSuffix(fn.Sym, "<ABIInternal>") ||
		strings.LastIndex(strings.TrimSpace(parts[len(parts)-1]), "-") <= 1) {
		return arm64GoABIContext("private tail root %q needs explicit source ABIInternal/args", fn.Sym)
	}
	for _, ins := range fn.Instrs[1:] {
		if ins.Op == OpTEXT || ins.Op == "CALL" || ins.Op == "BL" || ins.Op == "BLR" {
			return arm64GoABIContext("private tail %q is not a zero-frame call-free source", fn.Sym)
		}
	}
	return nil
}

func arm64PrivateTailDataRegister(reg Reg) bool {
	if arm64PrivateDataGP(reg) {
		return reg != "R26" // A private body has no hidden closure producer.
	}
	if _, ok := arm64ParseFReg(reg); ok {
		return true
	}
	_, ok := arm64ParseVReg(reg)
	return ok
}

// Purity does not prove an input initialized or a pointer safe. Actual typed
// lowering, register must-def, local-code and memory/return proofs still run on
// the entire resulting root CFG. Reject source expansions that independently
// materialize Go R27 even when it is absent from the written operands.
func arm64PrivateTailBody(fn Func) error {
	if err := arm64PrivateTailZeroFrame(fn, false); err != nil {
		return err
	}
	return arm64PrivateContinuationBody(fn, arm64PrivateTailDataRegister, nil, true)
}

// Operand purity is shared by CALL and tail continuations, but their entry and
// return contracts remain separate. This grammar grants neither initialized
// inputs nor pointer bounds: the complete root's independent proofs own those.
func arm64PrivateContinuationBody(fn Func, dataRegister func(Reg) bool, scratchContract func(Op, Instr, arm64GPDataForm) bool, allowAlignment bool) error {
	labels := map[string]bool{}
	for _, ins := range fn.Instrs[1:] {
		if ins.Op == OpLABEL {
			if len(ins.Args) != 1 || ins.Args[0].Kind != OpLabel || ins.Args[0].Sym == "" || labels[ins.Args[0].Sym] {
				return arm64GoABIContext("private tail %q has duplicate/incomplete labels", fn.Sym)
			}
			labels[ins.Args[0].Sym] = true
		}
	}
	returns := 0
	for _, ins := range fn.Instrs[1:] {
		if _, alignment, err := arm64PCAlignment(ins); alignment {
			if err != nil || !allowAlignment {
				return arm64GoABIContext("private continuation %q has unproved alignment at %q", fn.Sym, ins.Raw)
			}
			continue
		}
		if ins.Op == OpTEXT || ins.Op == "CALL" || ins.Op == "BL" || ins.Op == "BLR" {
			return arm64GoABIContext("private continuation %q is not a call-free complete source at %q", fn.Sym, ins.Raw)
		}
		if ins.Op == OpLABEL {
			continue
		}
		if ins.Op == OpRET {
			if len(ins.Args) != 0 {
				return arm64GoABIContext("private tail %q has a non-caller return", fn.Sym)
			}
			returns++
			continue
		}
		branch := ins.Op == "B" || ins.Op == "JMP" || arm64IsConditionalBranch(ins.Op)
		if branch {
			if len(ins.Args) == 0 || ins.Args[len(ins.Args)-1].Kind != OpIdent || !labels[ins.Args[len(ins.Args)-1].Ident] {
				return arm64GoABIContext("private tail %q has unresolved/escaping control at %q", fn.Sym, ins.Raw)
			}
		}
		op := arm64ControlOp(ins)
		if f, handled, err := parseARM64GPDataForm(op, ins); handled {
			if err != nil || (f.scratch != nil || len(f.implicit) != 0) &&
				(scratchContract == nil || !scratchContract(op, ins, f)) {
				return arm64GoABIContext("private continuation %q has unproved source scratch at %q", fn.Sym, ins.Raw)
			}
		}
		if f, handled, err := parseARM64ScalarMemoryForm(op, ins); handled && (err != nil || f.scratch) {
			return arm64GoABIContext("private tail %q has unproved memory scratch at %q", fn.Sym, ins.Raw)
		}
		pairBytes := arm64RawPrivatePairBytes(op)
		scalarBytes := arm64RawPrivateScalarBytes(op)
		_, structure, structureErr := parseARM64StructureMemory(ins)
		data := branch
		for i, arg := range ins.Args {
			if branch && i == len(ins.Args)-1 {
				continue
			}
			switch arg.Kind {
			case OpImm:
				if arg.ImmRaw != "" || arg.ImmIsFloat {
					return arm64GoABIContext("private tail %q has an unresolved/pool operand", fn.Sym)
				}
			case OpReg, OpRegShift, OpRegExtend:
				if !dataRegister(arg.Reg) || arg.ShiftReg != "" && !dataRegister(arg.ShiftReg) {
					return arm64GoABIContext("private tail %q touches hidden/stack/scratch state at %q", fn.Sym, ins.Raw)
				}
				data = true
			case OpRegList:
				for _, reg := range arg.RegList {
					if !dataRegister(reg) {
						return arm64GoABIContext("private tail %q has an unproved register list", fn.Sym)
					}
				}
				data = true
			case OpMem:
				m := arg.Mem
				if m.Sym != "" || m.Segment != "" || m.OffRaw != "" || !arm64PrivateDataGP(m.Base) || m.Base == ZR || !dataRegister(m.Base) ||
					m.Index != "" && (!arm64PrivateDataGP(m.Index) || !dataRegister(m.Index)) ||
					pairBytes != 0 && (m.Index != "" || m.Off%pairBytes != 0 || m.Off < -64*pairBytes || m.Off > 63*pairBytes) {
					return arm64GoABIContext("private tail %q has non-data or materialized memory at %q", fn.Sym, ins.Raw)
				}
				if structureErr != nil || !structure && scalarBytes == 0 && pairBytes == 0 ||
					scalarBytes != 0 && (m.Index != "" && m.Off != 0 || m.Index == "" &&
						!(m.Off >= -256 && m.Off <= 255 || m.Off >= 0 && m.Off%scalarBytes == 0 && m.Off/scalarBytes <= 4095)) {
					return arm64GoABIContext("private tail %q lacks a no-scratch typed memory row at %q", fn.Sym, ins.Raw)
				}
				data = true
			case OpIdent:
				if !armCondCodes[arg.Ident] {
					return arm64GoABIContext("private tail %q observes a non-data identity at %q", fn.Sym, ins.Raw)
				}
			default:
				return arm64GoABIContext("private tail %q has external/frame operands at %q", fn.Sym, ins.Raw)
			}
		}
		if !data {
			return arm64GoABIContext("private tail %q has unproved effects at %q", fn.Sym, ins.Raw)
		}
	}
	last := fn.Instrs[len(fn.Instrs)-1]
	if returns == 0 || last.Op != OpRET && last.Op != "B" && last.Op != "JMP" {
		return arm64GoABIContext("private tail %q falls outside its complete CFG", fn.Sym)
	}
	return nil
}

func coalesceARM64PrivateTailHelpers(file *File, remaining *int) (*File, error) {
	return coalesceARM64PrivateTailHelpersWithABI0(file, remaining, nil, nil)
}

func coalesceARM64PrivateTailHelpersWithABI0(file *File, remaining *int, sigs map[string]FuncSig, resolve func(string) string) (*File, error) {
	if file.Arch != ArchARM64 {
		return file, nil
	}
	requested := map[string]bool{}
	for _, fn := range file.Funcs {
		declaredABI0 := resolve != nil && sigs[resolve(goTextSymbolForResolution(fn.Sym))].arm64ABI0TailDeclaration != nil
		if !strings.HasSuffix(fn.Sym, "<ABIInternal>") && !declaredABI0 {
			continue // Preserve existing explicit ABI0/private callable contracts.
		}
		for _, ins := range fn.Instrs {
			if name, ok := arm64PrivateTailTarget(ins); ok {
				requested[name] = true
			}
		}
	}
	helpers := map[string]Func{}
	for _, fn := range file.Funcs {
		if !requested[fn.Sym] {
			continue
		}
		fp := false
		for _, ins := range fn.Instrs {
			for _, arg := range ins.Args {
				fp = fp || arg.Kind == OpFP || arg.Kind == OpFPAddr
			}
		}
		if fp || fn.ArgSize != 0 {
			continue // Existing explicit FP/callee contracts are not continuations.
		}
		if _, duplicate := helpers[fn.Sym]; duplicate {
			return nil, arm64GoABIContext("duplicate private tail TEXT %q", fn.Sym)
		}
		if err := arm64PrivateTailBody(fn); err != nil {
			return nil, err
		}
		helpers[fn.Sym] = fn
	}
	if len(helpers) == 0 {
		return file, nil
	}
	// Native PC/address observers anywhere in the original file prevent
	// removing standalone helper TEXT identities, even if KeepFunc excludes it.
	uses := map[string]int{}
	for _, data := range file.Data {
		for _, sym := range []string{data.Sym, data.Addr} {
			if base, _, _ := arm64PrivateSymbolRef(sym); requested[base] {
				return nil, arm64GoABIContext("private tail escapes through DATA")
			}
		}
	}
	for _, global := range file.Globl {
		if base, _, _ := arm64PrivateSymbolRef(global.Sym); requested[base] {
			return nil, arm64GoABIContext("private tail escapes through GLOBL")
		}
	}
	if len(file.UnlinkedPrelude) != 0 {
		return nil, arm64GoABIContext("private tail file has an unbound native prelude")
	}
	for _, fn := range file.Funcs {
		if len(fn.Instrs) == 0 {
			return nil, arm64GoABIContext("private tail file has an incomplete TEXT body")
		}
		for _, ins := range fn.Instrs[1:] {
			if _, _, err := arm64PCAlignment(ins); err != nil {
				return nil, err
			}
			switch ins.Op {
			case OpWORD, "DWORD", "ADR", "ADRP":
				return nil, arm64GoABIContext("private tail file observes native layout at %q", ins.Raw)
			}
			for _, arg := range ins.Args {
				mem, memory := arg.Mem, arg.Kind == OpMem
				if arg.Kind == OpSym && strings.HasPrefix(arg.Sym, "$") {
					mem, memory = parseMem(strings.TrimSpace(strings.TrimPrefix(arg.Sym, "$")))
				}
				if memory && mem.Base == PC {
					return nil, arm64GoABIContext("private tail file observes native PC")
				}
				if memory && mem.Sym != "" {
					if base, _, _ := arm64PrivateSymbolRef(mem.Sym); requested[base] {
						return nil, arm64GoABIContext("private tail has a native memory/address use")
					}
				}
				if arg.Kind != OpSym {
					continue
				}
				base, _, _ := arm64PrivateSymbolRef(arg.Sym)
				if _, helper := helpers[base]; !helper {
					continue
				}
				if target, ok := arm64PrivateTailTarget(ins); !ok || target != base {
					return nil, arm64GoABIContext("private tail %q has another address/native use", base)
				}
				var err error
				if strings.HasSuffix(fn.Sym, "<ABIInternal>") {
					err = arm64PrivateTailZeroFrame(fn, true)
				} else if resolve != nil {
					err = arm64ABI0TailRoot(fn, sigs[resolve(goTextSymbolForResolution(fn.Sym))])
				} else {
					err = arm64GoABIContext("private tail has no root source contract")
				}
				if err != nil {
					return nil, err
				}
				uses[base]++
			}
		}
	}
	for name, helper := range helpers {
		if uses[name] == 0 || uses[name] > *remaining/len(helper.Instrs) {
			return nil, arm64GoABIContext("private tail source exceeds the shared expansion budget")
		}
		*remaining -= uses[name] * len(helper.Instrs)
	}
	result := *file
	result.Funcs = make([]Func, 0, len(file.Funcs)-len(helpers))
	for _, fn := range file.Funcs {
		if _, helper := helpers[fn.Sym]; helper {
			continue
		}
		copyFn := fn
		var added []Instr
		originalHelpers := map[string]bool{}
		var helperSources []Func
		occupied := map[string]bool{"entry": true, "ret": true}
		for _, block := range arm64SplitBlocks(fn) {
			occupied[arm64LLVMBlockName(block.name)] = true
		}
		for i, ins := range fn.Instrs {
			name, tail := arm64PrivateTailTarget(ins)
			helper, present := helpers[name]
			if !tail || !present {
				continue
			}
			if !originalHelpers[name] {
				originalHelpers[name] = true
				helperSources = append(helperSources, arm64PrivateTailSnapshot(helper))
			}
			if len(added) == 0 {
				copyFn.Instrs = append([]Instr(nil), fn.Instrs...)
			}
			fresh := func() string {
				label := fmt.Sprintf("__arm64_tail_%d", len(occupied))
				for occupied[arm64LLVMBlockName(label)] {
					label += "_"
				}
				occupied[arm64LLVMBlockName(label)] = true
				return label
			}
			entry, labels := fresh(), map[string]string{}
			for _, original := range helper.Instrs[1:] {
				if original.Op == OpLABEL {
					labels[original.Args[0].Sym] = fresh()
				}
			}
			copyFn.Instrs[i].Op = "B"
			copyFn.Instrs[i].Args = []Operand{{Kind: OpIdent, Ident: entry}}
			added = append(added, Instr{Op: OpLABEL, Args: []Operand{{Kind: OpLabel, Sym: entry}}})
			for _, original := range helper.Instrs[1:] {
				cloned := original
				if original.Op == OpLABEL {
					cloned.Args = []Operand{{Kind: OpLabel, Sym: labels[original.Args[0].Sym]}}
				} else if original.Op == "B" || original.Op == "JMP" || arm64IsConditionalBranch(original.Op) {
					cloned.Args = append([]Operand(nil), original.Args...)
					last := len(cloned.Args) - 1
					cloned.Args[last] = Operand{Kind: OpIdent, Ident: labels[original.Args[last].Ident]}
				}
				added = append(added, cloned)
			}
		}
		if len(added) != 0 {
			last := fn.Instrs[len(fn.Instrs)-1].Op
			if last != OpRET && last != "B" && last != "JMP" {
				return nil, arm64GoABIContext("private tail root %q has a source fallthrough", fn.Sym)
			}
			copyFn.Instrs = append(copyFn.Instrs, added...)
			copyFn.arm64PrivateSourceAdded += len(added)
			if strings.HasSuffix(fn.Sym, "<ABIInternal>") {
				copyFn.arm64PrivateTailSource = &arm64PrivateTailSource{
					original: arm64PrivateTailSnapshot(fn), helpers: helperSources,
					prepared: arm64PrivateTailSnapshot(copyFn),
				}
			} else {
				sig := sigs[resolve(goTextSymbolForResolution(fn.Sym))]
				// Bind the actual FP normalization before sealing the prepared
				// source. Final consumers may not drop its physical-offset marker
				// or accept arbitrary changes as a normalization projection.
				var err error
				copyFn, err = normalizeARM64ScalarMemoryFrame(copyFn)
				if err != nil {
					return nil, err
				}
				copyFn.arm64ABI0TailSource = &arm64ABI0TailSource{
					declaration: sig.arm64ABI0TailDeclaration, original: arm64PrivateTailSnapshot(fn),
					helpers: helperSources, prepared: arm64PrivateTailSnapshot(copyFn),
				}
				if err := validateARM64ABI0TailSource(copyFn, sig); err != nil {
					return nil, err
				}
			}
		}
		result.Funcs = append(result.Funcs, copyFn)
	}
	return &result, nil
}
