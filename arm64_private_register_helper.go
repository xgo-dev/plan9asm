package plan9asm

import (
	"fmt"
	"strings"
)

// Limit added source instructions before allocating per-call continuations.
// The later CFG convergence budgets cannot bound this Cartesian expansion.
const arm64PrivateRegisterExpansionBudget = 1 << 16

// This is a source continuation contract, not a guessed callable signature.
// Only a closed, acyclic, zero-frame data leaf can share its caller's
// typed machine state. Purity here restricts operand classes; real lowering still
// validates every opcode/form and records actual register/flag effects. Native
// callouts are rejected here; native effects are also rejected by the later
// machine-availability proof.
func arm64PrivateRegisterLeaf(fn Func) error {
	if fn.FrameSize != 0 && fn.FrameSize != -8 || fn.ArgSize != 0 || arm64SourceGoFrame(fn).present {
		return arm64GoABIContext("private helper %q has an unproved native frame", fn.Sym)
	}
	if len(fn.Instrs) < 2 || fn.Instrs[0].Op != OpTEXT {
		return arm64GoABIContext("private helper %q has no complete source body", fn.Sym)
	}
	if !arm64SourceFrameFlagsKnown(fn) {
		return arm64GoABIContext("private helper %q has unbound source frame flags", fn.Sym)
	}
	_, text := splitOpcode(fn.Instrs[0].Raw)
	parts := strings.Split(text, ",")
	name, offset, valid := parseSBRef(strings.TrimSpace(parts[0]))
	frame, args, err := parseTEXTFrame(parts)
	if !valid || offset != 0 || name != fn.Sym || err != nil || frame != fn.FrameSize || args != fn.ArgSize {
		return arm64GoABIContext("private helper %q changed its complete TEXT identity", fn.Sym)
	}
	if err := arm64PrivateContinuationBody(fn, arm64PrivateCallDataRegister, arm64PrivateCallImmediateScratch, false); err != nil {
		return err
	}
	return arm64PrivateCallAcyclic(fn)
}

func arm64PrivateDataGP(reg Reg) bool {
	if reg == ZR {
		return true
	}
	// R18 is a physical platform register even after the source spelling
	// R18_PLATFORM has been normalized. R27 is the Go assembler scratch
	// register; R28/R29/R30 have hidden
	// runtime/frame/link roles. No source-private data promise is made for them.
	return isARM64GeneralOrZeroReg(reg) && !arm64PrivateReservedGP(reg) && reg != "R28" && reg != "R29" && reg != "R30"
}

func arm64PrivateReservedGP(reg Reg) bool {
	if root, ok := parseReg(string(reg)); ok {
		reg = root
	}
	return reg == "R18" || reg == "R27"
}

func arm64PrivateOperandMentionsReserved(arg Operand) bool {
	if arm64PrivateReservedGP(arg.Reg) || arm64PrivateReservedGP(arg.ShiftReg) || arm64PrivateReservedGP(arg.Mem.Base) || arm64PrivateReservedGP(arg.Mem.Index) {
		return true
	}
	for _, reg := range arg.RegList {
		if arm64PrivateReservedGP(reg) {
			return true
		}
	}
	if arg.Kind == OpSym && strings.HasPrefix(arg.Sym, "$") {
		address, ok := parseMem(strings.TrimSpace(strings.TrimPrefix(arg.Sym, "$")))
		if ok && (arm64PrivateReservedGP(address.Base) || arm64PrivateReservedGP(address.Index)) {
			return true
		}
	}
	return false
}

func arm64PrivateSymbolRef(sym string) (string, int64, bool) {
	return parseSBRef(strings.TrimPrefix(sym, "$"))
}

// CoalesceARM64PrivateRegisterHelpers folds closed ARM64 source continuations:
// acyclic data leaves at CALL sites, and zero-frame data/CFG leaves at ABIInternal
// tail sites. Tail roots still require their complete typed Go register ABI at
// final lowering. Neither family infers a callable helper signature or grants
// native-frame, hidden-register or pointer-ownership permissions.
// Call this before filtering or splitting a file: an excluded sibling or DATA
// initializer must not hide address-taking or alternate native helper uses.
// Other architectures are returned unchanged. The input is not modified.
func CoalesceARM64PrivateRegisterHelpers(file *File) (*File, error) {
	if file == nil {
		return nil, fmt.Errorf("nil assembly file")
	}
	return coalesceARM64PrivateRegisterHelpers(file)
}

// Run before KeepFunc: an excluded sibling or DATA initializer must not hide
// address-taking or an alternate native use of a helper we fold into a root.
func coalesceARM64PrivateRegisterHelpers(file *File) (*File, error) {
	if file.Arch != ArchARM64 {
		return file, nil
	}
	remaining := arm64PrivateRegisterExpansionBudget
	// Public preparation and final preparation can run separately. Retain each
	// root's actual earlier additions so appending another original root cannot
	// reset the single checked allowance. This count authorizes no source effect.
	for _, fn := range file.Funcs {
		if err := validateARM64PrivateCallSource(fn); err != nil {
			return nil, err
		}
		if fn.arm64PrivateSourceAdded < 0 || fn.arm64PrivateSourceAdded > remaining {
			return nil, arm64GoABIContext("private source exceeds its cumulative expansion budget")
		}
		remaining -= fn.arm64PrivateSourceAdded
	}
	if err := validateARM64PrivateContinuationFile(file); err != nil {
		return nil, err
	}
	prepared, err := coalesceARM64PrivateCallRegisterHelpers(file, &remaining)
	if err != nil {
		return nil, err
	}
	return coalesceARM64PrivateTailHelpers(prepared, &remaining)
}

func coalesceARM64PrivateCallRegisterHelpers(file *File, remaining *int) (*File, error) {
	if file.Arch != ArchARM64 {
		return file, nil
	}
	// Do not replace existing explicit FP/tail-entry contracts. This bounded
	// continuation mechanism starts only at real source BL/CALL sites, then
	// audits every other use of each such helper across the complete file.
	called := map[string]bool{}
	for _, fn := range file.Funcs {
		for _, ins := range fn.Instrs {
			if (ins.Op == "CALL" || ins.Op == "BL") && len(ins.Args) == 1 && ins.Args[0].Kind == OpSym {
				base, _, ok := arm64PrivateSymbolRef(ins.Args[0].Sym)
				if ok {
					called[base] = true
				}
			}
		}
	}
	helpers := map[string]Func{}
	for _, fn := range file.Funcs {
		if !strings.HasSuffix(fn.Sym, "<>") || !called[fn.Sym] {
			continue
		}
		fp := false
		for _, ins := range fn.Instrs {
			for _, arg := range ins.Args {
				fp = fp || arg.Kind == OpFP || arg.Kind == OpFPAddr
			}
		}
		if fp || fn.ArgSize != 0 {
			continue // Ordinary FP helpers retain their existing typed ABI path.
		}
		if _, duplicate := helpers[fn.Sym]; duplicate {
			return nil, fmt.Errorf("duplicate ARM64 private TEXT %q", fn.Sym)
		}
		if err := arm64PrivateRegisterLeaf(fn); err != nil {
			return nil, err
		}
		helpers[fn.Sym] = fn
	}
	if len(helpers) == 0 {
		return file, nil
	}
	if len(file.UnlinkedPrelude) != 0 {
		return nil, arm64GoABIContext("private call file has an unbound native prelude")
	}
	for _, data := range file.Data {
		for _, symbol := range []string{data.Sym, data.Addr} {
			base, _, _ := arm64PrivateSymbolRef(symbol)
			if _, escaped := helpers[base]; escaped {
				return nil, arm64GoABIContext("private helper %q escapes through DATA", base)
			}
		}
	}
	for _, global := range file.Globl {
		base, _, _ := arm64PrivateSymbolRef(global.Sym)
		if _, escaped := helpers[base]; escaped {
			return nil, arm64GoABIContext("private helper %q has a GLOBL/native address use", base)
		}
	}
	uses := map[string]int{}
	roots := map[string]map[string]bool{}
	for _, fn := range file.Funcs {
		for _, ins := range fn.Instrs {
			if ins.Op == OpTEXT {
				continue
			}
			// Folding removes the helper's standalone native TEXT identity.
			// A sibling excluded by KeepFunc must not hide an observation of
			// that original byte layout or a raw branch into the helper.
			_, alignment, _ := arm64PCAlignment(ins)
			if ins.Op == OpWORD || ins.Op == "DWORD" || ins.Op == "ADR" || ins.Op == "ADRP" || alignment {
				return nil, arm64GoABIContext("private helper file requires native byte-layout effects at %q", ins.Raw)
			}
			for ai, arg := range ins.Args {
				memory, hasMemory := arg.Mem, arg.Kind == OpMem
				if arg.Kind == OpSym && strings.HasPrefix(arg.Sym, "$") {
					memory, hasMemory = parseMem(strings.TrimSpace(strings.TrimPrefix(arg.Sym, "$")))
				}
				if hasMemory && memory.Base == PC {
					return nil, arm64GoABIContext("private helper file has a native PC use at %q", ins.Raw)
				}
				if hasMemory && memory.Sym != "" {
					base, _, _ := arm64PrivateSymbolRef(memory.Sym)
					if _, escaped := helpers[base]; escaped {
						return nil, arm64GoABIContext("private helper %q has a native memory/address use at %q", base, ins.Raw)
					}
				}
				if arg.Kind != OpSym {
					continue
				}
				base, off, ok := arm64PrivateSymbolRef(arg.Sym)
				if _, helper := helpers[base]; !ok || !helper {
					continue
				}
				if (ins.Op != "CALL" && ins.Op != "BL") || ai != 0 || len(ins.Args) != 1 || off != 0 || strings.HasPrefix(arg.Sym, "$") {
					return nil, arm64GoABIContext("private helper %q has a non-call/address use at %q", base, ins.Raw)
				}
				if roots[fn.Sym] == nil {
					roots[fn.Sym] = map[string]bool{}
				}
				roots[fn.Sym][base] = true
				uses[base]++
			}
		}
	}
	for helper := range helpers {
		if uses[helper] == 0 {
			return nil, arm64GoABIContext("private helper %q has no closed source caller", helper)
		}
	}
	for name, helper := range helpers {
		// LABEL and B (R30) replace TEXT and RET, so each continuation adds
		// exactly the original leaf's length. Divide before multiplying to
		// keep the file-wide preflight checked even for hostile source sizes.
		if uses[name] > *remaining/len(helper.Instrs) {
			return nil, arm64GoABIContext("private helper source exceeds its expansion budget of %d instructions", arm64PrivateRegisterExpansionBudget)
		}
		*remaining -= uses[name] * len(helper.Instrs)
	}
	result := *file
	result.Funcs = make([]Func, 0, len(file.Funcs)-len(helpers))
	for _, fn := range file.Funcs {
		if _, helper := helpers[fn.Sym]; helper {
			continue
		}
		if len(roots[fn.Sym]) == 0 {
			result.Funcs = append(result.Funcs, fn)
			continue
		}
		copyFn := fn
		if len(fn.Instrs) == 0 {
			return nil, arm64GoABIContext("private helper root %q has no source terminator", fn.Sym)
		}
		last := fn.Instrs[len(fn.Instrs)-1].Op
		if last != OpRET && last != "B" && last != "JMP" {
			return nil, arm64GoABIContext("private helper root %q has no source terminator", fn.Sym)
		}
		copyFn.Instrs = append([]Instr(nil), fn.Instrs...)
		copyFn.arm64PrivateRegisterEntry = true
		// Retain the pre-coalescing source proof. Only audited data-only
		// helpers are appended below; their rewritten local calls must not
		// erase the original real-symbol call's private-frame provenance.
		copyFn.arm64PrivateUnexposedFrame = arm64CallFrameUnexposed(fn)
		// Each static CALL needs its own helper continuation. Sharing a body
		// also shares its indirect RET edges, falsely joining an earlier call's
		// register state into a later caller continuation. The closed leaf has
		// no observable address/PC or LR use, so cloning its source preserves
		// the real CALL/LR transport without weakening must-defined joins.
		type sourceContinuation struct {
			label  string
			helper Func
		}
		var continuations []sourceContinuation
		occupied := map[string]bool{"entry": true, "ret": true}
		for _, block := range arm64SplitBlocks(fn) {
			occupied[arm64LLVMBlockName(block.name)] = true
		}
		fresh := func() string {
			label := fmt.Sprintf("__arm64_private_%d", len(occupied))
			for occupied[arm64LLVMBlockName(label)] {
				label += "_"
			}
			occupied[arm64LLVMBlockName(label)] = true
			return label
		}
		for i, ins := range copyFn.Instrs {
			_, alignment, _ := arm64PCAlignment(ins)
			if ins.Op == OpWORD || ins.Op == "ADR" || ins.Op == "ADRP" || alignment {
				return nil, arm64GoABIContext("private helper root %q requires native byte-layout effects at %q", fn.Sym, ins.Raw)
			}
			for _, arg := range ins.Args {
				if arm64PrivateOperandMentionsReserved(arg) {
					return nil, arm64GoABIContext("private helper root %q observes unmodelled platform/scratch state at %q", fn.Sym, ins.Raw)
				}
			}
			if (ins.Op == "CALL" || ins.Op == "BL") && len(ins.Args) == 1 && ins.Args[0].Kind == OpSym {
				name, _, _ := arm64PrivateSymbolRef(ins.Args[0].Sym)
				if helper, present := helpers[name]; present {
					label := fresh()
					continuations = append(continuations, sourceContinuation{label: label, helper: helper})
					copyFn.Instrs[i].Args = []Operand{{Kind: OpIdent, Ident: label}}
				}
			}
		}
		var err error
		copyFn, err = normalizeARM64NamedPCRelative(copyFn)
		if err != nil {
			return nil, err
		}
		var helperSources []Func
		for _, continuation := range continuations {
			copyFn.Instrs = append(copyFn.Instrs, Instr{Op: OpLABEL, Args: []Operand{{Kind: OpLabel, Sym: continuation.label}}})
			helper := continuation.helper
			helperSources = append(helperSources, arm64PrivateTailSnapshot(helper))
			labels := make(map[string]string)
			for _, ins := range helper.Instrs[1:] {
				if ins.Op == OpLABEL {
					labels[ins.Args[0].Sym] = fresh()
				}
			}
			for _, ins := range helper.Instrs[1:] {
				cloned := ins
				switch {
				case ins.Op == OpRET:
					cloned = Instr{Op: "B", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: "R30"}}}, Raw: "B (R30)"}
				case ins.Op == OpLABEL:
					cloned.Args = []Operand{{Kind: OpLabel, Sym: labels[ins.Args[0].Sym]}}
				case ins.Op == "B" || ins.Op == "JMP" || arm64IsConditionalBranch(ins.Op):
					cloned.Args = append([]Operand(nil), ins.Args...)
					last := len(cloned.Args) - 1
					cloned.Args[last] = Operand{Kind: OpIdent, Ident: labels[ins.Args[last].Ident]}
				}
				copyFn.Instrs = append(copyFn.Instrs, cloned)
			}
			copyFn.arm64PrivateSourceAdded += len(helper.Instrs)
		}
		copyFn, err = normalizeARM64ScalarMemoryFrame(copyFn)
		if err != nil {
			return nil, err
		}
		copyFn.arm64PrivateCallSource = &arm64PrivateCallSource{
			original: arm64PrivateTailSnapshot(fn), helpers: helperSources,
			prepared: arm64PrivateTailSnapshot(copyFn),
		}
		result.Funcs = append(result.Funcs, copyFn)
	}
	return &result, nil
}
