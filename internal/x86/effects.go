package x86

import (
	"fmt"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

// ABI0EffectReport summarizes the result of static ABI0 effect checking on an
// x86/amd64 function using the declarative OpTable.
type ABI0EffectReport struct {
	InitializedGP  map[asm.Reg]bool
	InitializedVec map[int]bool
	WrittenResults map[int64]bool
}

type abi0State struct {
	gpInit         map[asm.Reg]bool
	gpTaintedSP    map[asm.Reg]bool
	vecInit        map[int]bool
	vecFromRaw     map[int]bool
	fpBytesInit    map[int64]bool
	localSlotsInit map[int64]bool
}

func (s *abi0State) clone() *abi0State {
	out := &abi0State{
		gpInit:         make(map[asm.Reg]bool, len(s.gpInit)),
		gpTaintedSP:    make(map[asm.Reg]bool, len(s.gpTaintedSP)),
		vecInit:        make(map[int]bool, len(s.vecInit)),
		vecFromRaw:     make(map[int]bool, len(s.vecFromRaw)),
		fpBytesInit:    make(map[int64]bool, len(s.fpBytesInit)),
		localSlotsInit: make(map[int64]bool, len(s.localSlotsInit)),
	}
	for k, v := range s.gpInit {
		out.gpInit[k] = v
	}
	for k, v := range s.gpTaintedSP {
		out.gpTaintedSP[k] = v
	}
	for k, v := range s.vecInit {
		out.vecInit[k] = v
	}
	for k, v := range s.vecFromRaw {
		out.vecFromRaw[k] = v
	}
	for k, v := range s.fpBytesInit {
		out.fpBytesInit[k] = v
	}
	for k, v := range s.localSlotsInit {
		out.localSlotsInit[k] = v
	}
	return out
}

// merge combines incoming state `other` into `s` at a CFG join point:
//   - must-initialized sets (gpInit, vecInit, fpBytesInit, localSlotsInit) intersect
//   - may-tainted sets (gpTaintedSP, vecFromRaw) union
//
// Returns true if `s` changed.
func (s *abi0State) merge(other *abi0State) bool {
	changed := false
	for k := range s.gpInit {
		if !other.gpInit[k] {
			delete(s.gpInit, k)
			changed = true
		}
	}
	for k := range s.vecInit {
		if !other.vecInit[k] {
			delete(s.vecInit, k)
			changed = true
		}
	}
	for k := range s.fpBytesInit {
		if !other.fpBytesInit[k] {
			delete(s.fpBytesInit, k)
			changed = true
		}
	}
	for k := range s.localSlotsInit {
		if !other.localSlotsInit[k] {
			delete(s.localSlotsInit, k)
			changed = true
		}
	}
	for k, v := range other.gpTaintedSP {
		if v && !s.gpTaintedSP[k] {
			s.gpTaintedSP[k] = true
			changed = true
		}
	}
	for k, v := range other.vecFromRaw {
		if v && !s.vecFromRaw[k] {
			s.vecFromRaw[k] = true
			changed = true
		}
	}
	return changed
}

// CheckABI0ResultInit verifies that a Go ABI0 x86/amd64 function obeys register
// initialization, private stack-pointer confinement, raw-directive provenance,
// and CFG/byte-exact ABI0 result initialization rules before emitting code.
//
// Driven directly by OpTable so adding new instructions automatically participates
// in effect tracking without per-opcode boilerplate.
func CheckABI0ResultInit(fn asm.Func, sig asm.FuncSig, goarch string) (*ABI0EffectReport, error) {
	return CheckABI0ResultInitWithSigs(fn, sig, goarch, nil, nil)
}

// CheckABI0ResultInitWithSigs extends CheckABI0ResultInit with callee ABI0
// signatures so outgoing CALLs can verify outgoing parameter slots and mark
// callee ABI0 result stack slots initialized.
func CheckABI0ResultInitWithSigs(fn asm.Func, sig asm.FuncSig, goarch string, resolve func(string) string, sigs map[string]asm.FuncSig) (*ABI0EffectReport, error) {
	instrs, err := DecodeRawDirectives(fn.Instrs, goarch)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", asm.ErrProbeNeedsContext, err)
	}

	// Build CFG label index map and non-label instruction indices (for n(PC) jumps).
	labelIndex := map[string]int{}
	nonLabelIdx := make([]int, 0, len(instrs))
	pcOrderOf := make([]int, len(instrs))
	for i, ins := range instrs {
		pcOrderOf[i] = len(nonLabelIdx)
		if ins.Op == asm.OpLABEL && len(ins.Args) == 1 && ins.Args[0].Kind == asm.OpLabel {
			labelIndex[ins.Args[0].Sym] = i
			continue
		}
		if ins.Op == asm.OpTEXT {
			continue
		}
		nonLabelIdx = append(nonLabelIdx, i)
	}

	resolveJumpTarget := func(pc int, opnd asm.Operand) (int, bool, error) {
		switch opnd.Kind {
		case asm.OpLabel:
			if idx, ok := labelIndex[opnd.Sym]; ok {
				return idx, true, nil
			}
			return -1, false, fmt.Errorf("%w: unresolved jump label %q", asm.ErrProbeNeedsContext, opnd.Sym)
		case asm.OpIdent:
			if idx, ok := labelIndex[opnd.Ident]; ok {
				return idx, true, nil
			}
			return -1, false, fmt.Errorf("%w: unresolved jump target %q", asm.ErrProbeNeedsContext, opnd.Ident)
		case asm.OpMem:
			if opnd.Mem.Base == asm.PC {
				targetOrd := pcOrderOf[pc] + int(opnd.Mem.Off)
				if targetOrd < 0 || targetOrd >= len(nonLabelIdx) {
					return -1, false, fmt.Errorf("%w: out-of-range PC-relative jump %s", asm.ErrProbeNeedsContext, opnd.String())
				}
				return nonLabelIdx[targetOrd], true, nil
			}
		case asm.OpSym:
			// Tail-call JMP sym(SB): does not return through local RET.
			return -1, false, nil
		}
		return -1, false, fmt.Errorf("%w: unprovable indirect branch target %s", asm.ErrProbeNeedsContext, opnd.String())
	}

	// Build result byte ranges and parameter byte ranges from sig.Frame.
	resultByteOwned := map[int64]bool{}
	type slotSpan struct {
		offset int64
		size   int64
	}
	resultSpans := make([]slotSpan, 0, len(sig.Frame.Results))
	for _, s := range sig.Frame.Results {
		sz := x86ABI0SlotBytes(s.Type, goarch)
		if sz <= 0 {
			return nil, fmt.Errorf("%w: result initialization: unsupported result slot type %q at +%d(FP)", asm.ErrProbeNeedsContext, s.Type, s.Offset)
		}
		resultSpans = append(resultSpans, slotSpan{offset: s.Offset, size: sz})
		for off := s.Offset; off < s.Offset+sz; off++ {
			resultByteOwned[off] = true
		}
	}
	paramByteOwned := map[int64]bool{}
	for _, s := range sig.Frame.Params {
		sz := x86ABI0SlotBytes(s.Type, goarch)
		for off := s.Offset; off < s.Offset+sz; off++ {
			paramByteOwned[off] = true
		}
	}

	// Entry state at pc = 0.
	entry := &abi0State{
		gpInit:         map[asm.Reg]bool{},
		gpTaintedSP:    map[asm.Reg]bool{},
		vecInit:        map[int]bool{},
		vecFromRaw:     map[int]bool{},
		fpBytesInit:    map[int64]bool{},
		localSlotsInit: map[int64]bool{},
	}
	for _, r := range sig.ArgRegs {
		entry.gpInit[canonicalGP(r)] = true
	}

	if len(instrs) == 0 {
		if len(resultSpans) > 0 {
			return nil, fmt.Errorf("%w: empty function leaves result slot +%d(FP) uninitialized", asm.ErrProbeNeedsContext, resultSpans[0].offset)
		}
		return &ABI0EffectReport{
			InitializedGP:  entry.gpInit,
			InitializedVec: entry.vecInit,
			WrittenResults: map[int64]bool{},
		}, nil
	}

	inStates := make([]*abi0State, len(instrs))
	inStates[0] = entry
	repPending := make([]bool, len(instrs))
	queue := []int{0}
	inQueue := make([]bool, len(instrs))
	inQueue[0] = true

	enqueue := func(next int, st *abi0State, nextRep bool) {
		if next < 0 || next >= len(instrs) {
			return
		}
		if inStates[next] == nil {
			inStates[next] = st.clone()
			repPending[next] = nextRep
			if !inQueue[next] {
				queue = append(queue, next)
				inQueue[next] = true
			}
			return
		}
		changed := inStates[next].merge(st)
		if nextRep && !repPending[next] {
			repPending[next] = true
			changed = true
		}
		if changed && !inQueue[next] {
			queue = append(queue, next)
			inQueue[next] = true
		}
	}

	checkRead := func(st *abi0State, op asm.Operand, raw string) error {
		switch op.Kind {
		case asm.OpReg:
			if op.Reg == asm.SP {
				return nil
			}
			if idx, ok := anyVecRegIndex(op.Reg); ok {
				if !st.vecInit[idx] {
					return fmt.Errorf("%w: %s reads uninitialized vector register %s", asm.ErrProbeNeedsContext, raw, op.Reg)
				}
				return nil
			}
			r := canonicalGP(op.Reg)
			if !st.gpInit[r] {
				return fmt.Errorf("%w: %s reads uninitialized register %s", asm.ErrProbeNeedsContext, raw, op.Reg)
			}
		case asm.OpMem:
			if op.Mem.Base == asm.SP && op.Mem.Off >= 0 {
				if !st.localSlotsInit[op.Mem.Off] {
					return fmt.Errorf("%w: %s reads uninitialized stack slot %d(SP)", asm.ErrProbeNeedsContext, raw, op.Mem.Off)
				}
				return nil
			}
			if op.Mem.Base != "" && op.Mem.Base != asm.SP && op.Mem.Base != asm.PC {
				if !st.gpInit[canonicalGP(op.Mem.Base)] {
					return fmt.Errorf("%w: %s reads uninitialized base register %s", asm.ErrProbeNeedsContext, raw, op.Mem.Base)
				}
			}
			if op.Mem.Index != "" && !st.gpInit[canonicalGP(op.Mem.Index)] {
				return fmt.Errorf("%w: %s reads uninitialized index register %s", asm.ErrProbeNeedsContext, raw, op.Mem.Index)
			}
		}
		return nil
	}

	markWrite := func(st *abi0State, op asm.Operand, writeBytes int64, fromRaw bool, taintSP bool) error {
		switch op.Kind {
		case asm.OpReg:
			if idx, ok := anyVecRegIndex(op.Reg); ok {
				st.vecInit[idx] = true
				st.vecFromRaw[idx] = fromRaw
				return nil
			}
			r := canonicalGP(op.Reg)
			st.gpInit[r] = true
			st.gpTaintedSP[r] = taintSP
		case asm.OpFP:
			if writeBytes <= 0 {
				return nil
			}
			touchesResult := false
			for off := op.FPOffset; off < op.FPOffset+writeBytes; off++ {
				if resultByteOwned[off] {
					touchesResult = true
					break
				}
			}
			if touchesResult {
				if taintSP {
					return fmt.Errorf("%w: private frame address escapes to result slot +%d(FP)", asm.ErrProbeNeedsContext, op.FPOffset)
				}
				if fromRaw {
					return fmt.Errorf("%w: raw-decoded value written to result slot +%d(FP)", asm.ErrProbeNeedsContext, op.FPOffset)
				}
				for off := op.FPOffset; off < op.FPOffset+writeBytes; off++ {
					if resultByteOwned[off] {
						st.fpBytesInit[off] = true
					}
				}
			}
		case asm.OpMem:
			if op.Mem.Base == asm.SP && op.Mem.Off >= 0 {
				if taintSP {
					return fmt.Errorf("%w: private frame address escapes to stack slot %d(SP)", asm.ErrProbeNeedsContext, op.Mem.Off)
				}
				st.localSlotsInit[op.Mem.Off] = true
			}
		}
		return nil
	}

	var retStates []*abi0State
	var finalState *abi0State

	for len(queue) > 0 {
		pc := queue[0]
		queue = queue[1:]
		inQueue[pc] = false

		st := inStates[pc].clone()
		curRep := repPending[pc]
		ins := instrs[pc]
		op := asm.Op(strings.ToUpper(string(ins.Op)))

		if op == "REP" || op == "REPN" {
			enqueue(pc+1, st, true)
			continue
		}
		if op == "LOCK" || op == asm.OpTEXT || op == asm.OpLABEL || op == "NOP" || op == "PCALIGN" ||
			op == "NO_LOCAL_POINTERS" || op == "FUNCDATA" || op == "PCDATA" || op == "GO_ARGS" {
			if pc+1 < len(instrs) {
				enqueue(pc+1, st, false)
			} else {
				finalState = st
			}
			continue
		}

		// Any raw-decoded instruction cannot supply proven ABI0 result initialization
		// on its own until explicitly validated against the lowering contract.
		if ins.DecodedFromRaw {
			return nil, fmt.Errorf("%w: decoded raw directive %q requires verified lowering provenance for ABI0 result initialization", asm.ErrProbeNeedsContext, ins.Raw)
		}

		if op == asm.OpRET {
			retStates = append(retStates, st)
			continue
		}

		if op == "UD2" || op == "HLT" {
			// Trap/halt terminates the path without reaching RET.
			continue
		}

		if op == "JMP" {
			if len(ins.Args) != 1 {
				return nil, fmt.Errorf("%w: JMP expects one target: %q", asm.ErrProbeNeedsContext, ins.Raw)
			}
			target, isLocal, err := resolveJumpTarget(pc, ins.Args[0])
			if err != nil {
				return nil, err
			}
			if isLocal {
				enqueue(target, st, false)
			}
			// Unconditional JMP never falls through!
			continue
		}

		if isX86CondJumpOp(op) {
			if len(ins.Args) != 1 {
				return nil, fmt.Errorf("%w: %s expects one target: %q", asm.ErrProbeNeedsContext, op, ins.Raw)
			}
			if op == "JCXZ" || op == "JECXZ" || op == "JRCXZ" || op == "LOOP" || op == "LOOPEQ" || op == "LOOPNE" {
				if err := checkRead(st, asm.Operand{Kind: asm.OpReg, Reg: asm.CX}, ins.Raw); err != nil {
					return nil, err
				}
			}
			target, isLocal, err := resolveJumpTarget(pc, ins.Args[0])
			if err != nil {
				return nil, err
			}
			if isLocal {
				enqueue(target, st, false)
			}
			if pc+1 < len(instrs) {
				enqueue(pc+1, st, false)
			}
			continue
		}

		if op == "CALL" {
			// Outgoing ABI0 call: if callee ABI0 frame layout is known, verify
			// its incoming stack parameters and mark its stack result slots initialized.
			if len(ins.Args) == 1 && ins.Args[0].Kind == asm.OpSym && resolve != nil && sigs != nil {
				raw := strings.TrimSuffix(strings.TrimSpace(ins.Args[0].Sym), "(SB)")
				callee := resolve(raw)
				if csig, ok := sigs[callee]; ok && len(csig.ArgRegs) == 0 && len(csig.Frame.Params) > 0 {
					for _, ps := range csig.Frame.Params {
						if !st.localSlotsInit[ps.Offset] {
							return nil, fmt.Errorf("%w: %s reads uninitialized outgoing ABI0 arg slot %d(SP)", asm.ErrProbeNeedsContext, ins.Raw, ps.Offset)
						}
					}
					for _, rs := range csig.Frame.Results {
						st.localSlotsInit[rs.Offset] = true
					}
				}
			}
			st.gpInit[asm.AX] = true
			st.gpTaintedSP[asm.AX] = false
			if pc+1 < len(instrs) {
				enqueue(pc+1, st, false)
			} else {
				finalState = st
			}
			continue
		}

		spec, ok := OpTable.Lookup(op)
		if !ok {
			spec = asm.OpSpec{Op: op, Effect: asm.EffectWriteOnly}
		}

		// Self-XOR idiom (XORL AX, AX / PXOR X0, X0 / VPXOR X0, X0, X0) initializes dst to zero.
		if isZeroingIdiom(op, ins.Args) {
			wBytes := x86ABI0WriteBytes(op, spec, ins.Args)
			if err := markWrite(st, ins.Args[len(ins.Args)-1], wBytes, false, false); err != nil {
				return nil, err
			}
			if pc+1 < len(instrs) {
				enqueue(pc+1, st, false)
			} else {
				finalState = st
			}
			continue
		}

		// Check implicit architectural register reads (OpSpec.Implicit + string/mul/div/sys rules).
		impReads, impWrites := implicitRegEffects(op, spec, curRep)
		for _, r := range impReads {
			if err := checkRead(st, asm.Operand{Kind: asm.OpReg, Reg: r}, ins.Raw); err != nil {
				return nil, err
			}
		}

		// Check source operands. EffectPreserveUpper preserves upper lanes of the
		// destination register, so the destination is also read.
		n := len(ins.Args)
		readEnd := n - 1
		if spec.Effect == asm.EffectReadOnly || spec.Effect == asm.EffectReadWrite ||
			spec.Effect == asm.EffectPreserveUpper || (spec.Effect == asm.EffectImplicit && !spec.ThreeOp) {
			readEnd = n
		}
		if spec.ThreeOp && spec.Effect == asm.EffectImplicit && n == 3 {
			// MULXL/MULXQ src, hi, lo reads only src (args[0]) and writes both hi and lo.
			readEnd = 1
		}
		srcTaintSP := false
		srcFromRaw := false
		for i := 0; i < readEnd && i < n; i++ {
			a := ins.Args[i]
			if a.Kind == asm.OpReg && a.Reg == asm.SP {
				srcTaintSP = true
			}
			if a.Kind == asm.OpReg && st.gpTaintedSP[canonicalGP(a.Reg)] {
				srcTaintSP = true
			}
			if a.Kind == asm.OpReg {
				if idx, ok := anyVecRegIndex(a.Reg); ok && st.vecFromRaw[idx] {
					srcFromRaw = true
				}
			}
			if a.Kind == asm.OpMem && a.Mem.Base == asm.SP && (op == "LEAQ" || op == "LEAL") {
				srcTaintSP = true
			}
			// FP parameter reads are always initialized by the Go caller.
			if a.Kind == asm.OpFP && paramByteOwned[a.FPOffset] {
				continue
			}
			if err := checkRead(st, a, ins.Raw); err != nil {
				return nil, err
			}
		}

		wBytes := x86ABI0WriteBytes(op, spec, ins.Args)
		if spec.ThreeOp && spec.Effect == asm.EffectImplicit && n == 3 {
			for i := 1; i < n; i++ {
				if err := markWrite(st, ins.Args[i], wBytes, srcFromRaw, srcTaintSP); err != nil {
					return nil, err
				}
			}
		} else if n > 0 && spec.Effect != asm.EffectReadOnly && spec.Effect != asm.EffectNone && spec.Effect != asm.EffectImplicit {
			if err := markWrite(st, ins.Args[n-1], wBytes, srcFromRaw, srcTaintSP); err != nil {
				return nil, err
			}
		}
		for _, r := range impWrites {
			st.gpInit[r] = true
			st.gpTaintedSP[r] = false
		}
		if pc+1 < len(instrs) {
			enqueue(pc+1, st, false)
		} else {
			finalState = st
		}
	}

	// Verify that on EVERY reachable RET (and any fallthrough end), every byte of
	// every declared ABI0 result slot was initialized on ALL paths reaching it.
	if finalState != nil {
		retStates = append(retStates, finalState)
	}
	for _, st := range retStates {
		for _, span := range resultSpans {
			for off := span.offset; off < span.offset+span.size; off++ {
				if !st.fpBytesInit[off] {
					return nil, fmt.Errorf("%w: RET with uninitialized result byte +%d(FP) (result slot +%d(FP) width %d)",
						asm.ErrProbeNeedsContext, off, span.offset, span.size)
				}
			}
		}
	}

	// Build summary report from the intersection of reachable exit states (or entry if no RET).
	var summary *abi0State
	for _, st := range retStates {
		if summary == nil {
			summary = st.clone()
		} else {
			summary.merge(st)
		}
	}
	if summary == nil {
		summary = entry
	}
	writtenResults := map[int64]bool{}
	for _, span := range resultSpans {
		allInit := true
		for off := span.offset; off < span.offset+span.size; off++ {
			if !summary.fpBytesInit[off] {
				allInit = false
				break
			}
		}
		if allInit {
			writtenResults[span.offset] = true
		}
	}

	return &ABI0EffectReport{
		InitializedGP:  summary.gpInit,
		InitializedVec: summary.vecInit,
		WrittenResults: writtenResults,
	}, nil
}

func isX86CondJumpOp(op asm.Op) bool {
	switch op {
	case "JE", "JEQ", "JZ", "JNE", "JNZ",
		"JL", "JLT", "JLE", "JG", "JGT", "JGE",
		"JB", "JLO", "JBE", "JNA", "JLS", "JA", "JHI", "JAE", "JHS",
		"JC", "JNC", "JCC", "JCS",
		"JS", "JNS", "JO", "JNO", "JP", "JPE", "JNP", "JPO",
		"JCXZ", "JECXZ", "JRCXZ", "LOOP", "LOOPEQ", "LOOPNE":
		return true
	default:
		return false
	}
}

func x86ABI0SlotBytes(ty asm.LLVMType, goarch string) int64 {
	switch ty {
	case asm.I1, asm.I8:
		return 1
	case asm.I16:
		return 2
	case asm.I32, "float":
		return 4
	case asm.I64, "double":
		return 8
	case asm.Ptr:
		if goarch == "386" {
			return 4
		}
		return 8
	default:
		return int64(x86FrameTypeSize(ty))
	}
}

func x86ABI0WriteBytes(op asm.Op, spec asm.OpSpec, args []asm.Operand) int64 {
	name := strings.ToUpper(string(op))
	if dot := strings.IndexByte(name, '.'); dot >= 0 {
		name = name[:dot]
	}
	if spec.Width > 0 {
		return int64(spec.Width) / 8
	}
	// Vector stores to FP: infer width from vector source register if present.
	for _, a := range args {
		if a.Kind == asm.OpReg {
			if isAMD64ZReg(a.Reg) {
				return 64
			}
			if isAMD64YReg(a.Reg) {
				return 32
			}
			if isAMD64XReg(a.Reg) {
				switch name {
				case "MOVSS", "VMOVSS", "MOVD", "VMOVD", "MOVL":
					return 4
				case "MOVSD", "VMOVSD", "MOVQ", "VMOVQ", "MOVHPS", "MOVLPS", "MOVHPD", "MOVLPD":
					return 8
				default:
					return 16
				}
			}
			if isAMD64MReg(a.Reg) {
				return 8
			}
		}
	}
	// SETcc writes 1 byte.
	if strings.HasPrefix(name, "SET") {
		return 1
	}
	switch name {
	case "MOVB", "ADDB", "SUBB", "ANDB", "ORB", "XORB", "INCB", "DECB", "NEGB", "NOTB", "XCHGB", "XADDB", "CMPXCHGB",
		"SHLB", "SHRB", "SARB", "ROLB", "RORB", "RCLB", "RCRB", "SALB", "FMOVB", "FMOVBP":
		return 1
	case "MOVW", "ADDW", "SUBW", "ANDW", "ORW", "XORW", "INCW", "DECW", "NEGW", "NOTW", "XCHGW", "XADDW", "CMPXCHGW",
		"SHLW", "SHRW", "SARW", "ROLW", "RORW", "RCLW", "RCRW", "SALW", "FSTCW", "FSTSW", "FMOVW", "FMOVWP", "MOVBEW":
		return 2
	case "MOVL", "MOVSS", "VMOVSS", "ADDL", "SUBL", "ANDL", "ORL", "XORL", "INCL", "DECL", "NEGL", "NOTL", "XCHGL", "XADDL", "CMPXCHGL",
		"SHLL", "SHRL", "SARL", "ROLL", "RORL", "RCLL", "RCRL", "SALL", "BSWAPL", "FMOVF", "FMOVFP", "FMOVL", "FMOVLP", "MOVBEL", "MOVNTI":
		return 4
	case "MOVQ", "MOVSD", "VMOVSD", "ADDQ", "SUBQ", "ANDQ", "ORQ", "XORQ", "INCQ", "DECQ", "NEGQ", "NOTQ", "XCHGQ", "XADDQ", "CMPXCHGQ",
		"SHLQ", "SHRQ", "SARQ", "ROLQ", "RORQ", "RCLQ", "RCRQ", "SALQ", "BSWAPQ", "FMOVD", "FMOVDP", "FMOVV", "FMOVVP", "MOVBEQ", "MOVNTIQ":
		return 8
	case "MOVO", "MOVOU", "MOVOA", "MOVUPS", "MOVUPD", "MOVAPS", "MOVAPD", "MOVDQU", "MOVDQA", "MOVNTDQ", "MOVNTDQA", "MOVNTPS", "MOVNTPD":
		return 16
	}
	return 0
}

func implicitRegEffects(op asm.Op, spec asm.OpSpec, repeated bool) (reads []asm.Reg, writes []asm.Reg) {
	switch spec.Family {
	case asm.FamilyString:
		if repeated {
			reads = append(reads, asm.CX)
			writes = append(writes, asm.CX)
		}
		switch spec.LLVMOp {
		case "movs", "cmps":
			reads = append(reads, asm.SI, asm.DI)
			writes = append(writes, asm.SI, asm.DI)
		case "stos", "scas":
			reads = append(reads, asm.AX, asm.DI)
			writes = append(writes, asm.DI)
		case "lods":
			reads = append(reads, asm.SI)
			writes = append(writes, asm.AX, asm.SI)
		}
		return reads, writes
	}

	switch op {
	case "MULB", "MULW", "MULL", "MULQ":
		return []asm.Reg{asm.AX}, []asm.Reg{asm.AX, asm.DX}
	case "MULXL", "MULXQ":
		return []asm.Reg{asm.DX}, nil
	case "DIVB", "IDIVB":
		return []asm.Reg{asm.AX}, []asm.Reg{asm.AX}
	case "DIVW", "DIVL", "DIVQ", "IDIVW", "IDIVL", "IDIVQ":
		return []asm.Reg{asm.AX, asm.DX}, []asm.Reg{asm.AX, asm.DX}
	case "CQO", "CDQ", "CWD":
		return []asm.Reg{asm.AX}, []asm.Reg{asm.DX}
	case "CBW", "CWDE", "CDQE":
		return []asm.Reg{asm.AX}, []asm.Reg{asm.AX}
	case "CPUID":
		return []asm.Reg{asm.AX}, []asm.Reg{asm.AX, asm.BX, asm.CX, asm.DX}
	case "XGETBV":
		return []asm.Reg{asm.CX}, []asm.Reg{asm.AX, asm.DX}
	case "RDTSC":
		return nil, []asm.Reg{asm.AX, asm.DX}
	case "RDTSCP":
		return nil, []asm.Reg{asm.AX, asm.DX, asm.CX}
	case "SYSCALL":
		return []asm.Reg{asm.AX}, []asm.Reg{asm.AX, asm.DX, asm.CX}
	case "LAHF":
		return nil, []asm.Reg{asm.AX}
	case "SAHF":
		return []asm.Reg{asm.AX}, nil
	case "XLAT":
		return []asm.Reg{asm.AX, asm.BX}, []asm.Reg{asm.AX}
	case "CMPXCHGB", "CMPXCHGW", "CMPXCHGL", "CMPXCHGQ":
		return []asm.Reg{asm.AX}, []asm.Reg{asm.AX}
	case "CMPXCHG8B", "CMPXCHG16B":
		return []asm.Reg{asm.AX, asm.DX, asm.BX, asm.CX}, []asm.Reg{asm.AX, asm.DX}
	}

	if spec.Implicit != asm.ImplicitNone {
		for _, pair := range []struct {
			mask asm.RegMask
			reg  asm.Reg
		}{
			{asm.ImplicitAX, asm.AX},
			{asm.ImplicitBX, asm.BX},
			{asm.ImplicitCX, asm.CX},
			{asm.ImplicitDX, asm.DX},
			{asm.ImplicitSI, asm.SI},
			{asm.ImplicitDI, asm.DI},
		} {
			if spec.Implicit&pair.mask != 0 {
				writes = append(writes, pair.reg)
			}
		}
	}
	return reads, writes
}

func isZeroingIdiom(op asm.Op, args []asm.Operand) bool {
	if len(args) == 2 && args[0].Kind == asm.OpReg && args[1].Kind == asm.OpReg && args[0].Reg == args[1].Reg {
		switch op {
		case "XORQ", "XORL", "XORW", "XORB", "SUBQ", "SUBL", "SUBW", "SUBB", "PXOR", "XORPS", "XORPD":
			return true
		}
	}
	if len(args) == 3 && args[0].Kind == asm.OpReg && args[1].Kind == asm.OpReg && args[2].Kind == asm.OpReg &&
		args[0].Reg == args[1].Reg {
		switch op {
		case "VPXOR", "VPXORD", "VPXORQ", "VXORPS", "VXORPD", "VPSUBB", "VPSUBW", "VPSUBD", "VPSUBQ":
			return true
		}
	}
	return false
}

func anyVecRegIndex(r asm.Reg) (int, bool) {
	if idx, ok := amd64ParseXReg(r); ok {
		return idx, true
	}
	if idx, ok := amd64ParseYReg(r); ok {
		return idx, true
	}
	if idx, ok := amd64ParseZReg(r); ok {
		return idx, true
	}
	return 0, false
}

func canonicalGP(r asm.Reg) asm.Reg {
	up := asm.Reg(strings.ToUpper(strings.TrimSpace(string(r))))
	if base, _, ok := amd64ByteAlias(up); ok {
		return base
	}
	if parsed, ok := asm.ParseReg(string(up)); ok {
		if base, _, ok := amd64ByteAlias(parsed); ok {
			return base
		}
		return parsed
	}
	return up
}
