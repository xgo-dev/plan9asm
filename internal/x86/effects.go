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

const (
	abi0FlagCF  uint8 = 1 << 0
	abi0FlagOF  uint8 = 1 << 1
	abi0FlagZF  uint8 = 1 << 2
	abi0FlagSF  uint8 = 1 << 3
	abi0FlagPF  uint8 = 1 << 4
	abi0FlagAll uint8 = abi0FlagCF | abi0FlagOF | abi0FlagZF | abi0FlagSF | abi0FlagPF
)

type abi0State struct {
	// gpBytesInit records initialized bytes per canonical GP register:
	// bit i (0..7) corresponds to byte i (AL/R8B = bit 0, AH = bit 1,
	// 16-bit = bits 0..1, 32-bit = bits 0..3, 64-bit = bits 0..7).
	gpBytesInit map[asm.Reg]uint8
	gpTaintedSP map[asm.Reg]bool
	// gpFlagTags tracks the exact architectural status-flag definedness mask
	// carried by a GP register holding a saved FLAGS/RFLAGS/LAHF snapshot.
	gpFlagTags map[asm.Reg]uint8
	// vecBytesInit records initialized bytes per XMM/YMM/ZMM register:
	// bits 0..15 = XMM, bits 0..31 = YMM, bits 0..63 = ZMM.
	vecBytesInit map[int]uint64
	vecFromRaw   map[int]bool
	// fpBytesInit records initialized byte offsets in the FP frame
	// (pre-populated with declared parameter slot bytes plus written result bytes).
	fpBytesInit map[int64]bool
	// spBytesInit records initialized byte offsets in the private SP stack frame
	// (relative to initial SP at function entry; indexed by spOffset + mem.Off).
	spBytesInit      map[int64]bool
	spBytesTaintedSP map[int64]bool
	// spFlagSlots records the exact architectural status-flag definedness mask
	// pushed by PUSHFQ/PUSHFL/PUSHFW (or propagated via PUSHQ/PUSHL/PUSHW of a
	// tagged GP register) at a stack slot offset.
	spFlagSlots map[int64]uint8
	spOffset    int64
	// Architectural status flag definedness tracked independently:
	//   - cfInit: Carry Flag (CF)
	//   - ofInit: Overflow Flag (OF)
	//   - zfInit: Zero Flag (ZF) — preserved by BT/BTS/BTR/BTC
	//   - sfInit: Sign Flag (SF)
	//   - pfInit: Parity Flag (PF)
	cfInit bool
	ofInit bool
	zfInit bool
	sfInit bool
	pfInit bool
}

func (s *abi0State) flagsMask() uint8 {
	var m uint8
	if s.cfInit {
		m |= abi0FlagCF
	}
	if s.ofInit {
		m |= abi0FlagOF
	}
	if s.zfInit {
		m |= abi0FlagZF
	}
	if s.sfInit {
		m |= abi0FlagSF
	}
	if s.pfInit {
		m |= abi0FlagPF
	}
	return m
}

func (s *abi0State) setFlagsFromMask(m uint8) {
	s.cfInit = (m & abi0FlagCF) != 0
	s.ofInit = (m & abi0FlagOF) != 0
	s.zfInit = (m & abi0FlagZF) != 0
	s.sfInit = (m & abi0FlagSF) != 0
	s.pfInit = (m & abi0FlagPF) != 0
}

func (s *abi0State) effectiveStackFlagMask(off int64) uint8 {
	if m, ok := s.spFlagSlots[off]; ok {
		return m
	}
	var m uint8
	if s.spBytesInit[off] {
		m |= abi0FlagCF | abi0FlagPF | abi0FlagZF | abi0FlagSF
	}
	if s.spBytesInit[off+1] {
		m |= abi0FlagOF
	}
	return m
}

func (s *abi0State) effectiveGPFlagMask(r asm.Reg) uint8 {
	if m, ok := s.gpFlagTags[r]; ok {
		return m
	}
	var m uint8
	b := s.gpBytesInit[r]
	if (b & 0x01) != 0 {
		m |= abi0FlagCF | abi0FlagPF | abi0FlagZF | abi0FlagSF
	}
	if (b & 0x02) != 0 {
		m |= abi0FlagOF
	}
	return m
}

func (s *abi0State) invalidateStackFlagSlotsRange(start, end int64) {
	for slot := range s.spFlagSlots {
		if slot < end && start < slot+8 {
			delete(s.spFlagSlots, slot)
		}
	}
}

func (s *abi0State) clone() *abi0State {
	out := &abi0State{
		gpBytesInit:      make(map[asm.Reg]uint8, len(s.gpBytesInit)),
		gpTaintedSP:      make(map[asm.Reg]bool, len(s.gpTaintedSP)),
		gpFlagTags:       make(map[asm.Reg]uint8, len(s.gpFlagTags)),
		vecBytesInit:     make(map[int]uint64, len(s.vecBytesInit)),
		vecFromRaw:       make(map[int]bool, len(s.vecFromRaw)),
		fpBytesInit:      make(map[int64]bool, len(s.fpBytesInit)),
		spBytesInit:      make(map[int64]bool, len(s.spBytesInit)),
		spBytesTaintedSP: make(map[int64]bool, len(s.spBytesTaintedSP)),
		spFlagSlots:      make(map[int64]uint8, len(s.spFlagSlots)),
		spOffset:         s.spOffset,
		cfInit:           s.cfInit,
		ofInit:           s.ofInit,
		zfInit:           s.zfInit,
		sfInit:           s.sfInit,
		pfInit:           s.pfInit,
	}
	for k, v := range s.gpBytesInit {
		out.gpBytesInit[k] = v
	}
	for k, v := range s.gpTaintedSP {
		out.gpTaintedSP[k] = v
	}
	for k, v := range s.gpFlagTags {
		out.gpFlagTags[k] = v
	}
	for k, v := range s.vecBytesInit {
		out.vecBytesInit[k] = v
	}
	for k, v := range s.vecFromRaw {
		out.vecFromRaw[k] = v
	}
	for k, v := range s.fpBytesInit {
		out.fpBytesInit[k] = v
	}
	for k, v := range s.spBytesInit {
		out.spBytesInit[k] = v
	}
	for k, v := range s.spBytesTaintedSP {
		out.spBytesTaintedSP[k] = v
	}
	for k, v := range s.spFlagSlots {
		out.spFlagSlots[k] = v
	}
	return out
}

// merge combines incoming state `other` into `s` at a CFG join point:
//   - must-initialized byte masks/sets and saved-flag masks intersect
//   - may-tainted sets (gpTaintedSP, spBytesTaintedSP, vecFromRaw) union
//
// Returns true if `s` changed.
func (s *abi0State) merge(other *abi0State) bool {
	changed := false
	// Compute joined GP flag tags before intersecting gpBytesInit so untagged
	// paths contribute their byte-derived flag mask accurately.
	if len(s.gpFlagTags) > 0 || len(other.gpFlagTags) > 0 {
		keys := make(map[asm.Reg]struct{}, len(s.gpFlagTags)+len(other.gpFlagTags))
		for k := range s.gpFlagTags {
			keys[k] = struct{}{}
		}
		for k := range other.gpFlagTags {
			keys[k] = struct{}{}
		}
		for k := range keys {
			inter := s.effectiveGPFlagMask(k) & other.effectiveGPFlagMask(k)
			cur, had := s.gpFlagTags[k]
			if !had || cur != inter {
				s.gpFlagTags[k] = inter
				changed = true
			}
		}
	}
	for k, cur := range s.gpBytesInit {
		inter := cur & other.gpBytesInit[k]
		if inter != cur {
			if inter == 0 {
				delete(s.gpBytesInit, k)
			} else {
				s.gpBytesInit[k] = inter
			}
			changed = true
		}
	}
	for k, cur := range s.vecBytesInit {
		inter := cur & other.vecBytesInit[k]
		if inter != cur {
			if inter == 0 {
				delete(s.vecBytesInit, k)
			} else {
				s.vecBytesInit[k] = inter
			}
			changed = true
		}
	}
	for k := range s.fpBytesInit {
		if !other.fpBytesInit[k] {
			delete(s.fpBytesInit, k)
			changed = true
		}
	}
	if s.spOffset != other.spOffset {
		if len(s.spBytesInit) > 0 {
			s.spBytesInit = make(map[int64]bool)
			changed = true
		}
		if len(s.spFlagSlots) > 0 {
			s.spFlagSlots = make(map[int64]uint8)
			changed = true
		}
	} else {
		if len(s.spFlagSlots) > 0 || len(other.spFlagSlots) > 0 {
			keys := make(map[int64]struct{}, len(s.spFlagSlots)+len(other.spFlagSlots))
			for k := range s.spFlagSlots {
				keys[k] = struct{}{}
			}
			for k := range other.spFlagSlots {
				keys[k] = struct{}{}
			}
			for k := range keys {
				inter := s.effectiveStackFlagMask(k) & other.effectiveStackFlagMask(k)
				cur, had := s.spFlagSlots[k]
				if !had || cur != inter {
					s.spFlagSlots[k] = inter
					changed = true
				}
			}
		}
		for k := range s.spBytesInit {
			if !other.spBytesInit[k] {
				delete(s.spBytesInit, k)
				changed = true
			}
		}
	}
	if s.cfInit && !other.cfInit {
		s.cfInit = false
		changed = true
	}
	if s.ofInit && !other.ofInit {
		s.ofInit = false
		changed = true
	}
	if s.zfInit && !other.zfInit {
		s.zfInit = false
		changed = true
	}
	if s.sfInit && !other.sfInit {
		s.sfInit = false
		changed = true
	}
	if s.pfInit && !other.pfInit {
		s.pfInit = false
		changed = true
	}
	for k, v := range other.gpTaintedSP {
		if v && !s.gpTaintedSP[k] {
			s.gpTaintedSP[k] = true
			changed = true
		}
	}
	for k, v := range other.spBytesTaintedSP {
		if v && !s.spBytesTaintedSP[k] {
			s.spBytesTaintedSP[k] = true
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

// CheckABI0ResultInit verifies that a Go ABI0 x86/amd64 function obeys
// byte-level register, stack-slot, and FP initialization, private stack-pointer
// confinement, raw-directive provenance, and CFG/byte-exact ABI0 result
// initialization rules before emitting code.
//
// Driven directly by OpTable so adding new instructions automatically participates
// in effect tracking without per-opcode boilerplate.
func CheckABI0ResultInit(fn asm.Func, sig asm.FuncSig, goarch string) (*ABI0EffectReport, error) {
	return CheckABI0ResultInitWithSigs(fn, sig, goarch, nil, nil)
}

// CheckABI0ResultInitWithSigs extends CheckABI0ResultInit with callee ABI0
// signatures so outgoing CALLs can verify outgoing parameter bytes and mark
// callee ABI0 result stack bytes initialized.
func CheckABI0ResultInitWithSigs(fn asm.Func, sig asm.FuncSig, goarch string, resolve func(string) string, sigs map[string]asm.FuncSig) (*ABI0EffectReport, error) {
	instrs, err := DecodeRawDirectives(fn.Instrs, goarch)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", asm.ErrProbeNeedsContext, err)
	}

	wordMask := uint8(0xff)
	ptrBytes := int64(8)
	if goarch == "386" {
		wordMask = 0x0f
		ptrBytes = 4
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
	resultSpans := make([]abi0SlotSpan, 0, len(sig.Frame.Results))
	for _, s := range sig.Frame.Results {
		sz := x86ABI0SlotBytes(s.Type, goarch)
		if sz <= 0 {
			return nil, fmt.Errorf("%w: result initialization: unsupported result slot type %q at +%d(FP)", asm.ErrProbeNeedsContext, s.Type, s.Offset)
		}
		resultSpans = append(resultSpans, abi0SlotSpan{offset: s.Offset, size: sz})
		for off := s.Offset; off < s.Offset+sz; off++ {
			resultByteOwned[off] = true
		}
	}

	// Entry state at pc = 0: pre-populate declared parameter FP bytes and ArgRegs.
	entry := &abi0State{
		gpBytesInit:      map[asm.Reg]uint8{},
		gpTaintedSP:      map[asm.Reg]bool{},
		gpFlagTags:       map[asm.Reg]uint8{},
		vecBytesInit:     map[int]uint64{},
		vecFromRaw:       map[int]bool{},
		fpBytesInit:      map[int64]bool{},
		spBytesInit:      map[int64]bool{},
		spBytesTaintedSP: map[int64]bool{},
		spFlagSlots:      map[int64]uint8{},
	}
	for _, s := range sig.Frame.Params {
		sz := x86ABI0SlotBytes(s.Type, goarch)
		for off := s.Offset; off < s.Offset+sz; off++ {
			entry.fpBytesInit[off] = true
		}
	}
	for _, r := range sig.ArgRegs {
		entry.gpBytesInit[canonicalGP(r)] = wordMask
	}

	if len(instrs) == 0 {
		if len(resultSpans) > 0 {
			return nil, fmt.Errorf("%w: empty function leaves result slot +%d(FP) uninitialized", asm.ErrProbeNeedsContext, resultSpans[0].offset)
		}
		return buildABI0Report(entry, resultSpans, wordMask), nil
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

	checkGPRead := func(st *abi0State, reg asm.Reg, reqMask uint8, raw string) error {
		if reg == asm.SP {
			return nil
		}
		r := canonicalGP(reg)
		if (st.gpBytesInit[r] & reqMask) != reqMask {
			return fmt.Errorf("%w: %s reads uninitialized register bytes of %s (have=0x%02x want=0x%02x)",
				asm.ErrProbeNeedsContext, raw, reg, st.gpBytesInit[r], reqMask)
		}
		return nil
	}

	// evalOperand evaluates the exact byte-level definedness bitmask of an input
	// operand while enforcing hard safety checks on memory dereferences, FP slot
	// reads, and private SP stack reads. Pure GP/vector register reads propagate
	// exact byte-level definedness rather than rejecting dead scratch arithmetic
	// (e.g., Go stdlib hash/crc32's dead ADDQ $0x40, DI or math/big's TESTQ AX, AX).
	evalOperand := func(st *abi0State, op asm.Operand, readBytes int64, isLEA bool, opName asm.Op, raw string) (mask uint64, allInit bool, err error) {
		switch op.Kind {
		case asm.OpImm, asm.OpSym:
			full := abi0ByteMaskN(readBytes)
			return full, true, nil

		case asm.OpReg:
			if op.Reg == asm.SP || isAMD64KReg(op.Reg) || isAMD64MReg(op.Reg) {
				full := abi0ByteMaskN(readBytes)
				return full, true, nil
			}
			if idx, ok := anyVecRegIndex(op.Reg); ok {
				req := vecRegReadByteMask(op.Reg, opName, readBytes)
				have := st.vecBytesInit[idx] & req
				return have, have == req, nil
			}
			req := gpRegReadByteMask(op.Reg, readBytes, wordMask)
			have := st.gpBytesInit[canonicalGP(op.Reg)] & req
			aligned := uint64(have)
			if req == 0x02 {
				aligned = uint64((have >> 1) & 0x01)
			}
			return aligned, have == req, nil

		case asm.OpFP:
			if isLEA {
				full := abi0ByteMaskN(ptrBytes)
				return full, true, nil
			}
			nBytes := readBytes
			if nBytes <= 0 {
				nBytes = ptrBytes
			}
			for off := op.FPOffset; off < op.FPOffset+nBytes; off++ {
				if !st.fpBytesInit[off] {
					return 0, false, fmt.Errorf("%w: %s reads uninitialized FP byte +%d(FP) (read +%d(FP) width %d)",
						asm.ErrProbeNeedsContext, raw, off, op.FPOffset, nBytes)
				}
			}
			return abi0ByteMaskN(nBytes), true, nil

		case asm.OpMem:
			if op.Mem.Base == asm.SP {
				if isLEA {
					if op.Mem.Index != "" {
						r := canonicalGP(op.Mem.Index)
						if (st.gpBytesInit[r] & wordMask) != wordMask {
							return 0, false, nil
						}
					}
					return abi0ByteMaskN(ptrBytes), true, nil
				}
				if op.Mem.Index != "" {
					// Indexed stack read (e.g. sha256block_amd64.s (SP)(SI*1)):
					// index register must be initialized, and the loaded bytes are
					// conservatively treated as uninitialized so they cannot satisfy
					// an ABI0 result slot or be dereferenced as a pointer.
					if err := checkGPRead(st, op.Mem.Index, wordMask, raw); err != nil {
						return 0, false, err
					}
					return 0, false, nil
				}
				nBytes := readBytes
				if nBytes <= 0 {
					nBytes = ptrBytes
				}
				for off := op.Mem.Off; off < op.Mem.Off+nBytes; off++ {
					if !st.spBytesInit[st.spOffset+off] {
						return 0, false, fmt.Errorf("%w: %s reads uninitialized stack byte %d(SP) (read %d(SP) width %d)",
							asm.ErrProbeNeedsContext, raw, off, op.Mem.Off, nBytes)
					}
				}
				return abi0ByteMaskN(nBytes), true, nil
			}
			if isLEA {
				ok := true
				if op.Mem.Base != "" && op.Mem.Base != asm.PC {
					r := canonicalGP(op.Mem.Base)
					if (st.gpBytesInit[r] & wordMask) != wordMask {
						ok = false
					}
				}
				if op.Mem.Index != "" {
					r := canonicalGP(op.Mem.Index)
					if (st.gpBytesInit[r] & wordMask) != wordMask {
						ok = false
					}
				}
				if !ok {
					return 0, false, nil
				}
				return abi0ByteMaskN(ptrBytes), true, nil
			}
			if op.Mem.Base != "" && op.Mem.Base != asm.SP && op.Mem.Base != asm.PC {
				if err := checkGPRead(st, op.Mem.Base, wordMask, raw); err != nil {
					return 0, false, err
				}
			}
			if op.Mem.Index != "" {
				if err := checkGPRead(st, op.Mem.Index, wordMask, raw); err != nil {
					return 0, false, err
				}
			}
			return abi0ByteMaskN(readBytes), true, nil
		}
		return abi0ByteMaskN(readBytes), true, nil
	}

	writeDstMask := func(st *abi0State, op asm.Operand, writeBytes int64, valMask uint64, opName asm.Op, spec asm.OpSpec, pureCopy bool, fromRaw bool, taintSP bool, srcIsReg bool) error {
		switch op.Kind {
		case asm.OpReg:
			if op.Reg == asm.SP || isAMD64KReg(op.Reg) || isAMD64MReg(op.Reg) {
				return nil
			}
			if idx, ok := anyVecRegIndex(op.Reg); ok {
				name := strings.ToUpper(string(opName))
				if dot := strings.IndexByte(name, '.'); dot >= 0 {
					name = name[:dot]
				}
				wMask, zeroUpper := vecRegWriteByteMask(op.Reg, opName, writeBytes, srcIsReg)
				if pureCopy {
					lowWidth := vecCopyWidth(op.Reg, name, writeBytes)
					lowMask := abi0ByteMaskN(lowWidth)
					lowBits := valMask & lowMask
					if zeroUpper {
						st.vecBytesInit[idx] = lowBits | ^lowMask
					} else if (name == "MOVSS" || name == "MOVSD") && srcIsReg {
						st.vecBytesInit[idx] = (st.vecBytesInit[idx] &^ lowMask) | lowBits
					} else {
						// Legacy SSE write into XMM zeroes bytes [lowWidth..15] and preserves [16..63].
						st.vecBytesInit[idx] = (st.vecBytesInit[idx] &^ uint64(0xffff)) | lowBits | (uint64(0xffff) &^ lowMask)
					}
				} else if spec.Effect == asm.EffectPreserveUpper {
					lowWidth := int64(8)
					if strings.HasSuffix(name, "SS") {
						lowWidth = 4
					}
					lowMask := abi0ByteMaskN(lowWidth)
					if (valMask & lowMask) == lowMask {
						st.vecBytesInit[idx] |= lowMask
					} else {
						st.vecBytesInit[idx] &^= lowMask
					}
				} else {
					allInit := writeBytes <= 0 || (valMask&abi0ByteMaskN(writeBytes)) == abi0ByteMaskN(writeBytes)
					if zeroUpper {
						regMask := vecRegFullByteMask(op.Reg)
						if allInit {
							st.vecBytesInit[idx] = ^uint64(0)
						} else {
							st.vecBytesInit[idx] = ^regMask
						}
					} else {
						if allInit {
							st.vecBytesInit[idx] |= wMask
						} else {
							st.vecBytesInit[idx] &^= wMask
						}
					}
				}
				st.vecFromRaw[idx] = fromRaw
				return nil
			}
			r := canonicalGP(op.Reg)
			delete(st.gpFlagTags, r)
			wMask, clearsUpper := gpRegWriteByteMask(op.Reg, writeBytes, goarch)
			var placed uint8
			if wMask == 0x02 {
				placed = uint8((valMask & 0x01) << 1)
			} else {
				placed = uint8(valMask) & wMask
			}
			if clearsUpper {
				// 32-bit GP writes on amd64 zero-extend upper 4 bytes (known zero = initialized).
				upperZero := wordMask &^ wMask
				st.gpBytesInit[r] = placed | upperZero
			} else {
				st.gpBytesInit[r] = (st.gpBytesInit[r] &^ wMask) | placed
			}
			if taintSP {
				st.gpTaintedSP[r] = true
			} else if clearsUpper || wMask == wordMask {
				st.gpTaintedSP[r] = false
			}

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
			}
			for b := int64(0); b < writeBytes; b++ {
				off := op.FPOffset + b
				if b < 64 && (valMask&(uint64(1)<<uint(b))) != 0 {
					st.fpBytesInit[off] = true
				} else {
					delete(st.fpBytesInit, off)
				}
			}

		case asm.OpMem:
			if op.Mem.Base == asm.SP && op.Mem.Index == "" {
				if taintSP {
					return fmt.Errorf("%w: private frame address escapes to stack slot %d(SP)", asm.ErrProbeNeedsContext, op.Mem.Off)
				}
				nBytes := writeBytes
				if nBytes <= 0 {
					return nil
				}
				start := st.spOffset + op.Mem.Off
				st.invalidateStackFlagSlotsRange(start, start+nBytes)
				for b := int64(0); b < nBytes; b++ {
					off := start + b
					delete(st.spBytesTaintedSP, off)
					if b < 64 && (valMask&(uint64(1)<<uint(b))) != 0 {
						st.spBytesInit[off] = true
					} else {
						delete(st.spBytesInit, off)
					}
				}
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
			op == "NO_LOCAL_POINTERS" || op == "FUNCDATA" || op == "PCDATA" || op == "GO_ARGS" ||
			op == "VZEROUPPER" || op == "VZEROALL" || op == "CLD" || op == "STD" ||
			op == "LFENCE" || op == "SFENCE" || op == "MFENCE" || op == "PAUSE" || op == "EMMS" {
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

		if op == "UD2" || op == "HLT" || op == "UNDEF" {
			// Trap/halt terminates the path without reaching RET.
			continue
		}

		// Model stack-pointer displacement, exact byte-level stack-slot
		// initialization, and saved status-flag definedness for PUSH*/POP*/PUSHF*/POPF*.
		switch op {
		case "PUSHFQ", "PUSHFL", "PUSHFW":
			w := int64(8)
			if op == "PUSHFL" {
				w = 4
			} else if op == "PUSHFW" {
				w = 2
			}
			st.spOffset -= w
			st.invalidateStackFlagSlotsRange(st.spOffset, st.spOffset+w)
			for b := int64(0); b < w; b++ {
				st.spBytesInit[st.spOffset+b] = true
				delete(st.spBytesTaintedSP, st.spOffset+b)
			}
			// Preserve exact status-flag definedness so PUSHF*; POPF* cannot forge
			// defined CF/OF/ZF/SF/PF from undefined entry flags.
			st.spFlagSlots[st.spOffset] = st.flagsMask()
			if pc+1 < len(instrs) {
				enqueue(pc+1, st, false)
			} else {
				finalState = st
			}
			continue
		case "POPFQ", "POPFL", "POPFW":
			w := int64(8)
			if op == "POPFL" {
				w = 4
			} else if op == "POPFW" {
				w = 2
			}
			restored := st.effectiveStackFlagMask(st.spOffset)
			delete(st.spFlagSlots, st.spOffset)
			for b := int64(0); b < w; b++ {
				delete(st.spBytesInit, st.spOffset+b)
				delete(st.spBytesTaintedSP, st.spOffset+b)
			}
			st.spOffset += w
			st.setFlagsFromMask(restored)
			if pc+1 < len(instrs) {
				enqueue(pc+1, st, false)
			} else {
				finalState = st
			}
			continue
		case "PUSHQ", "PUSHL", "PUSHW":
			w := int64(8)
			if op == "PUSHL" {
				w = 4
			} else if op == "PUSHW" {
				w = 2
			}
			var pushMask uint64 = abi0ByteMaskN(w)
			var pushTaintSP bool
			var pushFlagTag uint8
			var hasPushFlagTag bool
			if len(ins.Args) == 1 {
				arg := ins.Args[0]
				if arg.Kind == asm.OpReg {
					if arg.Reg == asm.SP || st.gpTaintedSP[canonicalGP(arg.Reg)] {
						pushTaintSP = true
					}
					if tag, ok := st.gpFlagTags[canonicalGP(arg.Reg)]; ok && w >= 2 {
						pushFlagTag, hasPushFlagTag = tag, true
					}
				} else if arg.Kind == asm.OpMem && arg.Mem.Base == asm.SP && arg.Mem.Index == "" && w >= 2 {
					if tag, ok := st.spFlagSlots[st.spOffset+arg.Mem.Off]; ok {
						pushFlagTag, hasPushFlagTag = tag, true
					}
				}
				m, _, err := evalOperand(st, arg, w, false, op, ins.Raw)
				if err != nil {
					return nil, err
				}
				pushMask = m
			}
			st.spOffset -= w
			st.invalidateStackFlagSlotsRange(st.spOffset, st.spOffset+w)
			for b := int64(0); b < w; b++ {
				if (pushMask & (uint64(1) << uint(b))) != 0 {
					st.spBytesInit[st.spOffset+b] = true
				} else {
					delete(st.spBytesInit, st.spOffset+b)
				}
				if pushTaintSP {
					st.spBytesTaintedSP[st.spOffset+b] = true
				} else {
					delete(st.spBytesTaintedSP, st.spOffset+b)
				}
			}
			if hasPushFlagTag {
				st.spFlagSlots[st.spOffset] = pushFlagTag
			}
			if pc+1 < len(instrs) {
				enqueue(pc+1, st, false)
			} else {
				finalState = st
			}
			continue
		case "POPQ", "POPL", "POPW":
			w := int64(8)
			if op == "POPL" {
				w = 4
			} else if op == "POPW" {
				w = 2
			}
			var valMask uint64
			var popTaintSP bool
			for b := int64(0); b < w; b++ {
				if st.spBytesInit[st.spOffset+b] {
					valMask |= uint64(1) << uint(b)
				}
				if st.spBytesTaintedSP[st.spOffset+b] {
					popTaintSP = true
				}
			}
			popFlagTag, hasPopFlagTag := st.spFlagSlots[st.spOffset]
			delete(st.spFlagSlots, st.spOffset)
			for b := int64(0); b < w; b++ {
				delete(st.spBytesInit, st.spOffset+b)
				delete(st.spBytesTaintedSP, st.spOffset+b)
			}
			// Intel SDM: POP increments SP before computing an SP-relative destination address.
			st.spOffset += w
			if len(ins.Args) == 1 {
				dst := ins.Args[0]
				if dst.Kind == asm.OpMem {
					if dst.Mem.Base != "" && dst.Mem.Base != asm.SP && dst.Mem.Base != asm.PC {
						if err := checkGPRead(st, dst.Mem.Base, wordMask, ins.Raw); err != nil {
							return nil, err
						}
					}
					if dst.Mem.Index != "" {
						if err := checkGPRead(st, dst.Mem.Index, wordMask, ins.Raw); err != nil {
							return nil, err
						}
					}
				}
				specPop := asm.OpSpec{Op: op, Width: uint16(w * 8), Effect: asm.EffectWriteOnly}
				if err := writeDstMask(st, dst, w, valMask, op, specPop, true, false, popTaintSP, false); err != nil {
					return nil, err
				}
				if hasPopFlagTag && w >= 2 {
					switch dst.Kind {
					case asm.OpReg:
						if dst.Reg != asm.SP && !isAMD64KReg(dst.Reg) && !isAMD64MReg(dst.Reg) {
							if _, isVec := anyVecRegIndex(dst.Reg); !isVec {
								st.gpFlagTags[canonicalGP(dst.Reg)] = popFlagTag
							}
						}
					case asm.OpMem:
						if dst.Mem.Base == asm.SP && dst.Mem.Index == "" {
							st.spFlagSlots[st.spOffset+dst.Mem.Off] = popFlagTag
						}
					}
				}
			}
			if pc+1 < len(instrs) {
				enqueue(pc+1, st, false)
			} else {
				finalState = st
			}
			continue
		case "ADDQ", "SUBQ":
			if len(ins.Args) == 2 && ins.Args[0].Kind == asm.OpImm && ins.Args[1].Kind == asm.OpReg && ins.Args[1].Reg == asm.SP {
				if op == "ADDQ" {
					st.spOffset += ins.Args[0].Imm
				} else {
					st.spOffset -= ins.Args[0].Imm
				}
				st.cfInit = true
				st.ofInit = true
				st.zfInit = true
				st.sfInit = true
				st.pfInit = true
				if pc+1 < len(instrs) {
					enqueue(pc+1, st, false)
				} else {
					finalState = st
				}
				continue
			}
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
			// Unconditional JMP never falls through.
			continue
		}

		if isX86CondJumpOp(op) {
			if len(ins.Args) != 1 {
				return nil, fmt.Errorf("%w: %s expects one target: %q", asm.ErrProbeNeedsContext, op, ins.Raw)
			}
			if op == "JCXZ" || op == "JECXZ" || op == "JRCXZ" || op == "LOOP" || op == "LOOPEQ" || op == "LOOPNE" {
				if err := checkGPRead(st, asm.CX, wordMask, ins.Raw); err != nil {
					return nil, err
				}
				if (op == "LOOPEQ" || op == "LOOPNE") && !st.zfInit {
					return nil, fmt.Errorf("%w: %s reads uninitialized flag ZF", asm.ErrProbeNeedsContext, ins.Raw)
				}
			} else if missing := missingCondFlag(st, op); missing != "" {
				return nil, fmt.Errorf("%w: %s reads uninitialized flag %s", asm.ErrProbeNeedsContext, ins.Raw, missing)
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
			// Outgoing call: validate parameters and mark return slots strictly
			// according to the callee signature. Caller-saved registers and flags
			// are clobbered across CALL; ABI0 callees return via Frame.Results on
			// (SP) (including zero-parameter callees), never via AX.
			if len(ins.Args) == 1 && ins.Args[0].Kind == asm.OpSym {
				var csig asm.FuncSig
				var hasSig bool
				if resolve != nil && sigs != nil {
					raw := strings.TrimSuffix(strings.TrimSpace(ins.Args[0].Sym), "(SB)")
					callee := resolve(raw)
					csig, hasSig = sigs[callee]
				}
				if hasSig {
					if len(csig.ArgRegs) == 0 {
						for _, ps := range csig.Frame.Params {
							sz := x86ABI0SlotBytes(ps.Type, goarch)
							for off := ps.Offset; off < ps.Offset+sz; off++ {
								if !st.spBytesInit[st.spOffset+off] {
									return nil, fmt.Errorf("%w: %s reads uninitialized outgoing ABI0 arg byte %d(SP)", asm.ErrProbeNeedsContext, ins.Raw, off)
								}
							}
						}
					} else {
						for _, r := range csig.ArgRegs {
							if err := checkGPRead(st, r, wordMask, ins.Raw); err != nil {
								return nil, err
							}
						}
					}
				}
				st.gpBytesInit = map[asm.Reg]uint8{}
				st.gpTaintedSP = map[asm.Reg]bool{}
				st.gpFlagTags = map[asm.Reg]uint8{}
				st.vecBytesInit = map[int]uint64{}
				st.vecFromRaw = map[int]bool{}
				st.cfInit = false
				st.ofInit = false
				st.zfInit = false
				st.sfInit = false
				st.pfInit = false
				if hasSig {
					if len(csig.ArgRegs) == 0 {
						for _, rs := range csig.Frame.Results {
							sz := x86ABI0SlotBytes(rs.Type, goarch)
							st.invalidateStackFlagSlotsRange(st.spOffset+rs.Offset, st.spOffset+rs.Offset+sz)
							for off := rs.Offset; off < rs.Offset+sz; off++ {
								st.spBytesInit[st.spOffset+off] = true
								delete(st.spBytesTaintedSP, st.spOffset+off)
							}
						}
					} else if csig.Ret != "" && csig.Ret != asm.Void {
						sz := x86ABI0SlotBytes(csig.Ret, goarch)
						wMask, clearsUpper := gpRegWriteByteMask(asm.AX, sz, goarch)
						if clearsUpper {
							st.gpBytesInit[asm.AX] = wordMask
						} else if wMask != 0 {
							st.gpBytesInit[asm.AX] = wMask
						}
					}
				}
			} else if len(ins.Args) == 1 && ins.Args[0].Kind == asm.OpReg {
				// Indirect C-ABI/vDSO call (e.g. syscall/asm_linux_amd64.s CALL AX).
				if err := checkGPRead(st, ins.Args[0].Reg, wordMask, ins.Raw); err != nil {
					return nil, err
				}
				st.gpBytesInit = map[asm.Reg]uint8{}
				st.gpTaintedSP = map[asm.Reg]bool{}
				st.gpFlagTags = map[asm.Reg]uint8{}
				st.vecBytesInit = map[int]uint64{}
				st.vecFromRaw = map[int]bool{}
				st.cfInit = false
				st.ofInit = false
				st.zfInit = false
				st.sfInit = false
				st.pfInit = false
				st.gpBytesInit[asm.AX] = wordMask
			} else {
				st.gpBytesInit = map[asm.Reg]uint8{}
				st.gpTaintedSP = map[asm.Reg]bool{}
				st.gpFlagTags = map[asm.Reg]uint8{}
				st.vecBytesInit = map[int]uint64{}
				st.vecFromRaw = map[int]bool{}
				st.cfInit = false
				st.ofInit = false
				st.zfInit = false
				st.sfInit = false
				st.pfInit = false
			}
			if pc+1 < len(instrs) {
				enqueue(pc+1, st, false)
			} else {
				finalState = st
			}
			continue
		}

		if op == "CLC" || op == "STC" {
			// CLC and STC define CF only; OF/ZF/SF/PF are unaffected.
			st.cfInit = true
			if pc+1 < len(instrs) {
				enqueue(pc+1, st, false)
			} else {
				finalState = st
			}
			continue
		}

		if op == "CMC" {
			// CMC complements CF in place; CF remains defined iff it was already defined.
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

		readBytes, writeBytes := x86ABI0OpWidths(op, spec, ins.Args, goarch)
		isLEA := op == "LEAQ" || op == "LEAL" || op == "LEAW"

		// Self-XOR / self-SUB / self-PCMPEQ idioms materialize a known constant
		// (0 or all-ones) without depending on prior contents of dst.
		if isZeroingIdiom(op, ins.Args) {
			if err := writeDstMask(st, ins.Args[len(ins.Args)-1], writeBytes, abi0ByteMaskN(writeBytes), op, spec, false, false, false, true); err != nil {
				return nil, err
			}
			if isX86ClearCFOfOp(op) || isX86GPFlagWriter(op) {
				st.cfInit = true
				st.ofInit = true
				st.zfInit = true
				st.sfInit = true
				st.pfInit = true
			}
			if pc+1 < len(instrs) {
				enqueue(pc+1, st, false)
			} else {
				finalState = st
			}
			continue
		}

		// Check implicit architectural register reads. Memory/trapping ops (string
		// ops, DIV/IDIV, SYSCALL, XLAT) hard-require initialized implicit inputs;
		// nontrapping ALU ops propagate definedness to their outputs.
		impReads, impWrites := implicitRegByteEffects(op, spec, curRep, wordMask)
		allInputsInit := true
		hardImplicit := spec.Family == asm.FamilyString ||
			op == "DIVB" || op == "IDIVB" || op == "DIVW" || op == "IDIVW" ||
			op == "DIVL" || op == "IDIVL" || op == "DIVQ" || op == "IDIVQ" ||
			op == "SYSCALL" || op == "XLAT"
		for _, ir := range impReads {
			if hardImplicit {
				if err := checkGPRead(st, ir.reg, ir.mask, ins.Raw); err != nil {
					return nil, err
				}
			} else if (st.gpBytesInit[ir.reg] & ir.mask) != ir.mask {
				allInputsInit = false
			}
		}

		// Flag-consuming instructions require their exact consumed flag(s) to be initialized.
		// For RCL/RCR with an immediate effective count of 0, CF is neither read nor modified.
		if missingCondFlag(st, op) != "" {
			allInputsInit = false
		}
		if needsNonCondCF(op, ins.Args) && !st.cfInit {
			allInputsInit = false
		}
		if (op == "ADOXL" || op == "ADOXQ") && !st.ofInit {
			allInputsInit = false
		}

		// Check source operands. EffectPreserveUpper preserves upper lanes of the
		// destination register; for pure byte-preserving moves we propagate exact
		// per-byte definedness masks.
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
		if (op == "MOVSS" || op == "MOVSD") && n == 2 && ins.Args[0].Kind == asm.OpReg && ins.Args[1].Kind == asm.OpReg {
			readEnd = 1
		}
		// Check base/index registers of a memory destination (e.g. MOVQ $1, 8(BX) reads BX!).
		if n > 0 && readEnd < n && ins.Args[n-1].Kind == asm.OpMem {
			dstMem := ins.Args[n-1].Mem
			if dstMem.Base != "" && dstMem.Base != asm.SP && dstMem.Base != asm.PC {
				if err := checkGPRead(st, dstMem.Base, wordMask, ins.Raw); err != nil {
					return nil, err
				}
			}
			if dstMem.Index != "" {
				if err := checkGPRead(st, dstMem.Index, wordMask, ins.Raw); err != nil {
					return nil, err
				}
			}
		}

		pureCopy := isPureByteCopyOp(op, ins.Args)
		var copyMask uint64

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
			if a.Kind == asm.OpMem && a.Mem.Base == asm.SP && isLEA {
				srcTaintSP = true
			}
			argReadBytes := readBytes
			if i == n-1 && readEnd == n {
				// Read-modify-write destination reads its own write width.
				argReadBytes = writeBytes
			}
			if i == 0 && isShiftWithCountArg(op) && a.Kind == asm.OpReg {
				// Shift/rotate count in CL/CX only reads byte 0.
				argReadBytes = 1
			}
			// EffectPreserveUpper only reads the low scalar lane of src and preserves
			// upper lanes of dst (which should not poison the low lane).
			if spec.Effect == asm.EffectPreserveUpper && i == n-1 && a.Kind == asm.OpReg {
				continue
			}
			m, okInit, err := evalOperand(st, a, argReadBytes, isLEA, op, ins.Raw)
			if err != nil {
				return nil, err
			}
			if pureCopy && i == 0 {
				copyMask = m
			}
			if !okInit {
				allInputsInit = false
			}
		}

		// Capture saved-flag tag on pure copies before writeDstMask clears destination tags.
		var copyFlagTag uint8
		var hasCopyFlagTag bool
		if pureCopy && n == 2 && writeBytes >= 2 {
			src := ins.Args[0]
			if src.Kind == asm.OpReg {
				if tag, ok := st.gpFlagTags[canonicalGP(src.Reg)]; ok {
					copyFlagTag, hasCopyFlagTag = tag, true
				}
			} else if src.Kind == asm.OpMem && src.Mem.Base == asm.SP && src.Mem.Index == "" {
				if tag, ok := st.spFlagSlots[st.spOffset+src.Mem.Off]; ok {
					copyFlagTag, hasCopyFlagTag = tag, true
				}
			}
		}

		// Apply destination writes with exact byte-level definedness masks.
		var dstValMask uint64
		if pureCopy {
			dstValMask = copyMask
		} else if allInputsInit {
			dstValMask = abi0ByteMaskN(writeBytes)
		} else {
			dstValMask = 0
		}

		srcIsReg := n >= 2 && ins.Args[0].Kind == asm.OpReg
		if spec.ThreeOp && spec.Effect == asm.EffectImplicit && n == 3 {
			for i := 1; i < n; i++ {
				if err := writeDstMask(st, ins.Args[i], writeBytes, dstValMask, op, spec, false, srcFromRaw, srcTaintSP, srcIsReg); err != nil {
					return nil, err
				}
			}
		} else if n > 0 && spec.Effect != asm.EffectReadOnly && spec.Effect != asm.EffectNone && spec.Effect != asm.EffectImplicit {
			if err := writeDstMask(st, ins.Args[n-1], writeBytes, dstValMask, op, spec, pureCopy, srcFromRaw, srcTaintSP, srcIsReg); err != nil {
				return nil, err
			}
			if hasCopyFlagTag {
				dst := ins.Args[n-1]
				if dst.Kind == asm.OpReg && dst.Reg != asm.SP && !isAMD64KReg(dst.Reg) && !isAMD64MReg(dst.Reg) {
					if _, isVec := anyVecRegIndex(dst.Reg); !isVec {
						st.gpFlagTags[canonicalGP(dst.Reg)] = copyFlagTag
					}
				} else if dst.Kind == asm.OpMem && dst.Mem.Base == asm.SP && dst.Mem.Index == "" {
					st.spFlagSlots[st.spOffset+dst.Mem.Off] = copyFlagTag
				}
			}
		}
		for _, iw := range impWrites {
			delete(st.gpFlagTags, iw.reg)
			if allInputsInit {
				if iw.clearsUpper {
					st.gpBytesInit[iw.reg] = wordMask
					st.gpTaintedSP[iw.reg] = false
				} else {
					st.gpBytesInit[iw.reg] |= iw.mask
				}
			} else {
				if iw.clearsUpper {
					st.gpBytesInit[iw.reg] = wordMask &^ iw.mask
				} else {
					st.gpBytesInit[iw.reg] &^= iw.mask
				}
			}
		}
		if op == "LAHF" {
			// Record exact definedness of the low-byte flags copied into AH so
			// LAHF; SAHF cannot forge defined CF/ZF/SF/PF from undefined entry flags.
			st.gpFlagTags[asm.AX] = st.flagsMask() &^ abi0FlagOF
		}
		// Update status flags independently per architectural semantics.
		updateX86FlagsAfter(st, op, ins.Args, allInputsInit)
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
	return buildABI0Report(summary, resultSpans, wordMask), nil
}

type abi0SlotSpan struct {
	offset int64
	size   int64
}

func buildABI0Report(summary *abi0State, resultSpans []abi0SlotSpan, wordMask uint8) *ABI0EffectReport {
	initGP := make(map[asm.Reg]bool, len(summary.gpBytesInit))
	for r, mask := range summary.gpBytesInit {
		if (mask & wordMask) == wordMask {
			initGP[r] = true
		}
	}
	initVec := make(map[int]bool, len(summary.vecBytesInit))
	for idx, mask := range summary.vecBytesInit {
		if (mask & 0xffff) == 0xffff {
			initVec[idx] = true
		}
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
		InitializedGP:  initGP,
		InitializedVec: initVec,
		WrittenResults: writtenResults,
	}
}

func gpRegReadByteMask(r asm.Reg, readBytes int64, wordMask uint8) uint8 {
	up := asm.Reg(strings.ToUpper(strings.TrimSpace(string(r))))
	if _, shift, ok := amd64ByteAlias(up); ok {
		if shift == 8 {
			return 0x02
		}
		return 0x01
	}
	switch readBytes {
	case 1:
		return 0x01
	case 2:
		return 0x03
	case 4:
		return 0x0f
	case 8:
		return wordMask
	default:
		return wordMask
	}
}

func gpRegWriteByteMask(r asm.Reg, writeBytes int64, goarch string) (mask uint8, clearsUpper bool) {
	up := asm.Reg(strings.ToUpper(strings.TrimSpace(string(r))))
	if _, shift, ok := amd64ByteAlias(up); ok {
		if shift == 8 {
			return 0x02, false
		}
		return 0x01, false
	}
	switch writeBytes {
	case 1:
		return 0x01, false
	case 2:
		return 0x03, false
	case 4:
		// 32-bit GP writes zero-extend to 64 bits on amd64, and fill the full word on 386.
		return 0x0f, true
	case 8:
		return 0xff, true
	default:
		if goarch == "386" {
			return 0x0f, true
		}
		return 0xff, true
	}
}

func vecRegReadByteMask(r asm.Reg, op asm.Op, readBytes int64) uint64 {
	if isAMD64ZReg(r) {
		return ^uint64(0)
	}
	if isAMD64YReg(r) {
		return 0xffffffff
	}
	name := strings.ToUpper(string(op))
	if dot := strings.IndexByte(name, '.'); dot >= 0 {
		name = name[:dot]
	}
	switch name {
	case "MOVSS", "VMOVSS", "ADDSS", "SUBSS", "MULSS", "DIVSS", "SQRTSS", "MINSS", "MAXSS",
		"UCOMISS", "COMISS", "CVTSS2SD", "CVTSS2SI", "CVTTSS2SI", "CVTSS2SIL", "CVTSS2SIQ",
		"CVTTSS2SIL", "CVTTSS2SIQ", "MOVD", "VMOVD", "MOVL":
		return 0x0f
	case "MOVSD", "VMOVSD", "ADDSD", "SUBSD", "MULSD", "DIVSD", "SQRTSD", "MINSD", "MAXSD",
		"UCOMISD", "COMISD", "CVTSD2SS", "CVTSD2SI", "CVTTSD2SI", "CVTSD2SIL", "CVTSD2SIQ",
		"CVTTSD2SIL", "CVTTSD2SIQ", "MOVQ", "VMOVQ":
		return 0xff
	}
	if readBytes == 4 {
		return 0x0f
	}
	if readBytes == 8 {
		return 0xff
	}
	return 0xffff
}

func vecRegWriteByteMask(r asm.Reg, op asm.Op, writeBytes int64, srcIsReg bool) (mask uint64, zeroUpper bool) {
	name := strings.ToUpper(string(op))
	if dot := strings.IndexByte(name, '.'); dot >= 0 {
		name = name[:dot]
	}
	// VEX/EVEX instructions write their vector width and zero all upper bytes up to ZMM.
	if strings.HasPrefix(name, "V") {
		return ^uint64(0), true
	}
	// Legacy SSE scalar reg-to-reg MOVSS/MOVSD preserves upper bytes of XMM.
	if name == "MOVSS" && srcIsReg {
		return 0x0f, false
	}
	if name == "MOVSD" && srcIsReg {
		return 0xff, false
	}
	// All other legacy SSE writes (including MOVSS/MOVSD mem->reg, MOVL/MOVQ->XMM, MOVOU, PXOR, ...)
	// define all 16 bytes of the XMM register.
	return 0xffff, false
}

func isShiftWithCountArg(op asm.Op) bool {
	switch op {
	case "SHLB", "SHLW", "SHLL", "SHLQ",
		"SALB", "SALW", "SALL", "SALQ",
		"SHRB", "SHRW", "SHRL", "SHRQ",
		"SARB", "SARW", "SARL", "SARQ",
		"ROLB", "ROLW", "ROLL", "ROLQ",
		"RORB", "RORW", "RORL", "RORQ",
		"RCLB", "RCLW", "RCLL", "RCLQ",
		"RCRB", "RCRW", "RCRL", "RCRQ",
		"SHLDW", "SHLDL", "SHLDQ",
		"SHRDW", "SHRDL", "SHRDQ":
		return true
	default:
		return false
	}
}

func isX86CondJumpOp(op asm.Op) bool {
	switch op {
	case "JE", "JEQ", "JZ", "JNE", "JNZ",
		"JL", "JLT", "JLE", "JG", "JGT", "JGE",
		"JB", "JLO", "JBE", "JNA", "JLS", "JA", "JHI", "JAE", "JHS", "JNB", "JNAE", "JNBE", "JNGE", "JNL", "JNG", "JNLE",
		"JC", "JNC", "JCC", "JCS",
		"JS", "JNS", "JMI", "JPL",
		"JO", "JNO", "JOS", "JOC",
		"JP", "JPE", "JNP", "JPO", "JPS", "JPC",
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

func x86ABI0OpWidths(op asm.Op, spec asm.OpSpec, args []asm.Operand, goarch string) (readBytes, writeBytes int64) {
	name := strings.ToUpper(string(op))
	if dot := strings.IndexByte(name, '.'); dot >= 0 {
		name = name[:dot]
	}
	// Explicit widening / narrowing integer moves have distinct source and destination widths.
	switch name {
	case "MOVBWZX", "MOVBWSX":
		return 1, 2
	case "MOVBLZX", "MOVBLSX":
		return 1, 4
	case "MOVBQZX", "MOVBQSX":
		return 1, 8
	case "MOVWLZX", "MOVWLSX":
		return 2, 4
	case "MOVWQZX", "MOVWQSX":
		return 2, 8
	case "MOVLQZX", "MOVLQSX":
		return 4, 8
	case "KMOVB":
		// KMOVB k, r32 zero-extends to 32/64 bits on GP destination.
		if len(args) == 2 && args[1].Kind == asm.OpReg && !isAMD64KReg(args[1].Reg) {
			return 1, 4
		}
		return 1, 1
	case "KMOVW":
		// KMOVW k, r32 zero-extends to 32/64 bits on GP destination.
		if len(args) == 2 && args[1].Kind == asm.OpReg && !isAMD64KReg(args[1].Reg) {
			return 2, 4
		}
		return 2, 2
	case "PMOVMSKB", "VPMOVMSKB", "MOVMSKPS", "VMOVMSKPS", "MOVMSKPD", "VMOVMSKPD":
		return 16, 4
	case "PEXTRB", "VPEXTRB", "PEXTRW", "VPEXTRW", "PEXTRD", "VPEXTRD":
		if len(args) >= 2 && args[len(args)-1].Kind == asm.OpReg {
			return 16, 4
		}
	case "PEXTRQ", "VPEXTRQ":
		if len(args) >= 2 && args[len(args)-1].Kind == asm.OpReg {
			return 16, 8
		}
	case "CVTSI2SSL", "CVTSI2SDL", "CVTSS2SIL", "CVTSD2SIL", "CVTTSS2SIL", "CVTTSD2SIL",
		"VCVTSI2SSL", "VCVTSI2SDL", "VCVTSS2SIL", "VCVTSD2SIL", "VCVTTSS2SIL", "VCVTTSD2SIL":
		return 4, 4
	case "CVTSI2SSQ", "CVTSI2SDQ", "CVTSS2SIQ", "CVTSD2SIQ", "CVTTSS2SIQ", "CVTTSD2SIQ",
		"VCVTSI2SSQ", "VCVTSI2SDQ", "VCVTSS2SIQ", "VCVTSD2SIQ", "VCVTTSS2SIQ", "VCVTTSD2SIQ":
		return 8, 8
	}
	if spec.SrcWidth > 0 && spec.Width > 0 {
		return int64(spec.SrcWidth) / 8, int64(spec.Width) / 8
	}
	w := x86ABI0WriteBytes(op, spec, args)
	if w > 0 {
		return w, w
	}
	if goarch == "386" {
		return 4, 4
	}
	return 8, 8
}

func x86ABI0WriteBytes(op asm.Op, spec asm.OpSpec, args []asm.Operand) int64 {
	name := strings.ToUpper(string(op))
	if dot := strings.IndexByte(name, '.'); dot >= 0 {
		name = name[:dot]
	}
	if spec.Width > 0 {
		return int64(spec.Width) / 8
	}
	// Vector stores/loads: infer width from vector register if present.
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
	if strings.HasPrefix(name, "CMOV") {
		switch {
		case strings.HasPrefix(name, "CMOVW"):
			return 2
		case strings.HasPrefix(name, "CMOVL"):
			return 4
		case strings.HasPrefix(name, "CMOVQ"):
			return 8
		}
	}
	switch name {
	case "MOVB", "ADDB", "SUBB", "ANDB", "ORB", "XORB", "ADCB", "SBBB", "CMPB", "TESTB",
		"INCB", "DECB", "NEGB", "NOTB", "XCHGB", "XADDB", "CMPXCHGB",
		"SHLB", "SHRB", "SARB", "ROLB", "RORB", "RCLB", "RCRB", "SALB", "FMOVB", "FMOVBP", "KMOVB":
		return 1
	case "MOVW", "ADDW", "SUBW", "ANDW", "ORW", "XORW", "ADCW", "SBBW", "CMPW", "TESTW",
		"INCW", "DECW", "NEGW", "NOTW", "XCHGW", "XADDW", "CMPXCHGW", "IMULW", "MULW",
		"SHLW", "SHRW", "SARW", "ROLW", "RORW", "RCLW", "RCRW", "SALW", "SHLDW", "SHRDW",
		"BTWW", "BTW", "BTSW", "BTRW", "BTCW", "BSFW", "BSRW", "POPCNTW", "LZCNTW", "TZCNTW",
		"FSTCW", "FSTSW", "FMOVW", "FMOVWP", "MOVBEW", "LEAW", "KMOVW":
		return 2
	case "MOVL", "MOVSS", "VMOVSS", "ADDL", "SUBL", "ANDL", "ORL", "XORL", "ADCL", "SBBL", "CMPL", "TESTL",
		"INCL", "DECL", "NEGL", "NOTL", "XCHGL", "XADDL", "CMPXCHGL", "IMULL", "MULL", "MULXL",
		"SHLL", "SHRL", "SARL", "ROLL", "RORL", "RCLL", "RCRL", "SALL", "SHLDL", "SHRDL",
		"BTL", "BTSL", "BTRL", "BTCL", "BSFL", "BSRL", "POPCNTL", "LZCNTL", "TZCNTL", "ANDNL", "BEXTRL",
		"BLSIL", "BLSMSKL", "BLSRL", "BZHIL", "PEXPL", "PDEPL", "PEXTL", "RORXL", "SARXL", "SHLXL", "SHRXL",
		"BSWAPL", "FMOVF", "FMOVFP", "FMOVL", "FMOVLP", "MOVBEL", "MOVNTI", "MOVNTIL", "LEAL", "KMOVD", "MOVD":
		return 4
	case "MOVQ", "MOVSD", "VMOVSD", "ADDQ", "SUBQ", "ANDQ", "ORQ", "XORQ", "ADCQ", "SBBQ", "CMPQ", "TESTQ",
		"INCQ", "DECQ", "NEGQ", "NOTQ", "XCHGQ", "XADDQ", "CMPXCHGQ", "IMULQ", "MULQ", "MULXQ",
		"SHLQ", "SHRQ", "SARQ", "ROLQ", "RORQ", "RCLQ", "RCRQ", "SALQ", "SHLDQ", "SHRDQ",
		"BTQ", "BTSQ", "BTRQ", "BTCQ", "BSFQ", "BSRQ", "POPCNTQ", "LZCNTQ", "TZCNTQ", "ANDNQ", "BEXTRQ",
		"BLSIQ", "BLSMSKQ", "BLSRQ", "BZHIQ", "PDEPQ", "PEXTQ", "RORXQ", "SARXQ", "SHLXQ", "SHRXQ",
		"BSWAPQ", "FMOVD", "FMOVDP", "FMOVV", "FMOVVP", "MOVBEQ", "MOVNTIQ", "LEAQ", "KMOVQ", "ADCXQ", "ADOXQ":
		return 8
	case "MOVO", "MOVOU", "MOVOA", "MOVUPS", "MOVUPD", "MOVAPS", "MOVAPD", "MOVDQU", "MOVDQA", "MOVNTDQ", "MOVNTDQA", "MOVNTPS", "MOVNTPD":
		return 16
	}
	return 0
}

type regMaskEffect struct {
	reg         asm.Reg
	mask        uint8
	clearsUpper bool
}

func implicitRegByteEffects(op asm.Op, spec asm.OpSpec, repeated bool, wordMask uint8) (reads []regMaskEffect, writes []regMaskEffect) {
	full := func(r asm.Reg) regMaskEffect { return regMaskEffect{reg: r, mask: wordMask, clearsUpper: true} }
	part := func(r asm.Reg, m uint8, clear bool) regMaskEffect {
		return regMaskEffect{reg: r, mask: m, clearsUpper: clear}
	}

	switch spec.Family {
	case asm.FamilyString:
		if repeated {
			reads = append(reads, full(asm.CX))
			writes = append(writes, full(asm.CX))
		}
		axMask := wordMask
		axClear := true
		switch spec.Width {
		case 8:
			axMask, axClear = 0x01, false
		case 16:
			axMask, axClear = 0x03, false
		case 32:
			axMask, axClear = 0x0f, true
		}
		switch spec.LLVMOp {
		case "movs", "cmps":
			reads = append(reads, full(asm.SI), full(asm.DI))
			writes = append(writes, full(asm.SI), full(asm.DI))
		case "stos", "scas":
			reads = append(reads, part(asm.AX, axMask, false), full(asm.DI))
			writes = append(writes, full(asm.DI))
		case "lods":
			reads = append(reads, full(asm.SI))
			writes = append(writes, part(asm.AX, axMask, axClear), full(asm.SI))
		}
		return reads, writes
	}

	switch op {
	case "MULB":
		return []regMaskEffect{part(asm.AX, 0x01, false)}, []regMaskEffect{part(asm.AX, 0x03, false)}
	case "MULW":
		return []regMaskEffect{part(asm.AX, 0x03, false)}, []regMaskEffect{part(asm.AX, 0x03, false), part(asm.DX, 0x03, false)}
	case "MULL":
		return []regMaskEffect{part(asm.AX, 0x0f, false)}, []regMaskEffect{part(asm.AX, 0x0f, true), part(asm.DX, 0x0f, true)}
	case "MULQ":
		return []regMaskEffect{full(asm.AX)}, []regMaskEffect{full(asm.AX), full(asm.DX)}
	case "MULXL":
		return []regMaskEffect{part(asm.DX, 0x0f, false)}, nil
	case "MULXQ":
		return []regMaskEffect{full(asm.DX)}, nil
	case "DIVB", "IDIVB":
		return []regMaskEffect{part(asm.AX, 0x03, false)}, []regMaskEffect{part(asm.AX, 0x03, false)}
	case "DIVW", "IDIVW":
		return []regMaskEffect{part(asm.AX, 0x03, false), part(asm.DX, 0x03, false)}, []regMaskEffect{part(asm.AX, 0x03, false), part(asm.DX, 0x03, false)}
	case "DIVL", "IDIVL":
		return []regMaskEffect{part(asm.AX, 0x0f, false), part(asm.DX, 0x0f, false)}, []regMaskEffect{part(asm.AX, 0x0f, true), part(asm.DX, 0x0f, true)}
	case "DIVQ", "IDIVQ":
		return []regMaskEffect{full(asm.AX), full(asm.DX)}, []regMaskEffect{full(asm.AX), full(asm.DX)}
	case "CWD":
		return []regMaskEffect{part(asm.AX, 0x03, false)}, []regMaskEffect{part(asm.DX, 0x03, false)}
	case "CDQ":
		return []regMaskEffect{part(asm.AX, 0x0f, false)}, []regMaskEffect{part(asm.DX, 0x0f, true)}
	case "CQO":
		return []regMaskEffect{full(asm.AX)}, []regMaskEffect{full(asm.DX)}
	case "CBW":
		return []regMaskEffect{part(asm.AX, 0x01, false)}, []regMaskEffect{part(asm.AX, 0x03, false)}
	case "CWDE":
		return []regMaskEffect{part(asm.AX, 0x03, false)}, []regMaskEffect{part(asm.AX, 0x0f, true)}
	case "CDQE":
		return []regMaskEffect{part(asm.AX, 0x0f, false)}, []regMaskEffect{full(asm.AX)}
	case "CPUID":
		return []regMaskEffect{part(asm.AX, 0x0f, false)}, []regMaskEffect{full(asm.AX), full(asm.BX), full(asm.CX), full(asm.DX)}
	case "XGETBV":
		return []regMaskEffect{part(asm.CX, 0x0f, false)}, []regMaskEffect{full(asm.AX), full(asm.DX)}
	case "RDTSC":
		return nil, []regMaskEffect{full(asm.AX), full(asm.DX)}
	case "RDTSCP":
		return nil, []regMaskEffect{full(asm.AX), full(asm.DX), full(asm.CX)}
	case "SYSCALL":
		return []regMaskEffect{full(asm.AX)}, []regMaskEffect{full(asm.AX), full(asm.DX), full(asm.CX)}
	case "LAHF":
		return nil, []regMaskEffect{part(asm.AX, 0x02, false)}
	case "SAHF":
		return []regMaskEffect{part(asm.AX, 0x02, false)}, nil
	case "PCMPESTRI":
		return []regMaskEffect{part(asm.AX, 0x0f, false), part(asm.DX, 0x0f, false)}, []regMaskEffect{part(asm.CX, 0x0f, true)}
	case "XLAT":
		return []regMaskEffect{part(asm.AX, 0x01, false), full(asm.BX)}, []regMaskEffect{part(asm.AX, 0x01, false)}
	case "CMPXCHGB":
		return []regMaskEffect{part(asm.AX, 0x01, false)}, []regMaskEffect{part(asm.AX, 0x01, false)}
	case "CMPXCHGW":
		return []regMaskEffect{part(asm.AX, 0x03, false)}, []regMaskEffect{part(asm.AX, 0x03, false)}
	case "CMPXCHGL":
		return []regMaskEffect{part(asm.AX, 0x0f, false)}, []regMaskEffect{part(asm.AX, 0x0f, true)}
	case "CMPXCHGQ":
		return []regMaskEffect{full(asm.AX)}, []regMaskEffect{full(asm.AX)}
	case "CMPXCHG8B":
		return []regMaskEffect{part(asm.AX, 0x0f, false), part(asm.DX, 0x0f, false), part(asm.BX, 0x0f, false), part(asm.CX, 0x0f, false)},
			[]regMaskEffect{part(asm.AX, 0x0f, true), part(asm.DX, 0x0f, true)}
	case "CMPXCHG16B":
		return []regMaskEffect{full(asm.AX), full(asm.DX), full(asm.BX), full(asm.CX)}, []regMaskEffect{full(asm.AX), full(asm.DX)}
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
				writes = append(writes, full(pair.reg))
			}
		}
	}
	return reads, writes
}

func isZeroingIdiom(op asm.Op, args []asm.Operand) bool {
	if len(args) == 2 && args[0].Kind == asm.OpReg && args[1].Kind == asm.OpReg && args[0].Reg == args[1].Reg {
		switch op {
		case "XORQ", "XORL", "XORW", "XORB", "SUBQ", "SUBL", "SUBW", "SUBB",
			"PXOR", "XORPS", "XORPD", "PCMPEQB", "PCMPEQW", "PCMPEQD", "PCMPEQQ":
			return true
		}
	}
	if len(args) == 3 && args[0].Kind == asm.OpReg && args[1].Kind == asm.OpReg && args[2].Kind == asm.OpReg &&
		args[0].Reg == args[1].Reg {
		switch op {
		case "VPXOR", "VPXORD", "VPXORQ", "VXORPS", "VXORPD",
			"VPSUBB", "VPSUBW", "VPSUBD", "VPSUBQ",
			"VPCMPEQB", "VPCMPEQW", "VPCMPEQD", "VPCMPEQQ":
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

func abi0ByteMaskN(n int64) uint64 {
	if n <= 0 {
		return 0
	}
	if n >= 64 {
		return ^uint64(0)
	}
	return (uint64(1) << uint(n)) - 1
}

func vecRegFullByteMask(r asm.Reg) uint64 {
	if isAMD64ZReg(r) {
		return ^uint64(0)
	}
	if isAMD64YReg(r) {
		return 0xffffffff
	}
	return 0xffff
}

func vecCopyWidth(r asm.Reg, name string, writeBytes int64) int64 {
	switch name {
	case "MOVSS", "VMOVSS", "MOVD", "VMOVD", "MOVL":
		return 4
	case "MOVSD", "VMOVSD", "MOVQ", "VMOVQ":
		return 8
	}
	if isAMD64ZReg(r) {
		return 64
	}
	if isAMD64YReg(r) {
		return 32
	}
	if writeBytes > 0 && writeBytes <= 64 {
		return writeBytes
	}
	return 16
}

func isPureByteCopyOp(op asm.Op, args []asm.Operand) bool {
	if len(args) != 2 {
		return false
	}
	name := strings.ToUpper(string(op))
	if dot := strings.IndexByte(name, '.'); dot >= 0 {
		name = name[:dot]
	}
	switch name {
	case "MOVB", "MOVW", "MOVL", "MOVQ", "MOVD",
		"MOVO", "MOVOU", "MOVOA", "MOVUPS", "MOVUPD", "MOVAPS", "MOVAPD",
		"MOVDQU", "MOVDQA", "MOVNTDQ", "MOVNTDQA", "MOVNTPS", "MOVNTPD",
		"MOVSS", "MOVSD",
		"VMOVD", "VMOVQ", "VMOVSS", "VMOVSD",
		"VMOVUPS", "VMOVUPD", "VMOVAPS", "VMOVAPD",
		"VMOVDQU", "VMOVDQA", "VMOVDQU8", "VMOVDQU16", "VMOVDQU32", "VMOVDQU64",
		"VMOVDQA32", "VMOVDQA64":
		return true
	}
	return false
}

func isX86ClearCFOfOp(op asm.Op) bool {
	switch op {
	case "TESTB", "TESTW", "TESTL", "TESTQ",
		"ANDB", "ANDW", "ANDL", "ANDQ",
		"ORB", "ORW", "ORL", "ORQ",
		"XORB", "XORW", "XORL", "XORQ":
		return true
	}
	return false
}

func isX86GPFlagWriter(op asm.Op) bool {
	switch op {
	case "ADDB", "ADDW", "ADDL", "ADDQ",
		"SUBB", "SUBW", "SUBL", "SUBQ",
		"ADCB", "ADCW", "ADCL", "ADCQ",
		"SBBB", "SBBW", "SBBL", "SBBQ",
		"CMPB", "CMPW", "CMPL", "CMPQ",
		"INCB", "INCW", "INCL", "INCQ",
		"DECB", "DECW", "DECL", "DECQ",
		"NEGB", "NEGW", "NEGL", "NEGQ",
		"MULB", "MULW", "MULL", "MULQ",
		"IMULB", "IMULW", "IMULL", "IMULQ",
		"CMPXCHGB", "CMPXCHGW", "CMPXCHGL", "CMPXCHGQ", "CMPXCHG8B", "CMPXCHG16B",
		"XADDB", "XADDW", "XADDL", "XADDQ",
		"BTB", "BTW", "BTL", "BTQ",
		"BTSW", "BTSL", "BTSQ", "BTRW", "BTRL", "BTRQ", "BTCW", "BTCL", "BTCQ",
		"SHLB", "SHLW", "SHLL", "SHLQ", "SALB", "SALW", "SALL", "SALQ",
		"SHRB", "SHRW", "SHRL", "SHRQ", "SARB", "SARW", "SARL", "SARQ",
		"ROLB", "ROLW", "ROLL", "ROLQ", "RORB", "RORW", "RORL", "RORQ",
		"RCLB", "RCLW", "RCLL", "RCLQ", "RCRB", "RCRW", "RCRL", "RCRQ",
		"SHLDW", "SHLDL", "SHLDQ", "SHRDW", "SHRDL", "SHRDQ",
		"ANDNL", "ANDNQ", "BLSIL", "BLSIQ", "BLSMSKL", "BLSMSKQ", "BLSRL", "BLSRQ",
		"BEXTRL", "BEXTRQ", "BZHIL", "BZHIQ",
		"BSFW", "BSFL", "BSFQ", "BSRW", "BSRL", "BSRQ",
		"TZCNTW", "TZCNTL", "TZCNTQ", "LZCNTW", "LZCNTL", "LZCNTQ",
		"POPCNTW", "POPCNTL", "POPCNTQ",
		"CMPSB", "CMPSW", "CMPSL", "CMPSQ", "SCASB", "SCASW", "SCASL", "SCASQ",
		"PCMPESTRI", "PCMPESTRM", "PCMPISTRI", "PCMPISTRM",
		"VPCMPESTRI", "VPCMPESTRM", "VPCMPISTRI", "VPCMPISTRM",
		"RDRAND", "RDRANDW", "RDRANDL", "RDRANDQ",
		"RDSEED", "RDSEEDW", "RDSEEDL", "RDSEEDQ",
		"KORTESTB", "KORTESTW", "KORTESTD", "KORTESTQ",
		"KTESTB", "KTESTW", "KTESTD", "KTESTQ",
		"COMISS", "COMISD", "UCOMISS", "UCOMISD", "PTEST",
		"VCOMISS", "VCOMISD", "VUCOMISS", "VUCOMISD", "VPTEST", "VTESTPS", "VTESTPD",
		"FCOMI", "FCOMIP", "FUCOMI", "FUCOMIP",
		"SAHF", "POPFL", "POPFQ", "POPFW", "CMC":
		return true
	}
	return false
}

func isX86FlagCondJumpOp(op asm.Op) bool {
	if !isX86CondJumpOp(op) {
		return false
	}
	switch op {
	case "JCXZ", "JECXZ", "JRCXZ", "LOOP", "LOOPEQ", "LOOPNE":
		return false
	default:
		return true
	}
}

// x86ShiftEffectiveImmCount computes the architectural masked shift/rotate
// count for an immediate or implicit-1 shift/rotate instruction. ok is false
// when the count is dynamic (e.g., in CL).
func x86ShiftEffectiveImmCount(op asm.Op, args []asm.Operand) (eff int64, ok bool) {
	if len(args) == 1 {
		// One-operand Plan 9 shift/rotate forms use an implicit count of 1.
		return 1, true
	}
	if len(args) < 2 || args[0].Kind != asm.OpImm {
		return 0, false
	}
	mask := int64(0x1f)
	if strings.HasSuffix(string(op), "Q") {
		mask = 0x3f
	}
	eff = args[0].Imm & mask
	switch op {
	case "RCLB", "RCRB":
		eff %= 9
	case "RCLW", "RCRW":
		eff %= 17
	}
	return eff, true
}

func updateX86FlagsAfter(st *abi0State, op asm.Op, args []asm.Operand, allInputsInit bool) {
	if isX86ClearCFOfOp(op) {
		// TEST/AND/OR/XOR unconditionally clear CF=0 and OF=0, and set ZF/SF/PF from result.
		st.cfInit = true
		st.ofInit = true
		st.zfInit = allInputsInit
		st.sfInit = allInputsInit
		st.pfInit = allInputsInit
		return
	}
	switch op {
	case "SYSCALL":
		// On Darwin/BSD amd64, SYSCALL returns error status in CF (tested via JCC).
		st.cfInit = true
		return
	case "ADCXL", "ADCXQ":
		// ADCX updates CF only; OF/ZF/SF/PF are preserved.
		st.cfInit = allInputsInit
		return
	case "ADOXL", "ADOXQ":
		// ADOX updates OF only; CF/ZF/SF/PF are preserved.
		st.ofInit = allInputsInit
		return
	case "INCB", "INCW", "INCL", "INCQ", "DECB", "DECW", "DECL", "DECQ":
		// INC/DEC preserve CF and update OF/ZF/SF/PF.
		st.ofInit = allInputsInit
		st.zfInit = allInputsInit
		st.sfInit = allInputsInit
		st.pfInit = allInputsInit
		return
	case "CMPXCHG8B", "CMPXCHG16B":
		// Intel SDM: CMPXCHG8B/16B modify ZF only.
		st.zfInit = allInputsInit
		return
	case "BTB", "BTW", "BTL", "BTQ",
		"BTSW", "BTSL", "BTSQ", "BTRW", "BTRL", "BTRQ", "BTCW", "BTCL", "BTCQ":
		// Intel SDM: BT/BTS/BTR/BTC set CF from bit, preserve ZF, and leave OF/SF/AF/PF undefined.
		st.cfInit = allInputsInit
		st.ofInit = false
		st.sfInit = false
		st.pfInit = false
		return
	case "SHLB", "SHLW", "SHLL", "SHLQ", "SALB", "SALW", "SALL", "SALQ",
		"SHRB", "SHRW", "SHRL", "SHRQ", "SARB", "SARW", "SARL", "SARQ",
		"SHLDW", "SHLDL", "SHLDQ", "SHRDW", "SHRDL", "SHRDQ":
		if eff, isImm := x86ShiftEffectiveImmCount(op, args); isImm {
			if eff == 0 {
				// Intel SDM: effective shift count 0 leaves all flags unaffected.
				return
			}
			isDouble16 := (op == "SHLDW" || op == "SHRDW") || ((op == "SHLW" || op == "SHRW") && len(args) == 3)
			if isDouble16 && eff > 16 {
				// Intel SDM: 16-bit SHLD/SHRD with effective count > 16 leaves result and flags undefined.
				st.cfInit = false
				st.ofInit = false
				st.zfInit = false
				st.sfInit = false
				st.pfInit = false
				return
			}
			st.cfInit = allInputsInit
			st.ofInit = allInputsInit && eff == 1
			st.zfInit = allInputsInit
			st.sfInit = allInputsInit
			st.pfInit = allInputsInit
			return
		}
		// Dynamic CL count may be 0 (preserving flags) or >1 (leaving OF undefined).
		st.cfInit = st.cfInit && allInputsInit
		st.ofInit = false
		st.zfInit = st.zfInit && allInputsInit
		st.sfInit = st.sfInit && allInputsInit
		st.pfInit = st.pfInit && allInputsInit
		return
	case "ROLB", "ROLW", "ROLL", "ROLQ", "RORB", "RORW", "RORL", "RORQ",
		"RCLB", "RCLW", "RCLL", "RCLQ", "RCRB", "RCRW", "RCRL", "RCRQ":
		if eff, isImm := x86ShiftEffectiveImmCount(op, args); isImm {
			if eff == 0 {
				// Intel SDM: effective rotate count 0 leaves all flags unaffected.
				return
			}
			// Rotates update CF (and OF only for effective count 1); ZF/SF/PF are preserved.
			st.cfInit = allInputsInit
			st.ofInit = allInputsInit && eff == 1
			return
		}
		st.cfInit = st.cfInit && allInputsInit
		st.ofInit = false
		return
	case "MULB", "MULW", "MULL", "MULQ", "IMULB", "IMULW", "IMULL", "IMULQ":
		st.cfInit = allInputsInit
		st.ofInit = allInputsInit
		st.zfInit = false
		st.sfInit = false
		st.pfInit = false
		return
	case "BSFW", "BSFL", "BSFQ", "BSRW", "BSRL", "BSRQ":
		st.cfInit = false
		st.ofInit = false
		st.zfInit = allInputsInit
		st.sfInit = false
		st.pfInit = false
		return
	case "TZCNTW", "TZCNTL", "TZCNTQ", "LZCNTW", "LZCNTL", "LZCNTQ":
		st.cfInit = allInputsInit
		st.ofInit = false
		st.zfInit = allInputsInit
		st.sfInit = false
		st.pfInit = false
		return
	case "POPCNTW", "POPCNTL", "POPCNTQ":
		// Intel SDM: POPCNT sets ZF from source==0 and clears OF/SF/AF/CF/PF to 0.
		st.cfInit = true
		st.ofInit = true
		st.zfInit = allInputsInit
		st.sfInit = true
		st.pfInit = true
		return
	case "ANDNL", "ANDNQ", "BLSIL", "BLSIQ", "BLSMSKL", "BLSMSKQ", "BLSRL", "BLSRQ", "BZHIL", "BZHIQ":
		st.cfInit = allInputsInit
		st.ofInit = true
		st.zfInit = allInputsInit
		st.sfInit = allInputsInit
		st.pfInit = false
		return
	case "BEXTRL", "BEXTRQ":
		st.cfInit = true
		st.ofInit = true
		st.zfInit = allInputsInit
		st.sfInit = false
		st.pfInit = false
		return
	case "RDRAND", "RDRANDW", "RDRANDL", "RDRANDQ",
		"RDSEED", "RDSEEDW", "RDSEEDL", "RDSEEDQ",
		"XTEST":
		st.cfInit = true
		st.ofInit = true
		st.zfInit = true
		st.sfInit = true
		st.pfInit = true
		return
	case "COMISS", "COMISD", "UCOMISS", "UCOMISD",
		"VCOMISS", "VCOMISD", "VUCOMISS", "VUCOMISD",
		"FCOMI", "FCOMIP", "FUCOMI", "FUCOMIP":
		// Intel SDM: sets ZF/PF/CF from comparison and clears OF/SF/AF to 0.
		st.cfInit = allInputsInit
		st.ofInit = true
		st.zfInit = allInputsInit
		st.sfInit = true
		st.pfInit = allInputsInit
		return
	case "PTEST", "VPTEST", "VTESTPS", "VTESTPD",
		"KORTESTB", "KORTESTW", "KORTESTD", "KORTESTQ",
		"KTESTB", "KTESTW", "KTESTD", "KTESTQ":
		// Intel SDM: sets ZF/CF and clears OF/SF/AF/PF to 0.
		st.cfInit = allInputsInit
		st.ofInit = true
		st.zfInit = allInputsInit
		st.sfInit = true
		st.pfInit = true
		return
	case "SAHF":
		// SAHF loads SF/ZF/AF/PF/CF from AH; OF is preserved.
		// If AX carries a LAHF/PUSHF tag, restore only the flags that were actually defined.
		if tag, ok := st.gpFlagTags[asm.AX]; ok {
			st.cfInit = allInputsInit && (tag&abi0FlagCF) != 0
			st.zfInit = allInputsInit && (tag&abi0FlagZF) != 0
			st.sfInit = allInputsInit && (tag&abi0FlagSF) != 0
			st.pfInit = allInputsInit && (tag&abi0FlagPF) != 0
			return
		}
		st.cfInit = allInputsInit
		st.zfInit = allInputsInit
		st.sfInit = allInputsInit
		st.pfInit = allInputsInit
		return
	}
	if isX86GPFlagWriter(op) {
		st.cfInit = allInputsInit
		st.ofInit = allInputsInit
		st.zfInit = allInputsInit
		st.sfInit = allInputsInit
		st.pfInit = allInputsInit
	}
}

func x86CondSuffix(op asm.Op) (string, bool) {
	s := string(op)
	if strings.HasPrefix(s, "SET") && len(s) > 3 {
		return s[3:], true
	}
	for _, pfx := range []string{"CMOVW", "CMOVL", "CMOVQ"} {
		if strings.HasPrefix(s, pfx) && len(s) > len(pfx) {
			return s[len(pfx):], true
		}
	}
	if strings.HasPrefix(s, "J") && len(s) > 1 &&
		op != "JMP" && op != "JCXZ" && op != "JECXZ" && op != "JRCXZ" && isX86CondJumpOp(op) {
		return s[1:], true
	}
	return "", false
}

// x86CondRequiredFlags returns the exact set of architectural status flags
// consumed by a condition-code suffix (shared across Jcc, SETcc, and CMOVcc).
func x86CondRequiredFlags(cc string) (needCF, needOF, needZF, needSF, needPF bool) {
	switch cc {
	case "E", "EQ", "Z", "NE", "NZ":
		return false, false, true, false, false
	case "S", "NS", "MI", "PL":
		return false, false, false, true, false
	case "P", "PE", "NP", "PO", "PS", "PC":
		return false, false, false, false, true
	case "C", "NC", "CS", "CC", "B", "NB", "AE", "NAE", "LO", "HS":
		return true, false, false, false, false
	case "O", "NO", "OS", "OC":
		return false, true, false, false, false
	case "BE", "NA", "A", "NBE", "LS", "HI":
		return true, false, true, false, false
	case "L", "LT", "GE", "NGE", "NL":
		return false, true, false, true, false
	case "LE", "G", "GT", "NG", "NLE":
		return false, true, true, true, false
	default:
		return false, false, false, false, false
	}
}

// missingCondFlag checks whether any status flag required by a conditional
// instruction (Jcc, SETcc, or CMOVcc) is uninitialized in st.
func missingCondFlag(st *abi0State, op asm.Op) string {
	cc, ok := x86CondSuffix(op)
	if !ok {
		return ""
	}
	needCF, needOF, needZF, needSF, needPF := x86CondRequiredFlags(cc)
	if needCF && !st.cfInit {
		return "CF"
	}
	if needOF && !st.ofInit {
		return "OF"
	}
	if needZF && !st.zfInit {
		return "ZF"
	}
	if needSF && !st.sfInit {
		return "SF"
	}
	if needPF && !st.pfInit {
		return "PF"
	}
	return ""
}

func needsNonCondCF(op asm.Op, args []asm.Operand) bool {
	switch op {
	case "ADCB", "ADCW", "ADCL", "ADCQ",
		"SBBB", "SBBW", "SBBL", "SBBQ",
		"ADCXL", "ADCXQ":
		return true
	case "RCLB", "RCLW", "RCLL", "RCLQ",
		"RCRB", "RCRW", "RCRL", "RCRQ":
		if eff, isImm := x86ShiftEffectiveImmCount(op, args); isImm && eff == 0 {
			return false
		}
		return true
	}
	return false
}
