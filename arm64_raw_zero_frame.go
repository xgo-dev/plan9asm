package plan9asm

import (
	"reflect"
	"strconv"
	"strings"
)

// Raw leaf/C bodies can own an explicit stack allocation without a Go
// prologue. This is a separate whole-source proof: it does not invent a Go
// frame, turn arbitrary native calls into helpers, or weaken caller LR checks.
// Every local raw BL is interpreted in its bounded call context; every root
// return restores the entry SP, LR and BP. Incoming pointers cannot alias the
// fresh LLVM stack object unless an address escapes this checked source.
type arm64RawZeroState struct {
	addresses *arm64RawPrivateFrameState
	control   *arm64ControlState
}

// Go 1.27 abi-internal.md's ARM64 special-purpose table also applies to ABI0:
// R18 is OS-reserved; R28 carries g; R29 is BP. Their return meaning is Same,
// unlike ordinary scratch or the closure-context register R26. Raw WORD can
// touch registers excluded by Go's textual parser, so track their full entry
// identity independently of void-result transport and may-frame addresses.
var arm64RawZeroFixedEntry = [...]struct {
	reg   Reg
	token string
}{
	{reg: "R18", token: "entry-os18:"},
	{reg: "R28", token: "entry-g:"},
	{reg: "R29", token: "entry-bp:"},
}

func (s *arm64RawZeroState) clone() *arm64RawZeroState {
	return &arm64RawZeroState{addresses: s.addresses.clone(), control: s.control.clone()}
}

func (s *arm64RawZeroState) merge(other *arm64RawZeroState) (bool, bool) {
	if s.addresses.sp != other.addresses.sp {
		return false, false
	}
	changed := s.addresses.regs.merge(other.addresses.regs)
	spills := make(map[int64]arm64PrivateFrameAddress)
	for offset, value := range s.addresses.spills {
		if incoming, present := other.addresses.spills[offset]; !present || incoming != value {
			value = arm64PrivateFrameAddress{}
		}
		spills[offset] = value
	}
	for offset := range other.addresses.spills {
		if _, present := spills[offset]; !present {
			spills[offset] = arm64PrivateFrameAddress{}
		}
	}
	if !reflect.DeepEqual(spills, s.addresses.spills) {
		s.addresses.spills, changed = spills, true
	}
	return s.control.merge(other.control) || changed, true
}

type arm64RawZeroCall struct {
	block int
	sp    int64
}

type arm64RawZeroPoint struct {
	block   int
	context string
}

func arm64RawZeroFrameUnexposed(fn Func) bool {
	return arm64RawZeroFrameUnexposedForTransport(fn, nil)
}

// Only a complete ordinary ABI0 void declaration establishes that temporary
// virtual GP values are dead at the root return. This is not permission to
// expose them before returning, or to consume an unknown native register ABI.
func arm64RawZeroVoidTransport(fn Func, transport *arm64PrivateFrameTransport) bool {
	if transport == nil || fn.arm64PrivateRegisterEntry || strings.HasSuffix(fn.Sym, "<ABIInternal>") {
		return false
	}
	sig := transport.entry
	if sig.Ret != Void || len(sig.Frame.Results) != 0 || len(sig.ArgRegs) != 0 ||
		sig.ARM64GoRegisterABI != nil || sig.ARM64ClosureABI != nil || sig.ARMEntry != nil ||
		sig.WASMContext != "" || sig.WASMNative || len(sig.Frame.Params) != len(sig.Args) ||
		fn.ArgSize != int64(len(sig.Args))*8 {
		return false
	}
	for index, typ := range sig.Args {
		slot := sig.Frame.Params[index]
		if (typ != Ptr && typ != I64) || slot.Type != typ || slot.Offset != int64(index)*8 ||
			slot.Index != index || slot.Field != -1 || len(slot.Fields) != 0 {
			return false
		}
	}
	for _, ins := range fn.Instrs {
		if ins.Op != OpTEXT {
			continue
		}
		_, rest := splitOpcode(ins.Raw)
		parts := strings.Split(rest, ",")
		if len(parts) == 3 {
			expression := globlFlagName.ReplaceAllStringFunc(parts[1], func(name string) string {
				if value, ok := goTextFlagValues[name]; ok {
					return value
				}
				return name
			})
			flags, known := parseImmExpr(expression)
			if !known || flags&64 != 0 { // NEEDCTXT is hidden transport.
				return false
			}
		}
	}
	return true
}

func arm64RawZeroFrameUnexposedForTransport(fn Func, transport *arm64PrivateFrameTransport) bool {
	return arm64RawZeroFrameProof(fn, transport, nil)
}

func arm64RawZeroFrameProof(fn Func, transport *arm64PrivateFrameTransport, control *arm64LocalControlPlan) bool {
	if fn.FrameSize != 0 || arm64SourceGoFrame(fn).present || !arm64SourceFrameFlagsKnown(fn) ||
		(!arm64HasRawFrameCode(fn) && !arm64SourceUsesR20(fn)) {
		return false
	}
	text := 0
	for _, ins := range fn.Instrs {
		if ins.Op == OpTEXT {
			text++
		}
	}
	if text != 1 {
		return false
	}
	voidTransport := arm64RawZeroVoidTransport(fn, transport)
	// The exact raw PC boundary checker supplies only same-source labels.
	// Run it on the original too: later normalization cannot erase an escape.
	normalized, blobs, err := prepareARM64RawPCRelative(fn)
	if err != nil || len(blobs) != 0 {
		return false
	}
	if control != nil && !reflect.DeepEqual(fn.Instrs, normalized.Instrs) {
		return false // A plan cannot describe an earlier or differently normalized CFG.
	}
	blocks := arm64SplitBlocks(normalized)
	indices := make(map[string]int, len(blocks))
	for index, block := range blocks {
		indices[block.name] = index
	}
	entryLabel := "__entry_lr"
	for {
		if _, exists := indices[entryLabel]; !exists {
			break
		}
		entryLabel += "_"
	}
	entryLink := "label:" + entryLabel
	before := make(map[arm64RawZeroPoint]*arm64RawZeroState)
	contexts := map[string][]arm64RawZeroCall{"": nil}
	visited := make([]bool, len(blocks))
	queue := make([]arm64RawZeroPoint, 0, len(blocks))
	queued := make(map[arm64RawZeroPoint]bool)
	propagate := func(point arm64RawZeroPoint, state *arm64RawZeroState) bool {
		if point.block < 0 || point.block >= len(blocks) || len(before) >= 16384 {
			return false
		}
		changed := false
		if old := before[point]; old == nil {
			before[point], changed = state.clone(), true
		} else {
			var valid bool
			changed, valid = old.merge(state)
			if !valid {
				return false
			}
		}
		if changed && !queued[point] {
			queue, queued[point] = append(queue, point), true
		}
		return true
	}
	operations := 0
	for seed := range blocks {
		if visited[seed] {
			continue
		}
		entry := &arm64RawZeroState{
			addresses: &arm64RawPrivateFrameState{
				regs:   arm64PrivateFrameAddresses{"R18": {}, "R28": {}, "R29": {}},
				spills: make(map[int64]arm64PrivateFrameAddress),
			},
			control: &arm64ControlState{
				regs: map[Reg]arm64ControlValue{
					SP:    arm64ControlFromMap(map[string]bool{"sp:0": true}),
					"R30": arm64ControlFromMap(map[string]bool{entryLink: true}),
				},
				memory: make(map[string]arm64ControlValue), unexposedSP: true,
			},
		}
		if arm64SourceUsesR20(fn) {
			entry.addresses.regs["R20"] = arm64PrivateFrameAddress{}
		}
		for _, fixed := range arm64RawZeroFixedEntry {
			entry.control.regs[fixed.reg] = arm64ControlFromMap(map[string]bool{fixed.token: true})
		}
		if !propagate(arm64RawZeroPoint{block: seed}, entry) {
			return false
		}
		for next := 0; next < len(queue); next++ {
			point := queue[next]
			queued[point] = false
			visited[point.block] = true
			if control != nil && seed == 0 {
				control.reachable[point.block] = true
			}
			state := before[point].clone()
			calls := contexts[point.context]
			terminated := false
			for instructionIndex, original := range blocks[point.block].instrs {
				operations++
				if operations > 1<<24 {
					return false
				}
				ins := arm64ControlDecode(original)
				op := arm64ControlOp(ins)
				if arm64RawZeroReturn(original) {
					link := arm64ControlRead(state.control.regs, "R30")
					if len(calls) == 0 {
						if state.addresses.sp != 0 || arm64ControlCount(link) != 1 || !arm64ControlHas(link, entryLink) {
							return false
						}
						for _, fixed := range arm64RawZeroFixedEntry {
							value := arm64ControlRead(state.control.regs, fixed.reg)
							if arm64ControlCount(value) != 1 || !arm64ControlHas(value, fixed.token) {
								return false
							}
							delete(state.addresses.regs, fixed.reg)
						}
						if len(state.addresses.regs) != 0 && !voidTransport {
							return false
						}
					} else {
						caller := calls[len(calls)-1]
						label := "label:" + blocks[caller.block].name
						if state.addresses.sp != caller.sp || arm64ControlCount(link) != 1 || !arm64ControlHas(link, label) {
							return false
						}
						parent := point.context[:strings.LastIndex(point.context, "/")]
						if !propagate(arm64RawZeroPoint{block: caller.block, context: parent}, state) {
							return false
						}
					}
					if control != nil && seed == 0 {
						control.recordRawZeroReturn(point.block, instructionIndex, state.control, entryLink)
					}
					terminated = true
					break
				}
				if op == "BL" || op == "CALL" || op == "BLR" {
					if !original.arm64RawLocalCall || len(ins.Args) != 1 || len(calls) >= 16 || point.block+1 >= len(blocks) {
						return false
					}
					name, local := arm64BranchTarget(ins.Args[0])
					target, exists := indices[name]
					if !local || !exists || !arm64IsLocalBranchLink(ins) {
						return false
					}
					if target == point.block && arm64RawZeroSelfBLSink(blocks[point.block]) {
						// Exact same-PC raw BL writes LR and branches to itself
						// forever. There is no return edge or continuation proof.
						// Every prefix effect/join was checked before reaching it.
						if point.block+2 == len(blocks) && len(blocks[point.block+1].instrs) == 0 &&
							len(normalized.Instrs) != 0 && normalized.Instrs[len(normalized.Instrs)-1].arm64RawLocalCall {
							// SplitBlocks creates an empty PC+4 continuation when
							// the final source instruction is a call. This sink
							// cannot reach it, and it contains no source to check.
							visited[point.block+1] = true
						}
						terminated = true
						break
					}
					context := point.context + "/" + strconv.Itoa(point.block+1)
					contexts[context] = append(append([]arm64RawZeroCall(nil), calls...), arm64RawZeroCall{block: point.block + 1, sp: state.addresses.sp})
					state.control.regs["R30"] = arm64ControlFromMap(map[string]bool{"label:" + blocks[point.block+1].name: true})
					if !propagate(arm64RawZeroPoint{block: target, context: context}, state) {
						return false
					}
					terminated = true
					break
				}
				if op == "B" || op == "JMP" || arm64IsConditionalBranch(op) {
					if len(ins.Args) == 0 {
						return false
					}
					name, local := arm64BranchTarget(ins.Args[len(ins.Args)-1])
					target, exists := indices[name]
					if !local || !exists || !propagate(arm64RawZeroPoint{block: target, context: point.context}, state) {
						return false
					}
					if arm64IsConditionalBranch(op) && !propagate(arm64RawZeroPoint{block: point.block + 1, context: point.context}, state) {
						return false
					}
					terminated = true
					break
				}
				if op == "ADR" || op == "ADRP" || op == OpRET || op == arm64RawDataOp || !state.transfer(original, ins) {
					return false
				}
			}
			if !terminated && !propagate(arm64RawZeroPoint{block: point.block + 1, context: point.context}, state) {
				return false
			}
		}
		queue = queue[:0]
	}
	return true
}

// Only the decoder's exact raw-PC boundary witness may identify this sink.
// A block containing any additional effect remains an ordinary bounded call.
func arm64RawZeroSelfBLSink(block arm64Block) bool {
	if len(block.instrs) != 1 {
		return false
	}
	ins := block.instrs[0]
	return (ins.Op == "BL" || ins.Op == "CALL") && ins.arm64RawLocalCall && len(ins.Args) == 1 &&
		ins.Args[0].Kind == OpIdent && ins.Args[0].Ident == block.name
}

func arm64RawZeroReturn(original Instr) bool {
	if original.Op == OpWORD {
		decoded, err := decodeARM64RawWordInstruction(original)
		return err == nil && arm64RawPrivateSourceRET(decoded)
	}
	return arm64RawPrivateSourceRET(original)
}

func (s *arm64RawZeroState) transfer(original, ins Instr) bool {
	if ins.Op == "NOP" && len(ins.Args) == 0 && (original.Op != OpWORD ||
		len(original.Args) == 1 && original.Args[0].Kind == OpImm && original.Args[0].ImmRaw == "" && original.Args[0].Imm == 0xd503201f) {
		return true // Exact architectural NOP, not the wider system/hint class.
	}
	if form, handled, err := parseARM64StructureMemory(original); handled {
		if err != nil {
			return false
		}
		if address, private := s.addresses.address(form.memory.Mem.Base); private {
			if !address.exact || address.offset < s.addresses.sp || address.offset > -form.width() {
				return false // No implicit Go cell exists in a zero-source frame.
			}
		}
	}
	if form, known := arm64RawPrivateMemory(ins); known && form.memory.Kind == OpMem {
		mem := form.memory.Mem
		if address, private := s.addresses.address(mem.Base); private {
			offset := mem.Off
			if form.post {
				offset = 0
			}
			address, valid := arm64PrivateFrameOffset(address, offset)
			low := s.addresses.sp
			if form.pre && arm64StackReg(mem.Base) {
				low = address.offset
			}
			width := form.elementBytes * int64(len(form.registers))
			if !valid || !address.exact || mem.Index != "" || mem.OffRaw != "" || address.offset < low || address.offset > -width {
				return false // No implicit Go cell or unallocated red zone exists.
			}
		}
	}
	if !s.addresses.transfer(original, ins, -8) {
		return false
	}
	if !s.control.transferStructureMemory(original) {
		s.control.transfer(ins, arm64ControlOp(ins), strings.HasSuffix(string(ins.Op), ".P"), nil)
	}
	return true
}
