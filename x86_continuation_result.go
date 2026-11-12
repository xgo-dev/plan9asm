package plan9asm

import (
	"reflect"
	"strings"
)

type x86ContinuationAddress struct {
	kind         uint8 // 1: exact table object, 2: opaque code in one root.
	symbol, root string
}

type x86ContinuationResultState struct {
	flow        *x86ContinuationFlow // Immutable, independently authenticated source.
	gp          [16]x86ContinuationAddress
	written     []bool // Initializer cells only; never numerical bytes.
	tablesValid bool   // A possible native alias store revokes future table loads.
	invalid     bool   // A mismatched CFG state revokes, never panics or invents facts.
}

func (view *x86ContinuationFlow) bind(fn Func, sig FuncSig, arch string) (accepted bool) {
	graph := view.graph
	defer func() {
		if !accepted && graph != nil {
			graph.revoked.Store(true)
		}
	}()
	if graph == nil || graph.self != graph || graph.revoked.Load() || graph.arch != arch || graph.flows[fn.Sym] != view ||
		fn.Sym != view.symbol || !reflect.DeepEqual(graph.original, x86ContinuationSnapshot(graph.origin)) {
		return false
	}
	plan, err := graph.planHash()
	if err != nil || plan != graph.plan {
		return false
	}
	expected, found := graph.signatures[graph.symbols[fn.Sym]]
	if expected.Name == "" {
		expected.Name = graph.symbols[fn.Sym]
	}
	if sig.Name == "" {
		sig.Name = graph.symbols[fn.Sym]
	}
	if !found || !reflect.DeepEqual(sig, expected) {
		return false
	}
	plain := fn
	plain.x86ContinuationFlow, plain.x86ResultFlowBudget = nil, nil
	copy := x86ContinuationSnapshot(&File{Arch: ArchAMD64, Funcs: []Func{plain}}).Funcs[0]
	for _, original := range graph.prepared.Funcs {
		if original.Sym == fn.Sym && reflect.DeepEqual(original, copy) {
			return true
		}
	}
	return false
}

func (c *amd64Ctx) checkContinuationResultSource() error {
	view := c.fpScalarSource.x86ContinuationFlow
	if view == nil || view.graph == nil || view.graph.triple != c.targetTriple || !view.bind(c.fpScalarSource, c.fpSourceSig, c.goarch) {
		return x86ContinuationContext("lowering lost its complete coalesced source or actual root declaration")
	}
	emitted := c.sig
	if c.fpSourceSig.Attrs == "" && emitted.Attrs == c.fpFeatureAttrs {
		emitted.Attrs = "" // Only the renderer's exact independent inference handoff.
	}
	if !reflect.DeepEqual(emitted, c.fpSourceSig) {
		return x86ContinuationContext("emitted declaration differs from its actual root")
	}
	return nil
}

func (state *x86ContinuationResultState) checkReturn() bool {
	if state.invalid {
		return false
	}
	for _, table := range state.flow.graph.tables {
		if table.initializer != state.flow.symbol {
			continue
		}
		for index := table.first; index < table.first+table.cells; index++ {
			if index >= len(state.written) || !state.written[index] {
				return false
			}
		}
	}
	return true
}

// Opaque code and table addresses have only these complete full-word effects.
// A table load relies on the already explicit closed-target contract; it does
// not assert that an initializer has run or that any code bytes are readable.
func x86ContinuationResultStep(ordinal int, ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	role := state.continuation
	if role == nil {
		return false, false
	}
	if role.invalid {
		return false, true
	}
	graph := role.flow.graph
	word := x86ResultPointerWord(arch)
	move, lea := Op("MOVQ"), Op("LEAQ")
	if arch == "386" {
		move, lea = "MOVL", "LEAL"
	}
	form := x86SourceMoveInstruction(ins, arch)
	register := func(arg Operand) (int, bool) {
		index, _, ok := x86ResultGP(arg.Reg, word, arch)
		return index, ok && arg.Kind == OpReg
	}
	address := func(arg Operand) x86ContinuationAddress {
		if index, ok := register(arg); ok {
			return role.gp[index]
		}
		return x86ContinuationAddress{}
	}
	write := func(arg Operand, value x86ContinuationAddress) bool {
		index, ok := register(arg)
		if !ok {
			return false
		}
		role.gp[index] = value
		state.gp[index], state.canonicalGP[index] = 0, 0
		state.pointerGP[index], state.callerAddressGP[index] = false, false
		state.callerAddressOrigin[index], state.resultAddressGP[index] = 0, x86ResultSlotAddress{}
		return true
	}
	tableMemory := func(arg Operand) (x86ContinuationTable, int64, bool) {
		if !role.tablesValid && !state.shapeOnly {
			return x86ContinuationTable{}, 0, false
		}
		if location, ok := x86StaticSBReadAddress(arg, arch); ok {
			table, exists := graph.tables[location.symbol]
			return table, location.offset, exists && location.offset >= 0 && location.offset%word == 0 && location.offset <= table.bytes-word
		}
		if arg.Kind != OpMem || !x86ResultSlotMemory(arg.Mem) {
			return x86ContinuationTable{}, 0, false
		}
		base := address(Operand{Kind: OpReg, Reg: arg.Mem.Base})
		if base.kind == 1 {
			table := graph.tables[base.symbol]
			return table, arg.Mem.Off, arg.Mem.Off >= 0 && arg.Mem.Off%word == 0 && arg.Mem.Off <= table.bytes-word
		}
		if state.shapeOnly {
			// The source-wide pass checks shape, never a reaching table fact.
			for _, table := range graph.tables {
				if table.root == role.flow.root && arg.Mem.Off >= 0 && arg.Mem.Off%word == 0 && arg.Mem.Off <= table.bytes-word {
					return table, arg.Mem.Off, true
				}
			}
		}
		return x86ContinuationTable{}, 0, false
	}
	if role.flow.indirect[ordinal] {
		if form.Op != OpJMP || len(form.Args) != 1 {
			return false, true
		}
		if value := address(form.Args[0]); value.kind == 2 && value.root == role.flow.root {
			return true, true
		}
		if table, _, ok := tableMemory(form.Args[0]); ok && table.root == role.flow.root {
			return true, true
		}
		return state.shapeOnly && form.Args[0].Kind == OpReg, true
	}
	if len(form.Args) == 2 {
		first, last := form.Args[0], form.Args[1]
		if form.Op == lea || form.Op == move && first.Kind == OpSym && strings.HasPrefix(first.Sym, "$") {
			operand := first
			if operand.Kind == OpSym {
				operand.Sym = strings.TrimPrefix(operand.Sym, "$")
			}
			if location, ok := x86StaticSBReadAddress(operand, arch); ok {
				if target, found := graph.addresses[location.symbol]; found {
					shape := form
					shape.Op, shape.Args = lea, []Operand{operand, last}
					width, err := x86LEAOperandWidth(shape, arch)
					return location.offset == 0 && err == nil && width == word && write(last, x86ContinuationAddress{kind: 2, symbol: location.symbol, root: target.root}), true
				}
				if table, found := graph.tables[location.symbol]; found {
					shape := form
					shape.Op, shape.Args = lea, []Operand{operand, last}
					width, err := x86LEAOperandWidth(shape, arch)
					return location.offset == 0 && err == nil && width == word && write(last, x86ContinuationAddress{kind: 1, symbol: location.symbol, root: table.root}), true
				}
			}
		}
		if form.Op == move {
			if state.shapeOnly {
				if location, ok := x86StaticSBReadAddress(last, arch); ok {
					table, found := graph.tables[location.symbol]
					_, gp := register(first)
					return found && gp && table.initializer == role.flow.symbol && location.offset >= 0 && location.offset%word == 0 && location.offset <= table.bytes-word, true
				}
			}
			if value := address(first); value.kind != 0 {
				if _, ok := register(last); ok {
					return write(last, value), true
				}
				if location, ok := x86StaticSBReadAddress(last, arch); ok {
					table, found := graph.tables[location.symbol]
					if !found || value.kind != 2 || table.root != value.root || table.initializer != role.flow.symbol ||
						location.offset < 0 || location.offset%word != 0 || location.offset > table.bytes-word {
						return false, true
					}
					role.written[table.first+int(location.offset/word)] = true
					return true, true
				}
				return false, true // No code/table address may escape to data or FP.
			}
			if table, _, ok := tableMemory(first); ok {
				if table.root != role.flow.root {
					return false, true
				}
				return write(last, x86ContinuationAddress{kind: 2, root: table.root}), true
			}
		}
		// Only this paired ordinary scalar store consumes an actual declared
		// incoming address. It grants no extent, native backing or FP write.
		width := x86RawReturnScalarMoveBytes(form.Op)
		if width > 0 && !(width == 8 && arch == "386") && last.Kind == OpMem &&
			last.Mem.Sym == "" && x86OrdinaryNativeMemoryOperand(last, arch) &&
			x86ResultIncomingPointerAddressIdentity(last, state, arch) &&
			(first.Kind == OpReg || first.Kind == OpImm) && x86ResultRead(first, width, state, owned, arch) {
			role.tablesValid = false // The old Ptr contract is not a noalias promise.
			return true, true
		}
	}
	return false, false
}

// An unregistered use cannot turn opaque addresses into initialized values.
// Complete overwrite is allowed, but every partial/implicit write revokes the
// entire old identity through the shared typed GP footprint.
func x86ContinuationOrdinaryUses(ins Instr, state *x86ResultState, arch string) bool {
	role := state.continuation
	if role == nil {
		return true
	}
	for index, operand := range ins.Args {
		memory, static := x86SBMemoryAddressRole(operand, arch)
		if static {
			name, _, valid := parseSBRef(memory.Sym)
			_, table := role.flow.graph.tables[name]
			_, code := role.flow.graph.addresses[name]
			if valid && (table || code) {
				return false // Only the explicit full-word opaque effect may consume it.
			}
		}
		if operand.Kind == OpReg {
			root, _, ok := x86ResultGP(operand.Reg, 1, arch)
			if !ok {
				root, _, ok = x86ResultGP(operand.Reg, x86ResultPointerWord(arch), arch)
			}
			if ok && role.gp[root].kind != 0 && !x86ResultSlotOverwrite(ins, index, arch) {
				return false
			}
		}
		if operand.Kind == OpMem {
			for _, reg := range []Reg{operand.Mem.Base, operand.Mem.Index} {
				root, _, ok := x86ResultGP(reg, x86ResultPointerWord(arch), arch)
				if ok && role.gp[root].kind != 0 {
					return false
				}
			}
		}
	}
	return true
}

func x86ContinuationRevokeOverwrites(ins Instr, state *x86ResultState, arch string) {
	if state.continuation == nil {
		return
	}
	var before [16]bool
	for index, value := range state.continuation.gp {
		before[index] = value.kind != 0
	}
	after := x86ResultCallerAddressesAfter(ins, before, nil, arch)
	for index := range before {
		if !after[index] {
			state.continuation.gp[index] = x86ContinuationAddress{}
		}
	}
}
