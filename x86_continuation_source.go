package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"sync/atomic"
)

// This is the explicit X86TailGroups contract, not the independent source-only
// direct-tail producer. Its addresses denote blocks in one actual fused root;
// neither the helpers' declarations nor a table cell supplies numerical bytes.
type x86ContinuationGraph struct {
	self                       *x86ContinuationGraph
	origin, original, prepared *File
	arch, triple               string
	groups                     []X86TailGroup
	signatures                 map[string]FuncSig
	symbols                    map[string]string
	dataSymbols                map[string]string // Complete SB-use mapping, including aliases without GLOBL.
	flows                      map[string]*x86ContinuationFlow
	tables                     map[string]x86ContinuationTable
	addresses                  map[string]x86Continuation
	cells                      int
	plan                       [32]byte
	revoked                    atomic.Bool
}

type x86ContinuationTable struct {
	root, initializer string
	bytes             int64
	first, cells      int
}

type x86ContinuationFlow struct {
	graph        *x86ContinuationGraph
	symbol, root string
	instructions []Instr
	ordinals     []int
	edges        [][]int
	indirect     map[int]bool
}

func x86ContinuationContext(reason string) error {
	return fmt.Errorf("%w: x86 continuation: %s", ErrProbeNeedsContext, reason)
}

func x86ContinuationSnapshot(file *File) *File {
	copy := arm64ScratchFileSnapshot(file)
	copy.x86ContinuationGraph = nil
	copy.x86Continuations = make(map[string]x86Continuation, len(file.x86Continuations))
	for symbol, address := range file.x86Continuations {
		copy.x86Continuations[symbol] = address
	}
	for i := range copy.Funcs {
		fn := &copy.Funcs[i]
		fn.x86ContinuationFlow = nil
		fn.x86ResultFlowBudget = nil
		fn.x86IndirectLabels = append([]string(nil), fn.x86IndirectLabels...)
		fn.x86ContinuationAddresses = make(map[string]x86Continuation, len(file.Funcs[i].x86ContinuationAddresses))
		for symbol, address := range file.Funcs[i].x86ContinuationAddresses {
			fn.x86ContinuationAddresses[symbol] = address
		}
	}
	return copy
}

func sealX86Continuations(original, prepared *File, opt Options) (*File, error) {
	// Unlike numerical portable IR, an actual block address stored in a native
	// word needs its source mode and the physical target's pointer width bound.
	// In particular wasm must never receive blockaddress through an x86 route.
	profile := map[string]string{
		"x86_64-apple-darwin": "amd64", "x86_64-unknown-linux-gnu": "amd64", "x86_64-pc-windows-msvc": "amd64",
		"i386-unknown-linux-gnu": "386", "i686-pc-windows-msvc": "386",
	}
	if profile[opt.TargetTriple] != opt.Goarch || opt.Goarch == "" {
		return nil, x86ContinuationContext("code/table addresses require a matching explicit x86 pointer-width target")
	}
	if opt.NumericalReads != nil || opt.X86TLSMoves != nil || opt.ARM64ByteCarrierSource != nil ||
		len(original.UnlinkedPrelude) != 0 || original.x86DirectTails != nil {
		return nil, x86ContinuationContext("source/native roles need their independent complete-node association")
	}
	graph := &x86ContinuationGraph{origin: original, original: x86ContinuationSnapshot(original),
		arch: opt.Goarch, triple: opt.TargetTriple, flows: make(map[string]*x86ContinuationFlow),
		symbols: make(map[string]string), dataSymbols: make(map[string]string), tables: make(map[string]x86ContinuationTable),
		addresses: make(map[string]x86Continuation)}
	graph.self = graph
	var err error
	graph.signatures, err = numericalCloneSignatures(opt.Sigs)
	if err != nil {
		return nil, err
	}
	for _, group := range opt.X86TailGroups {
		graph.groups = append(graph.groups, X86TailGroup{Root: group.Root, Helpers: append([]string(nil), group.Helpers...)})
	}
	for symbol, address := range prepared.x86Continuations {
		graph.addresses[symbol] = address
	}
	resolve := opt.ResolveSym
	if resolve == nil {
		resolve = func(s string) string { return s }
	}
	owners := make(map[string]string)
	for _, group := range graph.groups {
		owners[group.Root] = group.Root
		for _, helper := range group.Helpers {
			owners[helper] = group.Root
		}
	}
	resolved := make(map[string]bool)
	for _, fn := range graph.original.Funcs {
		name := resolve(fn.Sym)
		if name == "" || resolved[name] {
			return nil, x86ContinuationContext("ambiguous original TEXT symbol mapping")
		}
		resolved[name], graph.symbols[fn.Sym] = true, name
	}
	for _, global := range graph.original.Globl {
		name := resolveAssemblyDataSymbol(global.Sym, resolve)
		if name == "" || resolved[name] {
			return nil, x86ContinuationContext("GLOBL/TEXT resolved identity is ambiguous")
		}
		resolved[name], graph.symbols[global.Sym] = true, name
	}
	observe := func(operand Operand) {
		if operand.Kind == OpSym {
			operand.Sym = strings.TrimLeft(operand.Sym, "*$")
		}
		memory, valid := x86SBMemoryAddressRole(operand, graph.arch)
		if !valid {
			return
		}
		name, _, valid := parseSBRef(memory.Sym)
		if valid {
			graph.dataSymbols[name] = resolveAssemblyDataSymbol(name, resolve)
		}
	}
	for _, fn := range graph.original.Funcs {
		for _, ins := range fn.Instrs {
			if ins.Op == OpTEXT {
				continue
			}
			for _, operand := range ins.Args {
				observe(operand)
			}
		}
	}
	for _, data := range graph.original.Data {
		observe(Operand{Kind: OpSym, Sym: data.Addr})
	}
	if err := graph.collectTables(owners); err != nil {
		return nil, err
	}
	combined := 0
	for i := range prepared.Funcs {
		fn := &prepared.Funcs[i]
		root := owners[fn.Sym]
		participant := root != ""
		for _, table := range graph.tables {
			participant = participant || table.initializer == fn.Sym
		}
		if !participant {
			continue
		}
		sig, declared := graph.signatures[graph.symbols[fn.Sym]]
		if !declared || sig.Ret == I1 {
			return nil, x86ContinuationContext("root lacks its independent ordinary scalar result role")
		}
		for _, slot := range sig.Frame.Results {
			if slot.Type == I1 {
				return nil, x86ContinuationContext("bool results need their independent canonical whole-graph role")
			}
		}
		if fn.FrameSize != 0 || fn.X86RawText != nil || fn.x86SourceStack != nil || fn.x86FixedLocal != nil ||
			fn.x86RawReplay != nil || fn.x86DirectTailRoot != nil || fn.x86BoolCalls != nil {
			return nil, x86ContinuationContext("native/frame/call role is not a logical continuation")
		}
		for _, ins := range fn.Instrs {
			if isX86RawDirective(ins) || ins.x86Encoded || ins.x86SourceRaw != nil || ins.x86RawNearReturn != nil ||
				ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride || ins.x86SegmentPrefix != 0 ||
				len(ins.x86SourceStackFP) != 0 || len(ins.x86CallerMemory) != 0 || len(ins.x86FixedLocalMemory) != 0 ||
				ins.x86NumericalRead != nil || ins.x86SDKLiteral != nil || ins.Op == OpCALL {
				return nil, x86ContinuationContext("unbound raw/native/call instruction")
			}
			for _, arg := range ins.Args {
				if arg.Kind == OpReg && x86LogicalSourceFrameRegister(arg.Reg, graph.arch) || arg.Kind == OpFPAddr ||
					arg.Kind == OpMem && (x86LogicalSourceFrameRegister(arg.Mem.Base, graph.arch) ||
						x86LogicalSourceFrameRegister(arg.Mem.Index, graph.arch) || arg.Mem.Base == PC) {
					return nil, x86ContinuationContext("physical frame or PC role is not closed")
				}
			}
		}
		view, err := graph.flow(*fn, root)
		if err != nil {
			return nil, err
		}
		combined += len(view.instructions)
		if combined > 4096 {
			return nil, x86ContinuationContext("combined source instruction budget exhausted")
		}
		graph.flows[fn.Sym], fn.x86ContinuationFlow = view, view
	}
	prepared.x86ContinuationGraph = graph
	graph.prepared = x86ContinuationSnapshot(prepared)
	if err := graph.auditReferences(); err != nil {
		return nil, err
	}
	graph.plan, err = graph.planHash()
	if err != nil {
		return nil, err
	}
	if err := graph.verify(prepared, opt); err != nil {
		return nil, err
	}
	return prepared, nil
}

// Tables are complete private GLOBL objects. Initializer execution order is
// still the explicit caller's closed-target contract, never inferred from a
// func() declaration. Every actual initializer RET must separately write all
// cells with this group's opaque code addresses.
func (graph *x86ContinuationGraph) collectTables(owners map[string]string) error {
	word := x86ResultPointerWord(graph.arch)
	lea, move := Op("LEAQ"), Op("MOVQ")
	if graph.arch == "386" {
		lea, move = "LEAL", "MOVL"
	}
	for _, fn := range graph.original.Funcs {
		if owners[fn.Sym] == "" {
			continue
		}
		for _, ins := range fn.Instrs {
			if ins.Op != lea || len(ins.Args) != 2 {
				continue
			}
			address, ok := x86StaticSBReadAddress(ins.Args[0], graph.arch)
			if !ok || graph.addresses[address.symbol].root != "" {
				continue
			}
			if !strings.HasSuffix(address.symbol, "<>") || address.offset != 0 {
				return x86ContinuationContext("table address is not an exact private object")
			}
			if old, exists := graph.tables[address.symbol]; exists && old.root != owners[fn.Sym] {
				return x86ContinuationContext("table belongs to another root")
			}
			graph.tables[address.symbol] = x86ContinuationTable{root: owners[fn.Sym]}
		}
	}
	for symbol, table := range graph.tables {
		matches := 0
		for _, global := range graph.original.Globl {
			if global.Sym == symbol {
				matches++
				flags := globlFlagName.ReplaceAllStringFunc(global.Flags, func(name string) string {
					if name == "NOPTR" {
						return "16"
					}
					return name
				})
				value, valid := uint64(0), true
				if strings.TrimSpace(flags) != "" {
					value, valid = parseImmExpr(flags)
				}
				if !valid || value&^16 != 0 {
					return x86ContinuationContext("table must be mutable unique ordinary storage, with only optional NOPTR")
				}
				if global.SizeRaw != "" || global.Size <= 0 || global.Size > 4096 || global.Size%word != 0 {
					return x86ContinuationContext("table extent is not complete bounded words")
				}
				table.bytes = global.Size
			}
		}
		if matches != 1 {
			return x86ContinuationContext("table has missing or duplicate storage")
		}
		for _, data := range graph.original.Data {
			if data.Sym == symbol {
				return x86ContinuationContext("table DATA requires its separate relocation contract")
			}
		}
		for _, fn := range graph.original.Funcs {
			if fn.Sym == symbol {
				return x86ContinuationContext("table aliases a TEXT")
			}
			for _, ins := range fn.Instrs {
				if len(ins.Args) != 2 {
					continue
				}
				address, ok := x86StaticSBReadAddress(ins.Args[1], graph.arch)
				if !ok || address.symbol != symbol {
					continue
				}
				if x86SourceMoveInstruction(ins, graph.arch).Op != move || address.offset < 0 || address.offset%word != 0 || address.offset > table.bytes-word || owners[fn.Sym] != "" ||
					table.initializer != "" && table.initializer != fn.Sym {
					return x86ContinuationContext("table write is not one exact closed initializer")
				}
				table.initializer = fn.Sym
			}
		}
		if table.initializer == "" {
			return x86ContinuationContext("table has no actual initializer source")
		}
		sig, found := graph.signatures[graph.symbols[table.initializer]]
		if !found || sig.Ret != Void || len(sig.Args) != 0 || len(sig.ArgRegs) != 0 || len(sig.Frame.Params)+len(sig.Frame.Results) != 0 {
			return x86ContinuationContext("table initializer is not an ordinary zero-argument void root")
		}
		table.first, table.cells = graph.cells, int(table.bytes/word)
		graph.cells += table.cells
		if graph.cells > 4096 {
			return x86ContinuationContext("combined table cell budget exhausted")
		}
		graph.tables[symbol] = table
	}
	return nil
}

func (graph *x86ContinuationGraph) auditReferences() error {
	for name, resolved := range graph.dataSymbols {
		for table := range graph.tables {
			if name != table && resolved == graph.symbols[table] {
				return x86ContinuationContext("SB alias has no exact closed-table source identity")
			}
		}
		for helper := range graph.addresses {
			if resolved == graph.symbols[helper] && name != helper || name == helper && resolved != graph.symbols[helper] {
				return x86ContinuationContext("SB alias has no exact coalesced code identity")
			}
		}
	}
	for _, data := range graph.original.Data {
		name, _, valid := parseSBRef(strings.TrimPrefix(data.Addr, "$"))
		if _, table := graph.tables[name]; valid && table {
			return x86ContinuationContext("table address escapes through DATA")
		}
	}
	for _, fn := range graph.original.Funcs {
		for _, ins := range fn.Instrs {
			if ins.Op == OpTEXT {
				continue
			}
			for _, operand := range ins.Args {
				memory, valid := x86SBMemoryAddressRole(operand, graph.arch)
				if !valid && operand.Kind == OpSym {
					memory, valid = x86SBMemoryAddressRole(Operand{Kind: OpSym, Sym: strings.TrimPrefix(operand.Sym, "$")}, graph.arch)
				}
				if !valid {
					continue
				}
				name, _, valid := parseSBRef(memory.Sym)
				_, table := graph.tables[name]
				_, code := graph.addresses[name]
				if !valid || !table && !code {
					continue
				}
				participant := graph.flows[fn.Sym] != nil || graph.addresses[fn.Sym].root != ""
				if !participant {
					return x86ContinuationContext("code/table reference is outside the complete closed participants")
				}
			}
		}
	}
	return nil
}

// Hash the entire derived plan, not only exported Instr JSON. Private graph
// copies or changed ordinals/edges/table extents cannot borrow an old source
// token. This is a private projection, not another source/ABI capability.
func (graph *x86ContinuationGraph) planHash() ([32]byte, error) {
	prepared := make(map[string]Func, len(graph.prepared.Funcs))
	for _, fn := range graph.prepared.Funcs {
		prepared[fn.Sym] = fn
	}
	tables := make(map[string]any, len(graph.tables))
	for name, table := range graph.tables {
		tables[name] = []any{table.root, table.initializer, table.bytes, table.first, table.cells}
	}
	addresses := make(map[string]any, len(graph.addresses))
	for name, address := range graph.addresses {
		addresses[name] = []string{address.root, address.label}
	}
	flows := make(map[string]any, len(graph.flows))
	for name, view := range graph.flows {
		if view == nil || view.graph != graph {
			return [32]byte{}, x86ContinuationContext("derived flow has another graph owner")
		}
		fn, present := prepared[name]
		if !present || len(view.instructions) != len(view.ordinals) {
			return [32]byte{}, x86ContinuationContext("derived flow has no complete source ordinals")
		}
		for pc, ins := range view.instructions {
			ordinal := view.ordinals[pc]
			if ordinal < 0 || ordinal >= len(fn.Instrs) || !reflect.DeepEqual(ins, fn.Instrs[ordinal]) {
				return [32]byte{}, x86ContinuationContext("derived instruction lost its exact original normalized tuple")
			}
		}
		flows[name] = []any{view.symbol, view.root, view.instructions, view.ordinals, view.edges, view.indirect}
	}
	return x86CallerSourceFingerprint([]any{tables, addresses, flows, graph.cells, graph.dataSymbols})
}

func (graph *x86ContinuationGraph) flow(fn Func, root string) (*x86ContinuationFlow, error) {
	view := &x86ContinuationFlow{graph: graph, symbol: fn.Sym, root: root, indirect: make(map[int]bool)}
	labels := make(map[string]int)
	for ordinal, ins := range fn.Instrs {
		if ins.Op == OpTEXT {
			continue
		}
		if ins.Op == OpLABEL {
			if len(ins.Args) != 1 || ins.Args[0].Kind != OpLabel {
				return nil, x86ContinuationContext("malformed coalesced label")
			}
			if _, duplicate := labels[ins.Args[0].Sym]; duplicate {
				return nil, x86ContinuationContext("duplicate coalesced label")
			}
			labels[ins.Args[0].Sym] = len(view.instructions)
			continue
		}
		view.instructions, view.ordinals = append(view.instructions, ins), append(view.ordinals, ordinal)
	}
	var targets []int
	for _, label := range fn.x86IndirectLabels {
		target, ok := labels[label]
		if !ok || target >= len(view.instructions) {
			return nil, x86ContinuationContext("indirect label is not a complete root block")
		}
		targets = append(targets, target)
	}
	view.edges = make([][]int, len(view.instructions))
	for pc, ins := range view.instructions {
		if ins.Op == OpRET {
			if len(ins.Args) != 0 {
				return nil, x86ContinuationContext("nonordinary RET")
			}
			continue
		}
		next := []int{pc + 1}
		if ins.Op == OpJMP || isAMD64ConditionalBranch(ins.Op) {
			args := x86DirectTailBranchArgs(ins)
			if len(args) != 1 {
				return nil, x86ContinuationContext("unbound branch operands")
			}
			arg := args[0]
			label := arg.Sym
			if arg.Kind == OpIdent {
				label = arg.Ident
			} else if arg.Kind == OpReg {
				label = string(arg.Reg)
			}
			target, local := labels[label]
			if !local {
				if ins.Op != OpJMP || len(targets) == 0 || root == "" || arg.Kind != OpReg && arg.Kind != OpMem {
					return nil, x86ContinuationContext("external or unresolved continuation branch")
				}
				view.indirect[view.ordinals[pc]] = true
				next = append([]int(nil), targets...)
			} else if ins.Op == OpJMP {
				next = []int{target}
			} else {
				next = append(next, target)
			}
		}
		for _, target := range next {
			if target < 0 || target >= len(view.instructions) {
				return nil, x86ContinuationContext("source falls outside the coalesced root")
			}
		}
		view.edges[pc] = next
	}
	return view, nil
}

func (graph *x86ContinuationGraph) verify(file *File, opt Options) (err error) {
	defer func() {
		if err != nil && graph != nil {
			graph.revoked.Store(true)
		}
	}()
	if graph == nil || graph.self != graph || graph.revoked.Load() || file == nil ||
		graph.arch != opt.Goarch || graph.triple != opt.TargetTriple ||
		opt.NumericalReads != nil || opt.X86TLSMoves != nil || opt.ARM64ByteCarrierSource != nil ||
		!reflect.DeepEqual(graph.groups, opt.X86TailGroups) || !reflect.DeepEqual(graph.signatures, opt.Sigs) ||
		!reflect.DeepEqual(graph.original, x86ContinuationSnapshot(graph.origin)) ||
		!reflect.DeepEqual(graph.prepared, x86ContinuationSnapshot(file)) {
		return x86ContinuationContext("complete source, graph, mode or declarations changed")
	}
	plan, planErr := graph.planHash()
	if planErr != nil || plan != graph.plan {
		return x86ContinuationContext("derived graph/table/source-ordinal plan changed")
	}
	resolve := opt.ResolveSym
	if resolve == nil {
		resolve = func(s string) string { return s }
	}
	for symbol, expected := range graph.symbols {
		actual := resolve(symbol)
		for _, global := range graph.original.Globl {
			if global.Sym == symbol {
				actual = resolveAssemblyDataSymbol(symbol, resolve)
				break
			}
		}
		if actual != expected {
			return x86ContinuationContext("complete symbol mapping changed")
		}
	}
	for symbol, expected := range graph.dataSymbols {
		if resolveAssemblyDataSymbol(symbol, resolve) != expected {
			return x86ContinuationContext("complete SB-use symbol mapping changed")
		}
	}
	plan, planErr = graph.planHash()
	if planErr != nil || plan != graph.plan || !reflect.DeepEqual(graph.groups, opt.X86TailGroups) ||
		!reflect.DeepEqual(graph.original, x86ContinuationSnapshot(graph.origin)) || !reflect.DeepEqual(graph.prepared, x86ContinuationSnapshot(file)) ||
		!reflect.DeepEqual(graph.signatures, opt.Sigs) || graph.revoked.Load() {
		return x86ContinuationContext("resolver changed source or declarations")
	}
	return nil
}
