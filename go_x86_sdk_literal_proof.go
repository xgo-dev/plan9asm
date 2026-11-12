package plan9asm

import (
	"math"
	"reflect"
	"sort"
	"strings"
)

type x86SDKLiteralAccess struct {
	Function    string
	Instruction int
	Operand     int
	Original    Instr
	Symbol      string
	Minimum     int64
	Maximum     int64
	Width       int64
	Address     bool
	LowBits     *x86SDKLiteralLowBits
}

type x86SDKLiteralValue struct {
	width                    int64
	minimum                  uint64
	maximum                  uint64
	symbol                   string // A literal identity is never numerical register data.
	bad                      bool   // A partial write retains may-literal taint, not authority.
	lowMask, lowValue        uint64 // Only the guaranteed minimum's address bits.
	hasMinimum               bool
	bitsOnly, lowIndependent bool // Neither state is a dereferenceable origin.
}

type x86SDKLiteralState struct {
	gp          [16]x86SDKLiteralValue
	comparison  int
	constant    uint64
	compared    bool
	opaqueFlags uint8 // May depend on uncovered address bits, not merely undefined.
}

// This is a path-sensitive, literal-only proof. It neither runs a caller proof
// nor invents an invariant for a cycle. A literal loop closes only when its
// complete typed state repeats at the same active label. Other literal cycles
// remain Context; cycles unrelated to literals belong to the result proof.
func proveX86SDKLiteralAccesses(fn Func, sig FuncSig, arch string, literals map[string]int64) ([]x86SDKLiteralAccess, error) {
	return proveX86SDKLiteralAccessesAtMinimum(fn, sig, arch, literals, nil)
}

func proveX86SDKLiteralAccessesAtMinimum(fn Func, sig FuncSig, arch string, literals map[string]int64, minima map[string]uint32) ([]x86SDKLiteralAccess, error) {
	return proveX86SDKLiteralAccessesAtMinimumRequest(fn, sig, arch, literals, minima, false)
}

func proveX86SDKLiteralAccessesAtMinimumRequest(fn Func, sig FuncSig, arch string, literals map[string]int64, minima map[string]uint32, requestOnly bool) ([]x86SDKLiteralAccess, error) {
	fail := func(reason string) ([]x86SDKLiteralAccess, error) {
		return nil, numericalSBContext("private literal source proof: %s", reason)
	}
	n := len(fn.Instrs)
	if n == 0 || n > 4096 || arch != "amd64" && arch != "386" || len(fn.X86RawText) != 0 || fn.x86SourceStack != nil || fn.x86FixedLocal != nil {
		return fail("requires complete bounded ordinary source")
	}
	labels := make(map[string]int)
	for ordinal, ins := range fn.Instrs {
		if ins.Op == OpLABEL {
			if len(ins.Args) != 1 || ins.Args[0].Kind != OpLabel {
				return fail("malformed source label")
			}
			if _, present := labels[ins.Args[0].Sym]; present {
				return fail("duplicate source label")
			}
			labels[ins.Args[0].Sym] = ordinal
		}
	}
	edges := make([][]int, n)
	named := make([]bool, n)
	for ordinal, ins := range fn.Instrs {
		if isX86RawDirective(ins) || ins.x86Encoded || ins.x86SourceRaw != nil || ins.x86RawNearReturn != nil || ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride {
			return fail("raw/native/address-size source needs its separate contract")
		}
		for index := range ins.Args {
			if form, valid := x86SDKLiteralOperandProperties(ins, index, arch); valid && literals[form.symbol] > 0 {
				named[ordinal] = true
			}
		}
		if ins.Op == OpRET {
			if len(ins.Args) != 0 {
				return fail("nonordinary source return")
			}
			continue
		}
		edges[ordinal] = []int{ordinal + 1}
		if ins.Op == OpJMP || isAMD64ConditionalBranch(ins.Op) {
			if len(ins.Args) != 1 {
				return fail("unbound source branch")
			}
			arg := ins.Args[0]
			label := arg.Sym
			if arg.Kind == OpIdent {
				label = arg.Ident
			}
			target, found := labels[label]
			if !found || arg.Kind != OpLabel && arg.Kind != OpIdent {
				return fail("external or indirect source branch")
			}
			if ins.Op == OpJMP {
				edges[ordinal] = []int{target}
			} else {
				edges[ordinal] = append(edges[ordinal], target)
			}
		}
		for _, successor := range edges[ordinal] {
			if successor < 0 || successor >= n {
				return fail("source continuation leaves complete function")
			}
		}
	}
	// Backwards reachability is scope, never an index or cycle invariant.
	future := append([]bool(nil), named...)
	for changed := true; changed; {
		changed = false
		for pc := n - 1; pc >= 0; pc-- {
			for _, target := range edges[pc] {
				if !future[pc] && future[target] {
					future[pc], changed = true, true
				}
			}
		}
	}
	word := x86ResultPointerWord(arch)
	initial := x86SDKLiteralState{}
	if strings.HasSuffix(fn.Sym, "<ABIInternal>") {
		if arch != "amd64" || len(sig.ArgRegs) != 0 || len(sig.Args) > 9 {
			return fail("requires the independent ordinary scalar register contract")
		}
		for index, reg := range []Reg{AX, BX, CX, DI, SI, "R8", "R9", "R10", "R11"} {
			if index >= len(sig.Args) {
				break
			}
			width := x86ResultScalarBytes(sig.Args[index], arch)
			root, _, valid := x86ResultGP(reg, width, arch)
			if valid {
				initial.gp[root] = x86SDKLiteralUnknownNumber(width)
			}
		}
	}
	facts := make(map[int]x86SDKLiteralAccess)
	nonliteral := make(map[int]bool)
	path := make([]bool, n)
	entries := make(map[int]x86SDKLiteralState, len(labels))
	visits := 0
	var walk func(int, x86SDKLiteralState) error
	walk = func(pc int, state x86SDKLiteralState) error {
		visits++
		if visits > 16384 {
			return numericalSBContext("private literal source path budget exhausted")
		}
		if path[pc] {
			if entry, present := entries[pc]; present {
				if entry == state {
					return nil
				}
				for _, value := range entry.gp {
					if value.symbol != "" {
						return numericalSBContext("private literal cyclic carrier changed its entry state")
					}
				}
			}
			for _, value := range state.gp {
				if value.symbol != "" {
					return numericalSBContext("private literal cyclic carrier needs its separate loop contract")
				}
			}
			if future[pc] {
				return numericalSBContext("private literal cyclic access needs its separate loop contract")
			}
			return nil
		}
		path[pc] = true
		defer func() { path[pc] = false }()
		ins := fn.Instrs[pc]
		if ins.Op == OpLABEL {
			// One snapshot per active label, charged to the same path budget.
			// No historical branch state or weakened range can close a cycle.
			entries[pc] = state
			defer delete(entries, pc)
		}
		if minima != nil && state.opaqueFlags&x86SDKLiteralFlagReads(ins, arch) != 0 {
			return numericalSBContext("private literal FLAG reader observes uncovered linked address bits: %s", ins.Raw)
		}
		if ins.Op == OpRET {
			if arch == "amd64" && strings.HasSuffix(fn.Sym, "<ABIInternal>") && sig.Ret != Void && state.gp[0].symbol != "" &&
				!(minima != nil && sig.Ret == I1 && state.gp[0].lowIndependent) {
				return numericalSBContext("private literal pointer escapes through the logical result")
			}
			return nil
		}
		if ins.Op == OpTEXT || ins.Op == OpLABEL || ins.Op == OpJMP || isAMD64ConditionalBranch(ins.Op) {
			for edge, target := range edges[pc] {
				next := state
				if isAMD64ConditionalBranch(ins.Op) && !x86SDKLiteralRefineEdge(ins.Op, edge == 1, &next) {
					continue
				}
				if err := walk(target, next); err != nil {
					return err
				}
			}
			return nil
		}
		for index, operand := range ins.Args {
			form, private := x86SDKLiteralOperandProperties(ins, index, arch)
			if private && literals[form.symbol] == 0 {
				private = false
			}
			if !private && operand.Kind == OpMem && operand.Mem.Sym == "" {
				root, _, valid := x86ResultGP(operand.Mem.Base, word, arch)
				if valid && state.gp[root].symbol != "" {
					value := state.gp[root]
					if value.bad || value.minimum != value.maximum || value.maximum > math.MaxInt64 ||
						operand.Mem.OffRaw != "" || operand.Mem.Segment != "" || operand.Mem.IndexExt != "" {
						return numericalSBContext("private literal derived address lost its exact origin")
					}
					width, write, valid := x86InstructionMemoryShape(x86SourceMoveInstruction(ins, arch), index, arch)
					if !valid || write || width <= 0 {
						return numericalSBContext("private literal derived access has an unbound read-only shape")
					}
					form = x86SDKLiteralOperand{memory: operand.Mem, symbol: value.symbol,
						offset: int64(value.maximum) + operand.Mem.Off, width: width}
					private = true
				}
			}
			if operand.Kind == OpMem && operand.Mem.Index != "" {
				root, _, valid := x86ResultGP(operand.Mem.Index, word, arch)
				if valid && state.gp[root].symbol != "" {
					return numericalSBContext("private literal address is not a numerical index")
				}
			}
			if !private {
				if width, write, known := x86InstructionMemoryShape(x86SourceMoveInstruction(ins, arch), index, arch); known && !write && width > 0 {
					nonliteral[pc] = true
				}
				continue
			}
			minimum, maximum := form.offset, form.offset
			if form.memory.Index != "" {
				root, _, valid := x86ResultGP(form.memory.Index, word, arch)
				value := state.gp[root]
				if !valid || value.symbol != "" || value.width < word || form.memory.Scale != 1 && form.memory.Scale != 2 && form.memory.Scale != 4 && form.memory.Scale != 8 ||
					value.maximum > math.MaxInt64/uint64(form.memory.Scale) || form.offset < 0 ||
					int64(value.maximum*uint64(form.memory.Scale)) > math.MaxInt64-form.offset {
					return numericalSBContext("private literal index lacks a closed numerical envelope at %q: %s %+v", ins.Raw, form.memory.Index, value)
				}
				minimum += int64(value.minimum * uint64(form.memory.Scale))
				maximum += int64(value.maximum * uint64(form.memory.Scale))
			}
			if minimum < 0 || maximum < minimum || maximum > literals[form.symbol]-form.width {
				return numericalSBContext("private literal complete access exceeds its observed byte extent")
			}
			fact := x86SDKLiteralAccess{Function: sig.Name, Instruction: pc, Operand: index, Original: ins,
				Symbol: form.symbol, Minimum: minimum, Maximum: maximum, Width: form.width, Address: form.address}
			if previous, present := facts[pc]; present {
				if previous.Symbol != fact.Symbol || previous.Operand != fact.Operand || previous.Address != fact.Address || previous.Width != fact.Width || !reflect.DeepEqual(previous.Original, ins) {
					return numericalSBContext("private literal has mixed source origins")
				}
				fact.Minimum, fact.Maximum = minSDKLiteral(previous.Minimum, fact.Minimum), maxSDKLiteral(previous.Maximum, fact.Maximum)
			}
			facts[pc] = fact
			if form.address {
				if minimum != maximum {
					return numericalSBContext("indexed literal materialization needs an affine address contract")
				}
				root, _, _ := x86ResultGP(ins.Args[1].Reg, word, arch)
				state.gp[root] = x86SDKLiteralValue{symbol: form.symbol, minimum: uint64(minimum), maximum: uint64(maximum)}
				if floor := minima[form.symbol]; floor != 0 {
					state.gp[root].hasMinimum = true
					state.gp[root].lowMask = uint64(floor - 1)
					state.gp[root].lowValue = uint64(minimum) & uint64(floor-1)
				}
				if state.comparison == root {
					state.compared = false
				}
				for _, target := range edges[pc] {
					if err := walk(target, state); err != nil {
						return err
					}
				}
				return nil
			}
		}
		if requestOnly {
			known, err := x86SDKLiteralAlignmentRequestStep(ins, &state, arch)
			if err != nil {
				return err
			}
			if known {
				for _, target := range edges[pc] {
					if err := walk(target, state); err != nil {
						return err
					}
				}
				return nil
			}
		}
		if minima != nil {
			lowBits, known, err := x86SDKLiteralLowBitStep(ins, &state, fn, sig, arch)
			if err != nil {
				return err
			}
			if known {
				if lowBits != nil {
					fact := x86SDKLiteralAccess{Function: sig.Name, Instruction: pc, Operand: 1, Original: ins,
						Symbol: lowBits.Symbol, Width: lowBits.Bytes, LowBits: lowBits}
					if previous, found := facts[pc]; found && !reflect.DeepEqual(previous, fact) {
						return numericalSBContext("private literal low-bit operation has mixed path guarantees")
					}
					facts[pc] = fact
				}
				for _, target := range edges[pc] {
					if err := walk(target, state); err != nil {
						return err
					}
				}
				return nil
			}
		}
		var literalRead *x86SDKLiteralAccess
		if fact, found := facts[pc]; found && !fact.Address {
			literalRead = &fact
		}
		if err := x86SDKLiteralTransfer(ins, &state, sig, arch, literalRead); err != nil {
			return err
		}
		if minima != nil {
			x86SDKLiteralIndependentFlagWrites(ins, &state, arch)
		}
		for _, target := range edges[pc] {
			if err := walk(target, state); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(0, initial); err != nil {
		return nil, err
	}
	ordinals := make([]int, 0, len(facts))
	for ordinal := range facts {
		if !facts[ordinal].Address && facts[ordinal].LowBits == nil && nonliteral[ordinal] {
			return fail("private literal read has an incoming/mixed origin on another feasible path")
		}
		ordinals = append(ordinals, ordinal)
	}
	sort.Ints(ordinals)
	result := make([]x86SDKLiteralAccess, 0, len(facts))
	for _, ordinal := range ordinals {
		result = append(result, facts[ordinal])
	}
	return result, nil
}

func minSDKLiteral(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
func maxSDKLiteral(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func x86SDKLiteralUnknownNumber(width int64) x86SDKLiteralValue {
	maximum := ^uint64(0)
	if width > 0 && width < 8 {
		maximum = uint64(1)<<(uint(width)*8) - 1
	}
	return x86SDKLiteralValue{width: width, maximum: maximum}
}

func x86SDKLiteralRefineEdge(op Op, taken bool, state *x86SDKLiteralState) bool {
	if !state.compared {
		return true
	}
	value := &state.gp[state.comparison]
	next, feasible := (x86UnsignedRange{value.minimum, value.maximum}).refine(op, taken, state.constant)
	value.minimum, value.maximum = next.minimum, next.maximum
	return feasible
}

func x86SDKLiteralTransfer(ins Instr, state *x86SDKLiteralState, sig FuncSig, arch string, literalRead *x86SDKLiteralAccess) error {
	ins = x86SourceMoveInstruction(ins, arch) // Facts retain the complete original instruction.
	word := x86ResultPointerWord(arch)
	op := string(ins.Op)
	width := int64(0)
	if strings.HasSuffix(op, "Q") {
		width = 8
	} else if strings.HasSuffix(op, "L") {
		width = 4
	}
	read := func(operand Operand, width int64) x86SDKLiteralValue {
		if literalRead != nil && width > 0 && width <= literalRead.Width && reflect.DeepEqual(operand, ins.Args[literalRead.Operand]) {
			return x86SDKLiteralUnknownNumber(width)
		}
		switch operand.Kind {
		case OpImm:
			if operand.ImmRaw == "" && !operand.ImmIsFloat {
				value := uint64(operand.Imm)
				if width == 4 {
					value = uint64(uint32(value))
				}
				return x86SDKLiteralValue{width: width, minimum: value, maximum: value}
			}
		case OpReg:
			if root, _, valid := x86ResultGP(operand.Reg, width, arch); valid {
				value := state.gp[root]
				if value.symbol == "" && value.width >= width {
					limit := x86SDKLiteralUnknownNumber(width).maximum
					if value.maximum > limit {
						return x86SDKLiteralUnknownNumber(width)
					}
					value.width = width
				}
				return value
			}
		case OpFP:
			for _, slot := range sig.Frame.Params {
				if slot.Offset == operand.FPOffset && x86ResultScalarBytes(slot.Type, arch) >= width {
					return x86SDKLiteralUnknownNumber(width)
				}
			}
		}
		return x86SDKLiteralValue{}
	}
	if (ins.Op == "LEAL" || ins.Op == "LEAQ") && len(ins.Args) == 2 && ins.Args[1].Kind == OpReg {
		// The complete Go LEA row overwrites only its destination and does
		// not read memory or change flags. An unrelated FP/native address is
		// still unknown here: no frame/address/backing permission is created.
		root, _, valid := x86ResultGP(ins.Args[1].Reg, width, arch)
		if valid {
			state.gp[root] = x86SDKLiteralValue{}
			if state.comparison == root {
				state.compared = false
			}
			return nil
		}
	}
	if (ins.Op == "CMPQ" || ins.Op == "CMPL") && len(ins.Args) == 2 && ins.Args[0].Kind == OpReg && ins.Args[1].Kind == OpImm {
		form, known, err := x86ScalarCompareProperties(ins.Op, ins, arch)
		if !known || err != nil {
			return numericalSBContext("private literal comparison has no complete original Go row")
		}
		root, _, valid := x86ResultGP(ins.Args[0].Reg, width, arch)
		value, constant := read(form.args[0], width), read(form.args[1], width)
		if value.symbol != "" {
			return numericalSBContext("private literal linked address-bit observation requires independent native alignment or physical identity")
		}
		state.compared = valid && value.symbol == "" && value.width >= width && constant.width == width &&
			(width == word || state.gp[root].maximum <= x86SDKLiteralUnknownNumber(width).maximum)
		state.comparison, state.constant = root, constant.minimum
		return nil
	}
	if len(ins.Args) == 2 && width > 0 && (strings.HasPrefix(op, "MOV") || strings.HasPrefix(op, "ADD") || strings.HasPrefix(op, "SUB") || strings.HasPrefix(op, "AND")) && ins.Args[1].Kind == OpReg {
		root, _, valid := x86ResultGP(ins.Args[1].Reg, width, arch)
		if valid {
			if !strings.HasPrefix(op, "MOV") {
				form, known, err := x86LockScalarRMWProperties(ins.Op, ins, arch)
				if !known || err != nil || form.spec.unary || form.source.Kind != ins.Args[0].Kind {
					return numericalSBContext("private literal numerical transform has no complete Go row")
				}
				ins.Args = append([]Operand(nil), ins.Args...)
				ins.Args[0] = form.source // Exact truncated/sign-extended original immediate.
			}
			first, previous := read(ins.Args[0], width), read(ins.Args[1], width)
			if strings.HasPrefix(op, "MOV") {
				if first.symbol != "" {
					if width != word || ins.Args[0].Kind != OpReg {
						return numericalSBContext("private literal partial pointer copy is not numerical data")
					}
					state.gp[root] = first
					if state.comparison == root {
						state.compared = false
					}
					return nil
				}
				if first.width < width {
					first = x86SDKLiteralValue{}
				}
				if width == 4 && arch == "amd64" && first.width != 0 {
					first.width = 8
				}
				state.gp[root] = first
				if state.comparison == root {
					state.compared = false
				}
				return nil
			}
			state.compared = false
			if first.symbol != "" || previous.symbol != "" {
				if strings.HasPrefix(op, "AND") {
					return numericalSBContext("private literal linked address-bit observation requires independent native alignment or physical identity")
				}
				return numericalSBContext("private literal address transform needs a separate affine contract")
			}
			result := x86SDKLiteralValue{}
			if first.width >= width && previous.width >= width {
				result = x86SDKLiteralUnknownNumber(width)
				if strings.HasPrefix(op, "ADD") && first.maximum <= result.maximum-previous.maximum {
					result.minimum, result.maximum = first.minimum+previous.minimum, first.maximum+previous.maximum
				} else if strings.HasPrefix(op, "SUB") && previous.minimum >= first.maximum {
					result.minimum, result.maximum = previous.minimum-first.maximum, previous.maximum-first.minimum
				} else if strings.HasPrefix(op, "AND") && ins.Args[0].Kind == OpImm {
					result.maximum = first.maximum
				}
				if width == 4 && arch == "amd64" {
					result.width = 8
				}
			}
			state.gp[root] = result
			return nil
		}
	}
	if form, known, err := x86ScalarCompareProperties(ins.Op, ins, arch); known {
		if err != nil {
			return numericalSBContext("private literal comparison has an invalid complete operand form")
		}
		for _, operand := range form.args {
			if operand.Kind == OpReg {
				root, _, valid := x86ResultGP(operand.Reg, int64(form.bits/8), arch)
				if valid && state.gp[root].symbol != "" {
					return numericalSBContext("private literal linked address-bit observation requires independent native alignment or physical identity")
				}
			}
		}
		state.compared = false
		return nil // Compare/test writes FLAGS, never a GP value.
	}
	if form, known, err := x86GPSIMDTransferProperties(ins, arch); known {
		if err != nil || form.mmx {
			return numericalSBContext("private literal GP/vector transfer needs its actual typed bank")
		}
		if ins.Args[0].Kind == OpReg && !form.sourceX {
			root, _, valid := x86ResultGP(ins.Args[0].Reg, int64(form.bits/8), arch)
			if valid && state.gp[root].symbol != "" {
				return numericalSBContext("private literal address escapes through a vector transfer")
			}
		}
		if ins.Args[1].Kind == OpReg && !form.destinationX {
			root, _, valid := x86ResultGP(ins.Args[1].Reg, int64(form.bits/8), arch)
			if valid {
				state.gp[root] = x86SDKLiteralValue{} // No vector numerical range is imported.
				if state.comparison == root {
					state.compared = false
				}
			}
		}
		return nil
	}
	if form, known, err := x86ScalarLaneProperties(ins, arch); known {
		if err != nil {
			return numericalSBContext("private literal scalar lane transfer has an invalid typed form")
		}
		operand := ins.Args[form.source]
		if !form.insert {
			operand = ins.Args[form.destination]
		}
		if operand.Kind == OpReg {
			root, _, valid := x86ResultGP(form.transferReg, int64(form.gpBits/8), arch)
			if valid && form.insert && state.gp[root].symbol != "" {
				return numericalSBContext("private literal address escapes through a scalar lane")
			}
			if valid && !form.insert {
				state.gp[root] = x86SDKLiteralValue{}
				if state.comparison == root {
					state.compared = false
				}
			}
		}
		return nil
	}
	if x86SDKLiteralVectorOnlyEffect(ins, arch) {
		return nil // Shared complete forms prove there are no GP/FLAGS outputs.
	}
	store := ins
	if len(ins.Args) == 2 && ins.Args[1].Kind == OpFP {
		// Project only the logical destination to check the existing machine
		// row. This observes register effects, never FP or native ownership.
		store.Args = []Operand{ins.Args[0], {Kind: OpMem, Mem: MemRef{Base: AX}}}
	}
	if form, known, err := x86ScalarRegisterStoreProperties(store.Op, store, arch); known {
		if err != nil {
			return numericalSBContext("private literal scalar store has an invalid typed form")
		}
		if form.source.Kind == OpReg {
			root, _, valid := x86ResultGP(form.source.Reg, form.bytes, arch)
			if valid && state.gp[root].symbol != "" {
				return numericalSBContext("private literal address escapes through a scalar store")
			}
		}
		return nil // No GP/FLAGS output; every memory role is proved separately.
	}
	effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
	if !known || err != nil {
		for _, value := range state.gp {
			if value.symbol != "" {
				return numericalSBContext("private literal live address reaches unknown effect: %s", ins.Raw)
			}
		}
		state.gp, state.compared = [16]x86SDKLiteralValue{}, false
		return nil // No literal permission follows; final source/result proof remains strict.
	}
	if effect.flagsKilled != 0 || effect.flagsDefined != 0 {
		state.compared = false
	}
	for _, operand := range effect.operands {
		if operand.operand.Kind != OpReg {
			continue
		}
		root, _, valid := x86ResultGP(operand.operand.Reg, operand.width, arch)
		if !valid {
			continue
		}
		value := state.gp[root]
		if operand.read && value.symbol != "" {
			if form, known, err := x86LockScalarRMWProperties(ins.Op, ins, arch); known && err == nil &&
				(form.spec.stem == "OR" || form.spec.stem == "XOR") {
				return numericalSBContext("private literal linked address-bit observation requires independent native alignment or physical identity")
			}
			return numericalSBContext("private literal address escapes as numerical/FP/vector data: %s", ins.Raw)
		}
		if operand.write {
			if operand.width < word && value.symbol != "" {
				value.bad = true
				state.gp[root] = value
			} else {
				state.gp[root] = x86SDKLiteralValue{}
			}
			if state.comparison == root {
				state.compared = false
			}
		}
	}
	return nil
}

func x86SDKLiteralVectorOnlyEffect(ins Instr, arch string) bool {
	valid := false
	if _, known, err := x86PackedLogicalProperties(ins, arch); known {
		valid = err == nil
	} else if _, known, err := x86AESProperties(ins.Op, ins, arch); known {
		valid = err == nil
	} else if _, known, err := x86ImmediateShuffleProperties(ins, arch); known {
		valid = err == nil
	} else if _, known, err := x86ByteShuffleProperties(ins.Op, ins, arch); known {
		valid = err == nil
	} else if _, known, err := x86LegacyPackedMoveProperties(ins.Op, ins, arch); known {
		valid = err == nil
	} else if form, known, err := amd64PackedVectorMoveProperties(ins, arch); known {
		valid = err == nil && !form.undefinedOpcode()
	}
	if !valid {
		return false
	}
	for _, operand := range ins.Args {
		if operand.Kind == OpReg {
			if _, gp := x86CallerGP(operand.Reg); gp {
				return false // An encoder's GP/MMX alias cannot hide an address observation.
			}
		}
	}
	return true
}
