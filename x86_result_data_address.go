package plan9asm

import "strings"

// This directory is private to the actual emitted module. It describes a
// complete address value, not arbitrary relocation bytes, an incoming Go
// pointer or a code address. numericLiterals supplies extents to the separate
// whole-source indexed-read proof; the address value itself grants no read.
type x86StaticAddressValues struct {
	objects         map[string]bool
	writable        map[string]bool
	cells           map[x86StaticSBAddress]bool
	numericLiterals map[string]int64 // Raw private names of complete emitted readonly numeric objects.
}

func x86LoweredStaticAddressValues(file *File, resolve func(string) string, sigs map[string]FuncSig, arch string) *x86StaticAddressValues {
	if file == nil || file.Arch != ArchAMD64 || resolve == nil ||
		arch != "386" && arch != "amd64" || len(file.Data)+len(file.Globl) == 0 {
		return nil
	}
	type object struct {
		raw                 string
		size, end           int64
		invalid             bool
		readOnly            bool
		definitions         int
		relocated, badFlags bool
	}
	objects := make(map[string]object)
	bind := func(raw string) (string, object) {
		name := resolveAssemblyDataSymbol(raw, resolve)
		current := objects[name]
		if current.raw != "" && current.raw != raw {
			current.invalid = true // Coalesced definitions do not prove one object.
		}
		current.raw = raw
		return name, current
	}
	for _, global := range file.Globl {
		name, current := bind(global.Sym)
		readOnly, err := globlReadOnly(global.Flags)
		current.definitions++
		current.badFlags = current.badFlags || err != nil
		current.readOnly = current.readOnly || readOnly || err != nil
		current.invalid = current.invalid || global.SizeRaw != "" || global.Size < 0 || global.Size > maxDataGlobalSize
		if global.Size > current.size {
			current.size = global.Size
		}
		objects[name] = current
	}
	for _, datum := range file.Data {
		name, current := bind(datum.Sym)
		end, err := dataStmtEnd(datum)
		current.invalid = current.invalid || err != nil || datum.Off < current.end
		current.relocated = current.relocated || datum.Addr != ""
		current.end = end
		if end > current.size {
			current.size = end
		}
		objects[name] = current
	}
	code := make(map[string]bool)
	for _, function := range file.Funcs {
		if len(function.x86ContinuationAddresses) != 0 {
			return nil // Prepared per-entry code identities retain their separate whole-source consumer.
		}
		code[resolve(function.Sym)] = true
		code[resolveAssemblyDataSymbol(function.Sym, resolve)] = true
	}
	for name, signature := range sigs {
		code[name], code[funcSigSymbol(name, signature)] = true, true
	}
	if graph := file.x86ContinuationGraph; graph != nil {
		for symbol := range graph.addresses {
			code[resolve(symbol)] = true
			code[resolveAssemblyDataSymbol(symbol, resolve)] = true
		}
		for symbol := range graph.tables {
			code[resolveAssemblyDataSymbol(symbol, resolve)] = true
		}
	}
	values := &x86StaticAddressValues{
		objects: make(map[string]bool), writable: make(map[string]bool),
		cells: make(map[x86StaticSBAddress]bool), numericLiterals: make(map[string]int64),
	}
	for name, current := range objects {
		if !current.invalid && !code[name] && current.size > 0 && current.size <= maxDataGlobalSize {
			values.objects[name] = true
			values.writable[name] = !current.readOnly
			if current.readOnly && current.definitions == 1 && !current.badFlags && !current.relocated &&
				strings.HasSuffix(current.raw, "<>") {
				values.numericLiterals[current.raw] = current.size
			}
		}
	}
	word := x86ResultPointerWord(arch)
	for _, datum := range file.Data {
		if datum.Addr == "" || datum.Width != word || datum.Payload != nil || datum.Value != 0 {
			continue
		}
		base, _, err := dataAddress(datum)
		if err != nil {
			continue
		}
		holder := resolveAssemblyDataSymbol(datum.Sym, resolve)
		target := resolveAssemblyDataSymbol(base, resolve)
		if values.objects[holder] && values.objects[target] && !code[resolve(base)] {
			values.cells[x86StaticSBAddress{holder, datum.Off}] = true
		}
	}
	return values
}

// Paired scalar stores use both the emitted numeric extent and the writable
// object identity. A label or relocation alone supplies neither fact.
func (c *amd64Ctx) ownsWritableStaticScalar(destination Operand, width int64, arch string) bool {
	values := c.fpStaticAddressValues
	if width <= 0 || values == nil || c.resolve == nil {
		return false
	}
	address, valid := x86StaticSBReadAddress(destination, arch)
	if !valid || c.fpScalarData[address] < width {
		return false
	}
	name := resolveAssemblyDataSymbol(address.symbol, c.resolve)
	return values.objects[name] && values.writable[name]
}

// Reuse the existing MOVQ source aliases and SB grammar. The only new value
// role is one complete native word; indexed reads and physical frame writes
// retain their independent contracts. Address annotations follow the same
// non-shared Go386 TYPE_ADDR rule as the existing paired emitter.
func x86StaticAddressValueMove(ins Instr, arch string) (x86StaticSBAddress, bool, int, bool) {
	ins = x86SourceMoveInstruction(ins, arch)
	word := x86ResultPointerWord(arch)
	if !x86ResultNamedPredicateInstruction(ins) || arch != "386" && arch != "amd64" ||
		x86RawReturnScalarMoveBytes(ins.Op) != word || len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
		return x86StaticSBAddress{}, false, 0, false
	}
	index, _, valid := x86ResultGP(ins.Args[1].Reg, word, arch)
	if !valid {
		return x86StaticSBAddress{}, false, 0, false
	}
	address, immediate, valid := x86StaticAddressValueSource(ins.Args[0], arch)
	return address, immediate, index, valid
}

// MOV and the non-shared mode32 Yi32 arithmetic rows share address spelling,
// including ignored source annotations. This never dereferences the address.
func x86StaticAddressValueSource(source Operand, arch string) (x86StaticSBAddress, bool, bool) {
	immediate := false
	if source.Kind == OpSym && strings.HasPrefix(strings.TrimSpace(source.Sym), "$") {
		immediate = true
		source.Sym = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(source.Sym), "$"))
		if memory, matched, err := parseX86SymbolIndexedMemory(source.Sym); matched {
			if err != nil {
				return x86StaticSBAddress{}, false, false
			}
			if arch == "386" {
				for _, register := range []Reg{memory.Base, memory.Index} {
					if register != "" && !x86SymbolGoRegisterName(string(register)) {
						return x86StaticSBAddress{}, false, false
					}
				}
				if memory.IndexExt != "" || memory.Index == "CS" || memory.Index == "DS" || memory.Index == "ES" || memory.Index == FS || memory.Index == GS {
					return x86StaticSBAddress{}, false, false
				}
				memory.Base, memory.Index, memory.Scale = "", "", 0
			}
			source = Operand{Kind: OpMem, Mem: memory}
		}
	}
	address, valid := x86StaticSBSourceAddress(source, arch)
	return address, immediate, valid && (immediate || address.offset >= 0)
}

func (c *amd64Ctx) ownsStaticAddressImmediate(source Operand, arch string) bool {
	if c.fpStaticAddressValues == nil || c.resolve == nil {
		return false
	}
	address, immediate, valid := x86StaticAddressValueSource(source, arch)
	return valid && immediate && c.fpStaticAddressValues.objects[resolveAssemblyDataSymbol(address.symbol, c.resolve)]
}

func (state *x86ResultState) hasOwnedStaticAddr(index int) bool {
	return state.ownedStaticAddrGP != nil && index >= 0 && index < len(state.ownedStaticAddrGP) && state.ownedStaticAddrGP[index]
}

func (state *x86ResultState) setOwnedStaticAddr(index int, value bool) {
	if index < 0 || index >= 16 {
		return
	}
	if value {
		if state.ownedStaticAddrGP == nil {
			state.ownedStaticAddrGP = new([16]bool)
		}
		state.ownedStaticAddrGP[index] = true
		return
	}
	if state.ownedStaticAddrGP == nil || !state.ownedStaticAddrGP[index] {
		return
	}
	state.ownedStaticAddrGP[index] = false
	for _, live := range state.ownedStaticAddrGP {
		if live {
			return
		}
	}
	state.ownedStaticAddrGP = nil
}

// Revoke owned static SB LEA identities after any transfer that overwrites a GP,
// while preserving fresh native-word SB LEA, relative stack adjustments, and
// private stack PUSH/POP transitions.
func x86ResultOwnedStaticAddrAfter(ins Instr, state *x86ResultState, arch string, relativeAdjusted bool) {
	if state.ownedStaticAddrGP == nil || relativeAdjusted {
		return
	}
	word := x86ResultPointerWord(arch)
	if _, _, width, _, known := x86SBLEAWriteShape(ins, arch); known && width == word {
		return
	}
	if spec, known, err := x86StackWidthProperties(ins, arch); known && err == nil {
		switch spec.mode {
		case amd64StackPushValue, amd64StackPushFlags, amd64StackPopFlags:
			return
		case amd64StackPopValue:
			if int64(spec.bits/8) == word {
				return
			}
		}
	}
	live := x86ResultCallerAddressesAfter(ins, *state.ownedStaticAddrGP, nil, arch)
	any := false
	for index := range state.ownedStaticAddrGP {
		if !live[index] {
			state.ownedStaticAddrGP[index] = false
		}
		any = any || state.ownedStaticAddrGP[index]
	}
	if !any {
		state.ownedStaticAddrGP = nil
	}
}

// Propagate owned static SB LEA identities across native-word GP copies and
// discharge native-word address differences (SUB) into complete numerical bytes
// without ever granting numerical memory, LEAW upper-byte or raw-store roles.
func x86ResultOwnedStaticAddressStep(ins Instr, state *x86ResultState, arch string) (bool, bool) {
	if state.ownedStaticAddrGP == nil || state.shapeOnly ||
		!x86ResultNamedPredicateInstruction(ins) || len(ins.Args) != 2 ||
		ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
		return false, false
	}
	word := x86ResultPointerWord(arch)
	move, sub, wordMask := Op("MOVQ"), Op("SUBQ"), uint8(0xff)
	if arch == "386" {
		move, sub, wordMask = "MOVL", "SUBL", 0x0f
	}
	view := x86SourceMoveInstruction(ins, arch)
	src, _, validSrc := x86ResultGP(view.Args[0].Reg, word, arch)
	dst, _, validDst := x86ResultGP(view.Args[1].Reg, word, arch)
	if !validSrc || !validDst {
		return false, false
	}
	if view.Op == move && state.hasOwnedStaticAddr(src) {
		state.gp[dst], state.canonicalGP[dst] = 0, 0
		if word == 4 {
			state.gp[dst], state.canonicalGP[dst] = 0xf0, 0xf0
		}
		state.pointerGP[dst], state.callerAddressGP[dst], state.callerAddressOrigin[dst] = false, false, 0
		state.resultAddressGP[dst] = x86ResultSlotAddress{}
		if state.boolFrameGP != nil {
			state.boolFrameGP[dst] = x86ResultSlotAddress{}
		}
		state.setOwnedStaticAddr(dst, true)
		return true, true
	}
	if ins.Op != sub || (!state.hasOwnedStaticAddr(src) && !state.hasOwnedStaticAddr(dst)) {
		return false, false
	}
	operandReady := func(reg int) bool {
		if state.hasOwnedStaticAddr(reg) {
			return true
		}
		return !state.pointerGP[reg] && !state.callerAddressGP[reg] && state.gp[reg]&wordMask == wordMask
	}
	if !operandReady(src) || !operandReady(dst) {
		return false, true
	}
	effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
	if !known || err != nil || effect.dynamicMemory {
		return false, true
	}
	state.gp[dst] = 0xff
	state.canonicalGP[dst] = 0
	if word == 4 {
		state.canonicalGP[dst] = 0xf0
	}
	state.pointerGP[dst], state.callerAddressGP[dst], state.callerAddressOrigin[dst] = false, false, 0
	state.resultAddressGP[dst] = x86ResultSlotAddress{}
	if state.boolFrameGP != nil {
		state.boolFrameGP[dst] = x86ResultSlotAddress{}
	}
	state.setOwnedStaticAddr(dst, false)
	state.flags = state.flags&^effect.flagsKilled | effect.flagsDefined
	return true, true
}

// A leaf can return the full bits of a same-module LEA. Keep the value in
// the address-only transport proof so it never supplies numerical inputs or
// storage authority to another instruction.
func (c *amd64Ctx) ownsStaticLEAResult(fn Func, sig FuncSig, arch string) bool {
	if !x86NativeWordIntegerResult(sig, arch) || c.fpStaticAddressValues == nil || c.resolve == nil {
		return false
	}
	word := x86ResultPointerWord(arch)
	seenLEA := false
	transport := x86AddressResultTransportRole(fn, sig, arch, func(ins Instr) (int, bool) {
		if address, immediate, dest, known := x86StaticAddressValueMove(ins, arch); known && immediate {
			name := resolveAssemblyDataSymbol(address.symbol, c.resolve)
			return dest, c.fpStaticAddressValues.objects[name]
		}
		dest, _, width, mem, known := x86SBLEAWriteShape(ins, arch)
		if !known || width != word {
			return 0, false
		}
		address, valid := x86StaticSBSourceAddress(Operand{Kind: OpMem, Mem: mem}, arch)
		owned := valid && c.fpStaticAddressValues.objects[resolveAssemblyDataSymbol(address.symbol, c.resolve)]
		seenLEA = seenLEA || owned
		return dest, owned
	})
	return transport && seenLEA
}

func (c *amd64Ctx) scalarStaticAddressValueTransfer(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	values := c.fpStaticAddressValues
	if values == nil {
		return false, false
	}
	if ins.Op == "PUSHL" && len(ins.Args) == 1 && x86AbsoluteRelocationSource(ins.Args[0], arch, 32) &&
		x86ResultNamedPredicateInstruction(ins) && ins.x86NumericalRead == nil &&
		c.ownsStaticAddressImmediate(ins.Args[0], arch) {
		// A bound immediate supplies one complete word to the private
		// stack. The same transfer runs in both result-check paths.
		return x86ResultBoundValueStackStep(ins, state, owned, 0, arch, x86StackValueOwnedAddress)
	}
	word := x86ResultPointerWord(arch)
	if ins.Op == "LEAL" || ins.Op == "LEAQ" {
		destination, _, width, memory, known := x86SBLEAWriteShape(ins, arch)
		if !known || width != word {
			return false, false
		}
		// Keep native-word owned SB LEA in its own disjoint address identity
		// domain instead of numerical GP bytes. This preserves PUSH/POP/ADJSP
		// and address-difference SUB without granting dereference, LEAW upper
		// byte or arbitrary static store/return permissions.
		address, valid := x86StaticSBSourceAddress(Operand{Kind: OpMem, Mem: memory}, arch)
		if !valid || !values.objects[resolveAssemblyDataSymbol(address.symbol, c.resolve)] {
			return false, false
		}
		state.gp[destination] = 0
		state.canonicalGP[destination] = 0
		if word == 4 {
			state.gp[destination] = 0xf0
			state.canonicalGP[destination] = 0xf0
		}
		state.pointerGP[destination], state.callerAddressGP[destination], state.callerAddressOrigin[destination] = false, false, 0
		state.resultAddressGP[destination] = x86ResultSlotAddress{}
		if state.boolFrameGP != nil {
			state.boolFrameGP[destination] = x86ResultSlotAddress{}
		}
		state.predicate = x86ResultPredicate{}
		state.setOwnedStaticAddr(destination, true)
		return true, true
	}
	address, immediate, index, valid := x86StaticAddressValueMove(ins, arch)
	if !valid {
		return false, false
	}
	address.symbol = resolveAssemblyDataSymbol(address.symbol, c.resolve)
	if immediate && !values.objects[address.symbol] || !immediate && !values.cells[address] {
		return false, false
	}
	if !x86ResultStore(ins.Args[1], word, state, owned, 0, arch) {
		return false, true
	}
	state.canonicalGP[index] = 0
	if word == 4 {
		state.canonicalGP[index] = 0xf0
	}
	state.pointerGP[index], state.callerAddressGP[index], state.callerAddressOrigin[index] = false, false, 0
	state.resultAddressGP[index] = x86ResultSlotAddress{}
	if state.boolFrameGP != nil {
		state.boolFrameGP[index] = x86ResultSlotAddress{}
	}
	return true, true // Actual relocation emission/load is unchanged; FLAGS/DF are untouched.
}
