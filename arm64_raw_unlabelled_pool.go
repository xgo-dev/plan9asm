package plan9asm

import (
	"encoding/binary"
	"fmt"
	"strings"

	"golang.org/x/arch/arm64/arm64asm"
)

// identifyARM64UnlabelledPool handles a trailing, contiguous raw routine and
// its appended constants. Walk actual control-flow edges before examining
// address references: data bytes can themselves look like branches or ADRs.
// Unknown source widths, indirect control flow, escaping addresses and mixed
// code/data regions remain on the ordinary fail-closed path.
func identifyARM64UnlabelledPool(fn Func, points []arm64RawLayoutPoint, known map[string]bool, returnClobbers uint32) (map[int]bool, []arm64RawDataBlob, map[int]string) {
	end := len(fn.Instrs)
	if end > 0 && fn.Instrs[end-1].Op == OpRET {
		end--
	}
	sourceReturn := end < len(fn.Instrs) && len(fn.Instrs[end].Args) == 0
	start := end
	for start > 0 && arm64RawLiteralWord(fn.Instrs[start-1]) {
		start--
	}
	if start == end {
		return nil, nil, nil
	}
	for _, ins := range fn.Instrs[:start] {
		if ins.Op == OpWORD {
			return nil, nil, nil
		}
		for _, arg := range ins.Args {
			if arg.Kind == OpMem && arg.Mem.Base == PC || arg.Kind == OpSym && strings.Contains(arg.Sym, fn.Sym+"+") {
				return nil, nil, nil
			}
		}
	}

	visited := make(map[int]bool)
	queue := []int{start}
	last := start
	addresses := make(map[int]int)
	for len(queue) > 0 {
		at := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if visited[at] {
			continue
		}
		if at == end && sourceReturn {
			// A raw branch may cross the appended data to the ordinary
			// source RET. Preserve its Go auto-epilogue rather than require
			// an unsafe hardware RET before the pool. No other boundary or
			// register-return contract is inferred here.
			continue
		}
		if at < start || at >= end {
			return nil, nil, nil
		}
		visited[at] = true
		if at > last {
			last = at
		}
		word := uint32(fn.Instrs[at].Args[0].Imm)
		// BR and BLR cannot prove their successor without value-flow analysis.
		if word&0xfffffc1f == 0xd61f0000 || word&0xfffffc1f == 0xd63f0000 {
			return nil, nil, nil
		}
		if word&0xfffffc1f == 0xd65f0000 { // RET Xn.
			continue
		}
		displacement, op, relative, err := arm64RawPCRelativeDisplacement(fn.Instrs[at])
		if err != nil {
			return nil, nil, nil
		}
		if relative {
			if displacement%4 != 0 {
				return nil, nil, nil
			}
			target := at + int(displacement/4)
			switch op {
			case "ADR":
				addresses[at] = target
			case "B", "BL", "CBZ", "CBNZ", "TBZ", "TBNZ":
				queue = append(queue, target)
			default:
				return nil, nil, nil
			}
		}
		if word&0xfc000000 != 0x14000000 { // Only unconditional B ends fallthrough.
			queue = append(queue, at+1)
		}
	}
	pool := last + 1
	if pool >= end {
		return nil, nil, nil
	}

	// An ADR can also construct a function pointer. Only classify its target
	// as data when the produced address is used exclusively by loads and killed
	// on every outgoing path (possibly by an explicit return contract).
	values := newARM64RawPoolValues(fn.Instrs, start, pool, visited)
	origins := make(map[int]uint64)
	for at, target := range addresses {
		if target >= pool && target < end {
			origins[at] = uint64(target-pool) * 4
		}
	}
	size := int64(end-pool) * 4
	if !arm64RawPoolAddressProof(fn.Instrs, pool, size, returnClobbers, values, origins) &&
		!arm64RawPoolAllVectorLengths(fn.Instrs, start, pool, size, returnClobbers, visited, origins) {
		return nil, nil, nil
	}
	insertions := make(map[int]string)
	label := func(at int) string {
		if name, ok := insertions[at]; ok {
			return name
		}
		name := arm64UniqueRawTargetLabel(known, points[at])
		known[name] = true
		insertions[at] = name
		return name
	}
	blob := arm64RawDataBlob{label: label(pool), aliases: make(map[string]int64)}
	for _, target := range addresses {
		if target >= pool && target < end {
			blob.aliases[label(target)] = int64(target-pool) * 4
		}
	}
	words := make(map[int]bool)
	for at := pool; at < end; at++ {
		words[at] = true
		var bytes [4]byte
		binary.LittleEndian.PutUint32(bytes[:], uint32(fn.Instrs[at].Args[0].Imm))
		blob.bytes = append(blob.bytes, bytes[:]...)
	}
	return words, []arm64RawDataBlob{blob}, insertions
}

func arm64RawAddressOnlyLoaded(instructions []Instr, at, end int) bool {
	return arm64RawAddressOnlyLoadedWithExit(instructions, at, end, 0)
}

// Only the translating caller has a FuncSig. Standalone layout probes remain
// conservative. Explicit parameter/result contracts identify registers that
// cannot be results. Restrict terminal kills to R0..R17, avoiding platform,
// callee-preserved, frame, Go-context and link registers. Exclude both normal
// ABI results and every frame-slot fallback register used by lowerRET.
func arm64RawPoolReturnClobbers(fn Func, sig FuncSig) uint32 {
	if len(sig.ArgRegs) != 0 || len(sig.Frame.Params) == 0 || fn.ArgSize <= 0 {
		return 0
	}
	const scratch = (1 << 18) - 1
	if sig.Ret == Void {
		if len(sig.Frame.Results) != 0 {
			return 0
		}
		return scratch
	}
	if len(sig.Frame.Results) == 0 {
		return 0
	}
	fields, aggregate := parseLiteralStructFields(sig.Ret)
	if !aggregate {
		fields = []LLVMType{sig.Ret}
	}
	mask := uint32(scratch)
	cursor := arm64ABIRegisterCursor{}
	for _, typ := range fields {
		if _, err := cursor.next(typ); err != nil {
			return 0
		}
		if isARM64ABIIntegerType(typ) {
			mask &^= 1 << (cursor.integer - 1)
		}
	}
	for _, slot := range sig.Frame.Results {
		if slot.Index < 0 || slot.Index > 31 {
			return 0
		}
		mask &^= 1 << slot.Index
	}
	return mask
}

func arm64RawAddressOnlyLoadedWithExit(instructions []Instr, at, end int, returnClobbers uint32) bool {
	return arm64RawAddressOnlyLoadedWithinPool(instructions, at, end, returnClobbers, nil)
}

type arm64RawPoolBounds struct {
	offset   int64
	size     int64
	values   *arm64RawPoolValues
	origins  map[int]uint64
	symbolic bool
}

type arm64RawPoolFlow struct {
	at       int
	register arm64asm.Reg
	offset   arm64RawPoolRange
}

func arm64RawAddressOnlyLoadedWithinPool(instructions []Instr, at, end int, returnClobbers uint32, bounds *arm64RawPoolBounds) bool {
	register := arm64asm.X0 + arm64asm.Reg(uint32(instructions[at].Args[0].Imm)&31)
	loaded := false
	initialOffset := int64(0)
	if bounds != nil {
		initialOffset = bounds.offset
		if bounds.symbolic {
			initialOffset = 0 // Numeric offsets come from reaching definitions at each read.
		}
	}
	visited := make(map[arm64RawPoolValue]arm64RawPoolRange)
	queue := []arm64RawPoolFlow{{at + 1, register, arm64RawPoolRange{initialOffset, initialOffset}}}
	for len(queue) > 0 {
		state := queue[len(queue)-1]
		i, offset := state.at, state.offset
		register := state.register
		wordRegister := register - arm64asm.X0 + arm64asm.W0
		isAddress := func(r arm64asm.Reg) bool { return r == register || r == wordRegister }
		next := func(at int) {
			if bounds != nil && bounds.values != nil && bounds.values.excluded[arm64RawPoolEdge{i, at}] {
				return
			}
			nextOffset := offset
			if bounds != nil && bounds.symbolic {
				nextOffset = arm64RawPoolRange{}
			}
			queue = append(queue, arm64RawPoolFlow{at, register, nextOffset})
		}
		queue = queue[:len(queue)-1]
		if i < 0 || i >= end {
			return false
		}
		key := arm64RawPoolValue{i, register}
		if previous, ok := visited[key]; ok {
			// A changing loop offset or disagreeing join needs range analysis,
			// not an instruction-only visited set that drops the second path.
			if previous != offset {
				return false
			}
			continue
		}
		visited[key] = offset
		if !arm64RawLiteralWord(instructions[i]) {
			return false
		}
		word := uint32(instructions[i].Args[0].Imm)
		if form, ok := decodeARM64RawSVEAddress(word); ok {
			if form.op != "RDVL" && form.source == int(register-arm64asm.X0) {
				derived, ok := arm64RawPoolScalableAlias(form, offset, bounds)
				if !ok {
					return false
				}
				alias := arm64asm.X0 + arm64asm.Reg(form.destination)
				queue = append(queue, arm64RawPoolFlow{i + 1, alias, derived})
			}
			if form.destination != int(register-arm64asm.X0) {
				next(i + 1)
			}
			continue
		}
		if form, ok := decodeARM64RawSVECnt(word); ok {
			if !form.vector && form.destination == int(register-arm64asm.X0) {
				if form.operation != "" { // INC/DEC reads and changes the address.
					return false
				}
			} else {
				next(i + 1)
			}
			continue
		}
		// CNTP has only predicate inputs and overwrites its explicit GP
		// destination. Writing this register kills the old pool address.
		if ins, ok := decodeARM64RawSVEPredicateCount(word); ok {
			if ins.Args[2].Reg != Reg(fmt.Sprintf("R%d", register-arm64asm.X0)) {
				next(i + 1)
			}
			continue
		}
		if bounds != nil && bounds.symbolic {
			if destination, ok := arm64RawPoolSymbolicAlias(word, int(register-arm64asm.X0)); ok {
				alias := arm64asm.X0 + arm64asm.Reg(destination)
				queue = append(queue, arm64RawPoolFlow{i + 1, alias, arm64RawPoolRange{}})
				if alias != register {
					next(i + 1)
				}
				continue
			}
		}
		if destination, derived, ok := arm64RawPoolAlias(word, i, int(register-arm64asm.X0), offset, bounds); ok {
			alias := arm64asm.X0 + arm64asm.Reg(destination)
			queue = append(queue, arm64RawPoolFlow{i + 1, alias, derived})
			if alias != register {
				next(i + 1) // Overwriting the original later does not kill its copy.
			}
			continue
		}
		if ins, ok := arm64RawPoolReplicateLoad(word); ok {
			memory := ins.Args[0].Mem
			name := Reg(fmt.Sprintf("R%d", register-arm64asm.X0))
			if memory.Index == name {
				return false
			}
			if memory.Base == name {
				var proven bool
				offset, proven = bounds.offsetAt(i, register, offset)
				if !proven {
					return false
				}
				spec := arm64SVEReplicateMemorySpecs[ins.Op]
				bytes := spec.blockBytes
				if bytes == 0 {
					bytes = spec.memoryBits / 8
				}
				if bounds == nil || memory.Index != "" && memory.Index != ZR || memory.OffRaw != "" ||
					!arm64RawPoolContains(offset.low+memory.Off, int64(bytes), bounds.size) ||
					!arm64RawPoolContains(offset.high+memory.Off, int64(bytes), bounds.size) {
					return false
				}
				loaded = true
			}
			next(i + 1)
			continue
		}
		if form, ok := decodeARM64RawSVELoadStore(word); ok && form.base == int(register-arm64asm.X0) {
			if !bounds.wholeScalableLoadInBounds(i, form) {
				return false
			}
			loaded = true
			next(i + 1)
			continue
		}
		if row, ok := arm64RawPoolContiguousLoad(word); ok &&
			(int(word>>5)&31 == int(register-arm64asm.X0) ||
				row.address == arm64SVELoadRegister && int(word>>16)&31 == int(register-arm64asm.X0)) {
			if !bounds.contiguousScalableLoadInBounds(i, word, row) {
				return false
			}
			loaded = true
			next(i + 1)
			continue
		}
		// x/arch does not decode SVE. Consult validated typed grammars for
		// vector-only effects and explicit unrelated scalar/memory operands.
		// Unknown effects and any use of this address still fail below.
		if arm64RawPoolSVEIgnoresAddress(word, int(register-arm64asm.X0)) {
			next(i + 1)
			continue
		}
		var code [4]byte
		binary.LittleEndian.PutUint32(code[:], word)
		decoded, err := arm64asm.Decode(code[:])
		if err != nil {
			return false
		}
		// A canonical return can kill a scratch address only when the caller
		// supplied an explicit return contract. Calls and other indirect exits
		// still expose live registers; RET through the address is never data.
		if word == 0xd65f03c0 && returnClobbers&(1<<uint(register-arm64asm.X0)) != 0 {
			continue
		}
		switch decoded.Op {
		case arm64asm.BL, arm64asm.BLR, arm64asm.BR, arm64asm.RET, arm64asm.ERET, arm64asm.DRPS:
			return false
		}
		// Restrict kill recognition to these unambiguous destination-first
		// operations. Other encodings can read/write registers implicitly.
		destinations := 0
		switch decoded.Op.String() {
		case "ADR", "MOV", "MOVZ", "MOVN", "AND", "ORR", "EOR":
			destinations = 1
		case "ADD", "ADDS", "ADC", "ADCS", "SUB", "SUBS", "SBC", "SBCS",
			"NEG", "NEGS", "NGC", "NGCS":
			destinations = 1
		case "LSL", "LSR", "ASR", "ROR", "FMOV", "SMOV", "UMOV":
			destinations = 1
		case "LDR", "LDRB", "LDRH", "LDRSB", "LDRSH", "LDRSW",
			"LDUR", "LDURB", "LDURH", "LDURSB", "LDURSH", "LDURSW",
			"CSEL", "CSINC", "CSINV", "CSNEG":
			destinations = 1
		case "LDP", "LDNP", "LDPSW":
			destinations = 2
		}
		kills := false
		for n, arg := range decoded.Args {
			if arg == nil {
				break
			}
			switch arg := arg.(type) {
			case arm64asm.PCRel:
				switch decoded.Op {
				case arm64asm.ADR:
				case arm64asm.B, arm64asm.CBZ, arm64asm.CBNZ, arm64asm.TBZ, arm64asm.TBNZ:
					if int64(arg)%4 != 0 {
						return false
					}
					next(i + int(arg)/4)
				default:
					return false
				}
			case arm64asm.Reg:
				if isAddress(arg) {
					if n < destinations {
						kills = true
					} else {
						return false
					}
				}
			case arm64asm.RegSP:
				if isAddress(arm64asm.Reg(arg)) {
					if n < destinations {
						kills = true
					} else {
						return false
					}
				}
			case arm64asm.MemImmediate:
				if arg.Mode == arm64asm.AddrPostReg {
					// x/arch's arg_Xns_mem_post_Xm keeps Rm private, but its
					// decoder defines it as bits 20:16. An unrelated post-index
					// operand is harmless; using the address as Rm is not.
					index := arm64asm.X0 + arm64asm.Reg(word>>16&31)
					if isAddress(index) {
						return false
					}
				}
				if arm64asm.Reg(arg.Base) == register {
					if !arm64RawPoolReadOnlyLoad(decoded.Op) {
						return false
					}
					if arg.Mode != arm64asm.AddrOffset {
						if _, _, valid := arm64PoolLoadWriteback(decoded, word); !valid || bounds == nil || !bounds.symbolic {
							return false
						}
					}
					var proven bool
					offset, proven = bounds.offsetAt(i, register, offset)
					if !proven {
						return false
					}
					if bounds != nil && (!arm64RawPoolLoadInBounds(decoded, word, arg, offset.low, bounds.size) ||
						!arm64RawPoolLoadInBounds(decoded, word, arg, offset.high, bounds.size)) {
						return false
					}
					loaded = true
				}
			case arm64asm.MemExtend:
				if isAddress(arg.Index) {
					return false
				}
				if isAddress(arm64asm.Reg(arg.Base)) {
					var proven bool
					offset, proven = bounds.offsetAt(i, register, offset)
					if !proven {
						return false
					}
					if bounds == nil || !arm64RawPoolReadOnlyLoad(decoded.Op) ||
						offset.low < 0 || !arm64RawPoolIndexedLoadInBounds(decoded, word, arg, i, offset.high, bounds) {
						return false
					}
					loaded = true
				}
			case arm64asm.RegExtshiftAmount:
				// x/arch keeps this typed operand's register field private, but
				// prints the register before the comma separating its modifier.
				name := strings.SplitN(arg.String(), ",", 2)[0]
				if name == register.String() || name == wordRegister.String() {
					return false
				}
			}
		}
		if kills {
			continue
		}
		if word&0xfc000000 != 0x14000000 {
			next(i + 1)
		}
	}
	return loaded
}

// Do not infer memory effects from an LD prefix: exclusive loads retain an
// address in the monitor and newer LD* atomics can also write memory.
func arm64RawPoolReadOnlyLoad(op arm64asm.Op) bool {
	switch op {
	case arm64asm.LDR, arm64asm.LDRB, arm64asm.LDRH, arm64asm.LDRSB, arm64asm.LDRSH, arm64asm.LDRSW,
		arm64asm.LDUR, arm64asm.LDURB, arm64asm.LDURH, arm64asm.LDURSB, arm64asm.LDURSH, arm64asm.LDURSW,
		arm64asm.LDTR, arm64asm.LDTRB, arm64asm.LDTRH, arm64asm.LDTRSB, arm64asm.LDTRSH, arm64asm.LDTRSW,
		arm64asm.LDAR, arm64asm.LDARB, arm64asm.LDARH,
		arm64asm.LDP, arm64asm.LDNP, arm64asm.LDPSW,
		arm64asm.LD1, arm64asm.LD2, arm64asm.LD3, arm64asm.LD4,
		arm64asm.LD1R, arm64asm.LD2R, arm64asm.LD3R, arm64asm.LD4R:
		return true
	}
	return false
}

func arm64RawPoolIndependentSVE(word uint32) bool {
	if effects, ok := arm64RawSVEEffects(word); ok {
		return effects.gpReads == 0 && effects.gpWrites == 0 && !effects.accesses
	}
	if form, ok := decodeARM64RawSVECnt(word); ok && form.vector {
		return true
	}
	if _, ok := decodeARM64RawSVEPTrue(word); ok {
		return true
	}
	if _, ok := decodeARM64RawSVEEOR(word); ok {
		return true
	}
	if _, ok := decodeARM64RawSVEAdd(word); ok {
		return true
	}
	if _, _, ok := decodeARM64RawSVEAddSub(word); ok {
		return true
	}
	if _, ok := decodeARM64RawSVEShift(word); ok {
		return true
	}
	if _, ok := decodeARM64RawSVESelect(word); ok {
		return true
	}
	if _, ok := decodeARM64RawSVEDupElement(word); ok {
		return true
	}
	if _, ok := decodeARM64RawSVEDupImmediate(word); ok {
		return true
	}
	if _, ok := decodeARM64RawSVEPermute(word); ok {
		return true
	}
	if _, ok := decodeARM64RawSVEFloat(word); ok {
		return true
	}
	if _, ok := decodeARM64RawSVEIntegerAddReduction(word); ok {
		return true // Scalar result is a V register, not a GP destination.
	}
	return false
}

// These instruction families have no implicit GP operands or writeback.
// Their memory may be mutable, but cannot contain the relocated pool address:
// the proof rejects every earlier copy/escape of that address. Do not extend
// this to exclusive/first-fault operations with hidden architectural state.
func arm64RawPoolSVEIgnoresAddress(word uint32, address int) bool {
	if effects, ok := arm64RawSVEEffects(word); ok {
		return address < 0 || address < 32 && effects.gpReads&(1<<uint(address)) == 0
	}
	if arm64RawPoolIndependentSVE(word) {
		return true
	}
	if ins, ok := decodeARM64RawSVECopy(word); ok && arm64SVECopyGeneralRegister(ins.Args[0]) {
		// A GP/SP copy writes only a vector, but copying this pool address
		// into that vector would expose a relocation-dependent numeric value.
		return int(word>>5)&31 != address
	}
	if row, ok := arm64RawPoolContiguousLoad(word); ok {
		return int(word>>5)&31 != address &&
			(row.address != arm64SVELoadRegister || int(word>>16)&31 != address)
	}
	if form, ok := decodeARM64RawSVELoadStore(word); ok {
		return form.base != address
	}
	if _, ok := decodeARM64RawSVEWhile(word); ok {
		return int(word>>5&31) != address && int(word>>16&31) != address
	}
	if form, ok := decodeARM64RawSVEDupGeneral(word); ok {
		return form.source != address
	}
	if form, ok := decodeARM64RawSVELDST1W(word); ok {
		return form.base != address && (!form.registerOffset || form.index != address)
	}
	if form, ok := decodeARM64RawSVELDST1D(word); ok {
		return form.base != address && (!form.registerOffset || form.index != address)
	}
	if ins, ok := decodeARM64RawSVEContiguousMemory(word); ok {
		register := Reg(fmt.Sprintf("R%d", address))
		for _, operand := range ins.Args {
			if operand.Kind == OpMem {
				return operand.Mem.Base != register && operand.Mem.Index != register
			}
		}
	}
	return false
}
