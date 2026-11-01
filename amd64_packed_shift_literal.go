package plan9asm

// One adjacent immediate logical-right shift retains bit dependencies which
// cannot be represented by the ordinary whole-byte vector domain. This is not
// a vector value, a memory permission or a fact about any other instruction.
type x86ResultShiftBits struct {
	input                        uint64
	register, width, lane, count uint8
}

func x86ResultShiftBitSource(ins Instr, form x86PackedShiftForm, input uint64, destination int) x86ResultShiftBits {
	if !x86ResultNamedPredicateInstruction(ins) || form.left || form.arithmetic || form.mmx ||
		form.mask >= 0 || form.countMode != x86PackedShiftUniform || form.countOperand.Kind != OpImm ||
		form.laneBits != 16 && form.laneBits != 32 && form.laneBits != 64 {
		return x86ResultShiftBits{}
	}
	return x86ResultShiftBits{input: input, register: uint8(destination),
		width: uint8(form.byteWidth), lane: uint8(form.laneBits), count: uint8(form.countOperand.Imm)}
}

// Only emitted, immutable same-module bytes may remove an input dependency.
// Extent and the actual full native read remain independently checked by the
// ordinary logical transfer before this projection is used.
type x86ShiftLiteral struct {
	bytes [64]byte
	width uint8
}

func (pending x86ResultShiftBits) definedBytes(ins Instr, form x86PackedLogicalForm, literals map[x86StaticSBAddress]x86ShiftLiteral, arch string) uint64 {
	if pending.width == 0 || form.byteWidth != int(pending.width) || form.mask >= 0 || form.memoryBytes <= 0 || form.memory != form.first ||
		!x86ResultNamedPredicateInstruction(ins) || form.spec.mode == amd64PackedLogicalXor {
		return 0
	}
	second, valid := amd64VectorRegisterIndex(ins.Args[form.second].Reg, form.byteWidth)
	address, static := x86StaticSBReadAddress(form.source, arch)
	literal := literals[address]
	if !valid || second != int(pending.register) || !static || int(literal.width) < form.memoryBytes {
		return 0
	}
	var known uint64
	for at := 0; at < form.byteWidth; at++ {
		mask := x86PackedLogicalSecondBits(form.spec.mode, literal.bytes[at%form.memoryBytes])
		defined := true
		for bit := 0; bit < 8; bit++ {
			if mask&(1<<uint(bit)) == 0 {
				continue
			}
			inLane := at*8%int(pending.lane) + bit + int(pending.count)
			if inLane >= int(pending.lane) {
				continue // Logical right shifts supply zero above the lane.
			}
			input := at*8/int(pending.lane)*int(pending.lane)/8 + inLane/8
			if pending.input&(uint64(1)<<uint(input)) == 0 {
				defined = false
				break
			}
		}
		if defined {
			known |= uint64(1) << uint(at)
		}
	}
	return known
}

// Requests describe source tuples only. Each consumer must obtain their bytes
// from its own validated immutable storage, with no permission transferred here.
func x86PackedLogicalLiteralRequests(file *File, arch string) map[string]map[int64]int {
	requests := make(map[string]map[int64]int)
	for _, function := range file.Funcs {
		for _, ins := range function.Instrs {
			form, known, err := x86PackedLogicalProperties(ins, arch)
			if !known || err != nil || form.mmx || form.memory < 0 || form.memoryBytes <= 0 || form.memoryBytes > 64 {
				continue
			}
			address, valid := x86StaticSBReadAddress(form.source, arch)
			if !valid || address.offset > maxDataGlobalSize-int64(form.memoryBytes) {
				continue
			}
			if requests[address.symbol] == nil {
				requests[address.symbol] = make(map[int64]int)
			}
			if requests[address.symbol][address.offset] < form.memoryBytes {
				requests[address.symbol][address.offset] = form.memoryBytes
			}
		}
	}
	return requests
}

// Snapshot only requested tuples (at most one Z register), never a large global
// allocation. The existing static directory rejects coalesced DATA definitions,
// overlapping ranges and code/signature namespaces. A unique valid readonly
// GLOBL and a relocation-free object are additional literal requirements.
func x86LoweredShiftLiterals(file *File, resolve func(string) string, values *x86StaticAddressValues, arch string) map[x86StaticSBAddress]x86ShiftLiteral {
	if file == nil || values == nil || resolve == nil {
		return nil
	}
	needed := false
	for _, function := range file.Funcs {
		for _, ins := range function.Instrs {
			form, known, err := x86PackedShiftProperties(ins.Op, ins, arch)
			needed = needed || known && err == nil && x86ResultShiftBitSource(ins, form, 0, 0).width != 0
		}
	}
	if !needed {
		return nil
	}
	type object struct {
		globals int
		literal bool
		data    []DataStmt
	}
	objects := make(map[string]*object)
	objectFor := func(symbol string) *object {
		name := resolveAssemblyDataSymbol(symbol, resolve)
		if objects[name] == nil {
			objects[name] = &object{literal: values.objects[name] && !values.writable[name]}
		}
		return objects[name]
	}
	for _, global := range file.Globl {
		current := objectFor(global.Sym)
		readonly, err := globlReadOnly(global.Flags)
		current.globals++
		current.literal = current.literal && err == nil && readonly
	}
	for _, datum := range file.Data {
		current := objectFor(datum.Sym)
		current.literal = current.literal && datum.Addr == "" && int64(len(datum.Payload)) <= datum.Width
		current.data = append(current.data, datum)
	}
	literals := make(map[x86StaticSBAddress]x86ShiftLiteral)
	for symbol, offsets := range x86PackedLogicalLiteralRequests(file, arch) {
		current := objects[resolveAssemblyDataSymbol(symbol, resolve)]
		if current == nil || !current.literal || current.globals != 1 {
			continue
		}
		for offset, width := range offsets {
			address := x86StaticSBAddress{symbol, offset}
			literal := x86ShiftLiteral{width: uint8(width)}
			for _, datum := range current.data {
				for at := 0; at < width; at++ {
					offset := address.offset + int64(at) - datum.Off
					if offset < 0 || offset >= datum.Width {
						continue
					}
					// Same little-endian, sign-extended numeric/padded string
					// bytes as dataStmtPayload, without allocating datum.Width.
					if datum.Payload != nil {
						if offset < int64(len(datum.Payload)) {
							literal.bytes[at] = datum.Payload[offset]
						}
					} else if offset < 8 {
						literal.bytes[at] = byte(datum.Value >> uint(offset*8))
					} else if datum.Value < 0 {
						literal.bytes[at] = 0xff
					}
				}
			}
			literals[address] = literal
		}
	}
	return literals
}
