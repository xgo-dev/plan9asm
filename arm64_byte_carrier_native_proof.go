package plan9asm

import (
	"encoding/binary"
	"strconv"
	"strings"
)

type arm64ByteCarrierOperation struct {
	kind          string
	register      Reg
	from          Reg
	incoming      bool
	offset, bytes int64
	signed        bool
	constant      uint64
	callee        string
}

type arm64ByteCarrierFunction struct {
	source      Func
	signature   FuncSig
	privateName string
	entry       arm64ByteCarrierEntryObservation
	allocation  int64
	operations  []arm64ByteCarrierOperation
	reads       map[int64]bool
	writes      map[int64]bool
	registers   map[Reg]bool
	proved      bool
}

func arm64ByteCarrierRegister(register Reg) (uint32, bool) {
	if register == ZR {
		return 31, true
	}
	if !strings.HasPrefix(string(register), "R") {
		return 0, false
	}
	number, err := strconv.Atoi(strings.TrimPrefix(string(register), "R"))
	// R18_PLATFORM, R28/g, FP, LR and SP require independent machine-state
	// roles. An immediate overwrite does not make platform state disposable.
	return uint32(number), err == nil && number >= 0 && number <= 27 && number != 18
}

func (binding *arm64ByteCarrierBinding) prepareNative() error {
	for ordinal, function := range binding.file.Funcs {
		if err := binding.source.liveCarrier(); err != nil {
			return err
		}
		name := binding.symbols[function.Sym]
		plan := binding.functions[name]
		if binding.functions[plan.privateName] != nil {
			return arm64ByteCarrierContext("generated private body collides with a source entry")
		}
		found := false
		for _, text := range binding.source.report.Archive[1].Texts {
			if text.Name == name && text.ABI == 1 {
				entry, err := arm64ByteCarrierTypedEntry(text, plan.signature)
				if err != nil || found {
					return arm64ByteCarrierContext("actual complete typed compiler entry differs: %v", err)
				}
				plan.entry, found = entry, true
			}
		}
		if !found {
			return arm64ByteCarrierContext("actual compiler entry is missing")
		}
		if err := binding.prepareNativeFunction(plan, ordinal); err != nil {
			return err
		}
	}
	for _, function := range binding.file.Funcs {
		if err := binding.proveDefinedBytes(binding.functions[binding.symbols[function.Sym]], make(map[string]bool)); err != nil {
			return err
		}
	}
	return nil
}

func (binding *arm64ByteCarrierBinding) prepareNativeFunction(plan *arm64ByteCarrierFunction, ordinal int) error {
	text := binding.source.report.Standalone[ordinal]
	if text.Name != plan.signature.Name || text.ABI != 0 || text.Size != int64(len(text.Code)) || len(text.Code)%4 != 0 || len(text.Code) > 65536 {
		return arm64ByteCarrierContext("complete native body identity/extent differs")
	}
	pc := int64(0)
	word := func() (uint32, bool) {
		if pc < 0 || pc+4 > int64(len(text.Code)) {
			return 0, false
		}
		return binary.LittleEndian.Uint32(text.Code[pc:]), true
	}
	consume := func(expected uint32) bool {
		actual, exists := word()
		if !exists || actual != expected {
			return false
		}
		pc += 4
		return true
	}
	frame := arm64SourceGoFrame(plan.source)
	if frame.present {
		first, exists := word()
		if !exists || first&^uint32(511<<12) != 0xf8000ffe {
			return arm64ByteCarrierContext("original implicit frame allocation is not closed")
		}
		immediate := int64(first >> 12 & 511)
		if immediate&256 != 0 {
			immediate -= 512
		}
		plan.allocation = -immediate
		if plan.allocation <= 8 || plan.allocation > 240 || plan.allocation%16 != 0 ||
			!arm64SourceFrameFlagsKnown(plan.source) || plan.allocation != arm64SourceFrameAutosize(plan.source.FrameSize) ||
			!consume(first) || !consume(0xf81f83fd) || !consume(0xd10023fd) {
			return arm64ByteCarrierContext("complete original frame/SP/FP producer differs")
		}
	}
	normalized, err := normalizeARM64ScalarMemoryFrame(plan.source)
	if err != nil {
		return err
	}
	returned, calls := false, 0
	for index, instruction := range normalized.Instrs {
		if err := binding.source.liveCarrier(); err != nil {
			return err
		}
		if instruction.Op == OpTEXT && index == 0 {
			continue
		}
		if returned {
			return arm64ByteCarrierContext("source continues after its sole native return")
		}
		if instruction.Op == "RET" && len(instruction.Args) == 0 {
			if frame.present && (!consume(0xf85f83fd) || !consume(0xf84007fe|uint32(plan.allocation)<<12)) || !consume(0xd65f03c0) {
				return arm64ByteCarrierContext("complete native frame/link/continuation restore differs")
			}
			plan.operations = append(plan.operations, arm64ByteCarrierOperation{kind: "return"})
			returned = true
			continue
		}
		if instruction.Op == "CALL" && len(instruction.Args) == 1 {
			base, offset, valid := parseSBRef(instruction.Args[0].Sym)
			callee := binding.symbols[base]
			matched := false
			for _, call := range binding.source.report.Calls {
				matched = matched || call.Caller == text.Name && call.Callee == callee && call.SourceInstruction == index &&
					call.CallPC == pc && call.ContinuationPC == pc+4
			}
			if instruction.Args[0].Kind != OpSym || !valid || offset != 0 || callee == "" || !matched || !consume(0x94000000) {
				return arm64ByteCarrierContext("exact source/native direct-call continuation differs")
			}
			plan.operations = append(plan.operations, arm64ByteCarrierOperation{kind: "call", callee: callee})
			calls++
			continue
		}
		form, handled, err := parseARM64ScalarMemoryForm(arm64ControlOp(instruction), instruction)
		if err != nil {
			return err
		}
		if handled {
			register, valid := arm64ByteCarrierRegister(form.data)
			incoming := form.memory.Kind == OpFP
			offset := form.memory.Mem.Off
			if incoming {
				offset = form.memory.FPOffset
			}
			physical := offset
			if incoming {
				physical += plan.allocation + 8
			}
			width := int64(form.bits / 8)
			if !valid || form.pre || form.post || form.scratch || width == 0 ||
				!incoming && (form.memory.Kind != OpMem || form.memory.Mem.Base != SP || form.memory.Mem.Index != "" || form.memory.Mem.Sym != "") ||
				physical < 0 || physical%width != 0 || physical/width > 4095 {
				return arm64ByteCarrierContext("source memory needs an independent address/effect role")
			}
			shift := uint32(0)
			for int64(1)<<shift < width {
				shift++
			}
			expected, kind := uint32(0x390003e0), "store"
			if !form.store {
				expected, kind = 0x394003e0, "load"
				if form.signed {
					expected = 0x398003e0
				}
			}
			expected |= shift<<30 | uint32(physical/width)<<10 | register
			if !consume(expected) {
				return arm64ByteCarrierContext("whole source/normalized/native memory width/offset/register differs")
			}
			if !incoming {
				offset -= 8 // exact fresh outgoing data root, never saved FP/LR
			}
			plan.operations = append(plan.operations, arm64ByteCarrierOperation{kind: kind, register: form.data,
				incoming: incoming, offset: offset, bytes: width, signed: form.signed})
			continue
		}
		if instruction.Op != "MOVD" || len(instruction.Args) != 2 || instruction.Args[1].Kind != OpReg {
			return arm64ByteCarrierContext("source is outside the closed scalar move/call grammar")
		}
		register, valid := arm64ByteCarrierRegister(instruction.Args[1].Reg)
		if !valid {
			return arm64ByteCarrierContext("source consumes a hidden machine-state register")
		}
		if input := instruction.Args[0]; input.Kind == OpImm && input.ImmRaw == "" && !input.ImmIsFloat {
			value, first := uint64(0), true
			for count := 0; count < 4; count++ {
				actual, exists := word()
				if !exists || actual&31 != register {
					break
				}
				encoding := actual & 0xff800000
				bits, position := uint64(actual>>5&65535), uint(actual>>21&3)*16
				if first && (encoding == 0xd2800000 || encoding == 0x92800000) {
					value = bits << position
					if encoding == 0x92800000 {
						value = ^value
					}
				} else if !first && encoding == 0xf2800000 {
					value = value&^(uint64(65535)<<position) | bits<<position
				} else {
					break
				}
				pc += 4
				first = false
			}
			if first || value != uint64(input.Imm) {
				return arm64ByteCarrierContext("complete original constant materialization differs")
			}
			plan.operations = append(plan.operations, arm64ByteCarrierOperation{kind: "constant", register: instruction.Args[1].Reg, constant: value})
		} else if input.Kind == OpReg {
			from, valid := arm64ByteCarrierRegister(input.Reg)
			if !valid || !consume(0xaa0003e0|from<<16|register) {
				return arm64ByteCarrierContext("complete source/native register move differs")
			}
			plan.operations = append(plan.operations, arm64ByteCarrierOperation{kind: "move", register: instruction.Args[1].Reg, from: input.Reg})
		} else {
			return arm64ByteCarrierContext("nonliteral/address materialization needs a separate source role")
		}
	}
	if !returned || calls != len(text.Relocations) {
		return arm64ByteCarrierContext("native source/control inventory is incomplete")
	}
	for pc < int64(len(text.Code)) {
		if !consume(0) {
			return arm64ByteCarrierContext("native body has an executable unconsumed tail")
		}
	}
	return nil
}

func (binding *arm64ByteCarrierBinding) proveDefinedBytes(plan *arm64ByteCarrierFunction, active map[string]bool) error {
	if plan.proved {
		return nil
	}
	if active[plan.signature.Name] {
		return arm64ByteCarrierContext("recursive source needs an independent native call-state proof")
	}
	active[plan.signature.Name] = true
	defer delete(active, plan.signature.Name)
	plan.reads, plan.writes, plan.registers = make(map[int64]bool), make(map[int64]bool), make(map[Reg]bool)
	incoming, local, registers := make(map[int64]bool), make(map[int64]bool), map[Reg]bool{ZR: true}
	for _, parameter := range plan.signature.Frame.Params {
		for byte := parameter.Offset; byte < parameter.Offset+frameTypeSize(parameter.Type, 8); byte++ {
			incoming[byte] = true
		}
	}
	for _, operation := range plan.operations {
		if err := binding.source.liveCarrier(); err != nil {
			return err
		}
		switch operation.kind {
		case "constant", "move":
			if operation.kind == "move" && !registers[operation.from] {
				return arm64ByteCarrierContext("source reads an undefined entry register")
			}
			registers[operation.register], plan.registers[operation.register] = true, true
		case "load", "store":
			// The original caller's saved FP occupies the frame top even
			// though this function also saves its own FP below the new SP.
			defined, capacity := local, plan.allocation-16
			if operation.incoming {
				defined, capacity = incoming, plan.entry.dataBytes
			}
			if operation.offset < 0 || operation.bytes <= 0 || operation.offset+operation.bytes > capacity {
				return arm64ByteCarrierContext("native bytes exceed the actual caller-owned data region")
			}
			if operation.kind == "store" && !registers[operation.register] {
				return arm64ByteCarrierContext("native store consumes undefined register bits")
			}
			for byte := operation.offset; byte < operation.offset+operation.bytes; byte++ {
				if operation.kind == "load" {
					if !defined[byte] {
						return arm64ByteCarrierContext("native load observes an undefined byte")
					}
					if operation.incoming {
						plan.reads[byte] = true
					}
				} else {
					defined[byte] = true
					if operation.incoming {
						plan.writes[byte] = true
					}
				}
			}
			if operation.kind == "load" {
				registers[operation.register], plan.registers[operation.register] = true, true
			}
		case "call":
			callee := binding.functions[operation.callee]
			if callee == nil || callee.allocation != 0 {
				return arm64ByteCarrierContext("call has no complete native leaf state/effect proof")
			}
			if err := binding.proveDefinedBytes(callee, active); err != nil {
				return err
			}
			for register := range callee.registers {
				if register != "R0" {
					return arm64ByteCarrierContext("call requires more than its closed R0 poststate carrier")
				}
			}
			for byte := range callee.reads {
				if byte < 0 || byte >= plan.allocation-16 || !local[byte] {
					return arm64ByteCarrierContext("call did not initialize the exact incoming native bytes")
				}
			}
			for byte := range callee.writes {
				if byte < 0 || byte >= plan.allocation-16 {
					return arm64ByteCarrierContext("callee native write aliases protected/outside caller storage")
				}
				local[byte] = true
			}
			registers["R0"], plan.registers["R0"] = true, true
		case "return":
			if !registers["R0"] {
				return arm64ByteCarrierContext("return R0 poststate is not defined")
			}
			for _, field := range plan.signature.Frame.Results {
				for byte := field.Offset; byte < field.Offset+frameTypeSize(field.Type, 8); byte++ {
					if !incoming[byte] {
						return arm64ByteCarrierContext("typed return observes an undefined result byte")
					}
				}
			}
		default:
			return arm64ByteCarrierContext("source operation is outside the closed effect grammar")
		}
	}
	plan.proved = true
	return nil
}
