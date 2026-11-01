package plan9asm

// A SIMD lane write preserves the other low 128 bits. Prefix widths alone
// cannot describe its definedness: D[1] may be defined while D[0] is not.
// Scalable upper bits remain separate from this finite architectural bank.
type arm64MachineVectorDefinition struct {
	low, high uint64
	scalable  bool
}

func arm64MachineVectorMask(offset, width int) arm64MachineVectorDefinition {
	var mask arm64MachineVectorDefinition
	for bit := offset; bit < offset+width; bit++ {
		if bit < 64 {
			mask.low |= uint64(1) << uint(bit)
		} else {
			mask.high |= uint64(1) << uint(bit-64)
		}
	}
	return mask
}

func (state arm64MachineState) vectorDefinition(reg string) arm64MachineVectorDefinition {
	if definition, present := state.vectors[reg]; present {
		return definition
	}
	width := state.values[reg]
	if width > 128 {
		return arm64MachineVectorDefinition{low: ^uint64(0), high: ^uint64(0), scalable: true}
	}
	return arm64MachineVectorMask(0, width)
}

func (state *arm64MachineState) setVectorDefinition(reg string, definition arm64MachineVectorDefinition) {
	if state.vectors == nil {
		state.vectors = make(map[string]arm64MachineVectorDefinition)
	}
	state.vectors[reg] = definition
	width := 0
	for width < 128 {
		word, bit := definition.low, width
		if width >= 64 {
			word, bit = definition.high, width-64
		}
		if word&(uint64(1)<<uint(bit)) == 0 {
			break
		}
		width++
	}
	if width == 128 && definition.scalable {
		width = arm64WholeScalableRegister
	}
	state.values[reg] = width
}

func (state *arm64MachineState) applyVectorSpan(effect arm64MachineEffect) error {
	if _, valid := arm64ParseVReg(Reg(effect.register)); !valid ||
		effect.vectorOffset < 0 || effect.width <= 0 || effect.width > 128 || effect.vectorOffset > 128-effect.width {
		return arm64GoABIContext("invalid SIMD defined-bit span at %q", effect.source)
	}
	if effect.copyFrom != "" {
		if _, valid := arm64ParseVReg(Reg(effect.copyFrom)); !valid || !effect.write || effect.vectorOffset != 0 || effect.width != 128 {
			return arm64GoABIContext("invalid complete SIMD defined-bit copy at %q", effect.source)
		}
		definition := state.vectorDefinition(effect.copyFrom)
		definition.scalable = true // The architectural write clears scalable upper bits.
		state.setVectorDefinition(effect.register, definition)
		return nil
	}
	definition := state.vectorDefinition(effect.register)
	mask := arm64MachineVectorMask(effect.vectorOffset, effect.width)
	if effect.write {
		definition.low |= mask.low
		definition.high |= mask.high
		// A NEON write clears the scalable upper part, but never initializes
		// preserved, previously unknown bits inside the low 128-bit bank.
		definition.scalable = true
		state.setVectorDefinition(effect.register, definition)
		return nil
	}
	if definition.low&mask.low != mask.low || definition.high&mask.high != mask.high {
		return arm64GoABIContext("%s lane read [%d,%d) is not supplied by entry, call results or reaching writes at %q",
			effect.register, effect.vectorOffset, effect.vectorOffset+effect.width, effect.source)
	}
	return nil
}

// Record the complete validated VMOV/VDUP form before emitting its virtual
// assembly. Loading an old destination to preserve its untouched bytes is not
// a semantic read of those bytes; later actual consumers still require them.
func (c *arm64Ctx) recordMachineVectorTransfer(form arm64VectorTransferForm) func() {
	flow := c.machineAvailability
	if flow == nil || flow.flagsOnly || flow.suspended != 0 {
		return func() {}
	}
	if form.sourceGP {
		c.recordMachineRegister(form.source, form.bits, false)
	} else {
		width := form.bits
		if form.copy {
			width *= form.lanes
		}
		flow.blocks[flow.current].effects = append(flow.blocks[flow.current].effects, arm64MachineEffect{
			register: arm64MachineRegister(form.source), width: width,
			vectorOffset: form.sourceLane * form.bits, vectorSpan: true, source: flow.source,
		})
	}
	if form.destinationGP {
		c.recordMachineRegister(form.destination, 64, true)
	} else if form.preserve {
		flow.blocks[flow.current].effects = append(flow.blocks[flow.current].effects, arm64MachineEffect{
			register: arm64MachineRegister(form.destination), width: form.bits, write: true,
			vectorOffset: form.destinationLane * form.bits, vectorSpan: true, source: flow.source,
		})
	} else {
		// Every non-preserving row writes its complete bank, with explicit
		// upper zeroing for Q=0 and scalar-lane destination forms.
		c.recordMachineRegister(form.destination, arm64WholeScalableRegister, true)
	}
	flow.suspended++
	return func() { flow.suspended-- }
}
