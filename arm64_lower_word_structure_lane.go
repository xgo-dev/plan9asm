package plan9asm

import "fmt"

func decodeARM64RawStructureLane(word uint32) (arm64RawStructureMemory, bool) {
	// Advanced SIMD load/store single structure. Q, L, R, opcode, S, size,
	// Rm, Rn, and Rt are decoded below. Bit 23 distinguishes no-offset from
	// post-indexed forms. In the no-offset form Rm is reserved and must be zero.
	if word&0xbf000000 != 0x0d000000 {
		return arm64RawStructureMemory{}, false
	}
	form, valid := arm64RawStructureAddress(word)
	if !valid {
		return arm64RawStructureMemory{}, false
	}

	q := int(word>>30) & 1
	s := int(word>>12) & 1
	size := int(word>>10) & 3
	opcode := int(word>>13) & 7
	form.count = 1 + (int(word>>21) & 1) + 2*(opcode&1)

	elementBits := 0
	lane := 0
	switch opcode >> 1 {
	case 0: // B: index = UInt(Q:S:size)
		elementBits = 8
		lane = q<<3 | s<<2 | size
	case 1: // H: index = UInt(Q:S:size<1>), size<0> is reserved.
		if size&1 != 0 {
			return arm64RawStructureMemory{}, false
		}
		elementBits = 16
		lane = q<<2 | s<<1 | size>>1
	case 2: // S uses size=00; D uses S=0,size=01.
		if size == 0 {
			elementBits = 32
			lane = q<<1 | s
		} else if size == 1 && s == 0 {
			elementBits = 64
			lane = q
		} else {
			return arm64RawStructureMemory{}, false
		}
	default:
		// opcode<2:1> == 11 is the load-and-replicate family.
		return arm64RawStructureMemory{}, false
	}

	form.arrangement = arm64VectorArrangement{elementBits: elementBits, lanes: 128 / elementBits}
	form.lane = lane
	return form, true
}

func (c *arm64Ctx) lowerStructureLane(form arm64StructureMemoryForm) error {
	addr, increment, err := c.structureAddress(form)
	if err != nil {
		return err
	}
	arrangement := form.arrangement
	elementBits := arrangement.elementBits
	elementBytes := elementBits / 8

	for registerOffset, reg := range form.registers {
		offset := int64(registerOffset * elementBytes)
		if form.load {
			element, err := c.arm64LoadStructureElement(addr, offset, elementBits)
			if err != nil {
				return err
			}
			vector, err := c.loadARM64VectorInteger(reg, arrangement)
			if err != nil {
				return err
			}
			inserted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> %s, i%d %s, i32 %d\n",
				inserted, arrangement.lanes, elementBits, vector,
				elementBits, element, form.lane)
			if err := c.storeARM64VectorInteger(reg, arrangement, "%"+inserted); err != nil {
				return err
			}
			continue
		}

		vector, err := c.loadARM64VectorInteger(reg, arrangement)
		if err != nil {
			return err
		}
		element := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %s, i32 %d\n",
			element, arrangement.lanes, elementBits, vector, form.lane)
		if err := c.arm64StoreStructureElement(addr, offset, elementBits, "%"+element); err != nil {
			return err
		}
	}

	if !form.post {
		return nil
	}
	return c.arm64UpdatePostIncrement(form.memory.Mem.Base, increment)
}
