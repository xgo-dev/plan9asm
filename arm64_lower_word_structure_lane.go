package plan9asm

import "fmt"

// arm64RawStructureLane describes the Advanced SIMD load/store single
// structure encodings. These are the LD1/ST1 through LD4/ST4 forms that move
// one selected lane in each consecutive vector register, rather than the
// whole-register structure forms accepted by Go's named VLDn/VSTn syntax.
type arm64RawStructureLane struct {
	load          bool
	count         int
	elementBits   int
	lane          int
	firstRegister int
	base          int
	post          bool
	postRegister  int // 31 selects the architecture-defined fixed increment.
}

func decodeARM64RawStructureLane(word uint32) (arm64RawStructureLane, bool) {
	// Advanced SIMD load/store single structure. Q, L, R, opcode, S, size,
	// Rm, Rn, and Rt are decoded below. Bit 23 distinguishes no-offset from
	// post-indexed forms. In the no-offset form Rm is reserved and must be zero.
	if word&0xbf000000 != 0x0d000000 {
		return arm64RawStructureLane{}, false
	}
	post := word&(1<<23) != 0
	postRegister := int(word>>16) & 31
	if !post && postRegister != 0 {
		return arm64RawStructureLane{}, false
	}

	q := int(word>>30) & 1
	s := int(word>>12) & 1
	size := int(word>>10) & 3
	opcode := int(word>>13) & 7
	count := 1 + (int(word>>21) & 1) + 2*(opcode&1)

	elementBits := 0
	lane := 0
	switch opcode >> 1 {
	case 0: // B: index = UInt(Q:S:size)
		elementBits = 8
		lane = q<<3 | s<<2 | size
	case 1: // H: index = UInt(Q:S:size<1>), size<0> is reserved.
		if size&1 != 0 {
			return arm64RawStructureLane{}, false
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
			return arm64RawStructureLane{}, false
		}
	default:
		// opcode<2:1> == 11 is the load-and-replicate family.
		return arm64RawStructureLane{}, false
	}

	return arm64RawStructureLane{
		load:          word&(1<<22) != 0,
		count:         count,
		elementBits:   elementBits,
		lane:          lane,
		firstRegister: int(word) & 31,
		base:          int(word>>5) & 31,
		post:          post,
		postRegister:  postRegister,
	}, true
}

func (c *arm64Ctx) lowerRawStructureLane(form arm64RawStructureLane) error {
	base := Reg(fmt.Sprintf("R%d", form.base))
	if form.base == 31 {
		base = SP
	}
	addr, err := c.loadReg(base)
	if err != nil {
		return err
	}
	arrangement := arm64VectorArrangement{
		elementBits: form.elementBits,
		lanes:       128 / form.elementBits,
	}
	elementBytes := form.elementBits / 8

	for registerOffset := 0; registerOffset < form.count; registerOffset++ {
		reg := Reg(fmt.Sprintf("V%d", (form.firstRegister+registerOffset)%32))
		offset := int64(registerOffset * elementBytes)
		if form.load {
			element, err := c.arm64LoadStructureElement(addr, offset, form.elementBits)
			if err != nil {
				return err
			}
			vector, err := c.loadARM64VectorInteger(reg, arrangement)
			if err != nil {
				return err
			}
			inserted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> %s, i%d %s, i32 %d\n",
				inserted, arrangement.lanes, form.elementBits, vector,
				form.elementBits, element, form.lane)
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
			element, arrangement.lanes, form.elementBits, vector, form.lane)
		if err := c.arm64StoreStructureElement(addr, offset, form.elementBits, "%"+element); err != nil {
			return err
		}
	}

	if !form.post {
		return nil
	}
	increment := c.imm64(int64(form.count * elementBytes))
	if form.postRegister != 31 {
		increment, err = c.loadReg(Reg(fmt.Sprintf("R%d", form.postRegister)))
		if err != nil {
			return err
		}
	}
	return c.arm64UpdatePostIncrement(base, increment)
}
