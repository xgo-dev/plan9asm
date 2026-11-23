package plan9asm

import "fmt"

type arm64NonTemporalPairView struct {
	typ   string
	bank  string
	bytes int
	simd  bool
}

var arm64NonTemporalPairViews = [2][4]arm64NonTemporalPairView{
	{
		0: {typ: "i32", bank: "w", bytes: 4},
		2: {typ: "i64", bank: "x", bytes: 8},
	},
	{
		0: {typ: "float", bank: "s", bytes: 4, simd: true},
		1: {typ: "double", bank: "d", bytes: 8, simd: true},
		2: {typ: "<16 x i8>", bank: "q", bytes: 16, simd: true},
	},
}

type arm64NonTemporalPair struct {
	view      arm64NonTemporalPairView
	load      bool
	base      int
	registers [2]int
	offset    int64
}

// LDNP and STNP are WORD-only in Go. This is the signed-offset instruction
// class, with reserved widths and constrained-unpredictable load overlap
// excluded. The adjacent ordinary and writeback pair encodings remain separate.
func decodeARM64RawNonTemporalPair(word uint32) (arm64NonTemporalPair, bool) {
	if word&0x3b800000 != 0x28000000 {
		return arm64NonTemporalPair{}, false
	}
	view := arm64NonTemporalPairViews[word>>26&1][word>>30]
	load := word&(1<<22) != 0
	first, second := int(word&31), int(word>>10&31)
	if view.bytes == 0 || load && first == second {
		return arm64NonTemporalPair{}, false
	}
	return arm64NonTemporalPair{
		view: view, load: load, base: int(word >> 5 & 31),
		registers: [2]int{first, second},
		offset:    int64(int32(word<<10)>>25) * int64(view.bytes),
	}, true
}

func (f arm64NonTemporalPair) effects() arm64RawContinuationEffects {
	effects := arm64RawContinuationEffects{
		gpReads: arm64RawGPBit(f.base), readsSP: f.base == 31, stores: !f.load,
	}
	if !f.view.simd {
		data := arm64RawGPBit(f.registers[0]) | arm64RawGPBit(f.registers[1])
		if f.load {
			effects.gpWrites = data
		} else {
			effects.gpReads |= data
		}
	}
	return effects
}

func (f arm64NonTemporalPair) baseRegister() Reg {
	if f.base == 31 {
		return SP
	}
	return Reg(fmt.Sprintf("R%d", f.base))
}

func (f arm64NonTemporalPair) dataRegister(index int) Reg {
	if f.view.simd {
		return Reg(fmt.Sprintf("F%d", index))
	}
	if index == 31 {
		return ZR
	}
	return Reg(fmt.Sprintf("R%d", index))
}

func (f arm64NonTemporalPair) privateMemory() arm64RawPrivateMemoryForm {
	return arm64RawPrivateMemoryForm{
		memory: Operand{Kind: OpMem, Mem: MemRef{Base: f.baseRegister(), Off: f.offset}},
		registers: []Reg{
			f.dataRegister(f.registers[0]), f.dataRegister(f.registers[1]),
		},
		elementBytes: int64(f.view.bytes), store: !f.load, gp: !f.view.simd,
	}
}

func (c *arm64Ctx) lowerARM64NonTemporalPair(f arm64NonTemporalPair) error {
	if !arm64ScalarConversionNativeTarget(c.targetTriple) {
		return fmt.Errorf("%w: ARM64 non-temporal pairs require a native little-endian AArch64 target", ErrProbeNeedsContext)
	}
	base, err := c.loadReg(f.baseRegister())
	if err != nil {
		return err
	}
	left, right := f.dataRegister(f.registers[0]), f.dataRegister(f.registers[1])
	bank := f.view.bank
	operands := fmt.Sprintf("${0:%s}, ${1:%s}, [$2, #%d]", bank, bank, f.offset)
	if f.load {
		// The native outputs must remain distinct even when one result is
		// dead. Offset addressing permits the base to overlap either output.
		registerBank := bank
		if !f.view.simd {
			registerBank = "x" // LLVM's GP constraint uses the whole register.
		}
		constraints := fmt.Sprintf("={%s0},={%s1},r,~{memory}", registerBank, registerBank)
		pair := fmt.Sprintf("{ %s, %s }", f.view.typ, f.view.typ)
		result := c.newTmp()
		c.emitMachineNeutralNativeIR("  %%%s = call %s asm sideeffect %q, %q(i64 %s)\n",
			result, pair, "ldnp "+operands, constraints, base)
		for index, register := range [2]Reg{left, right} {
			value := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractvalue %s %%%s, %d\n", value, pair, result, index)
			if err := c.storeARM64NonTemporalPairValue(f.view, register, "%"+value); err != nil {
				return err
			}
		}
		return nil
	}

	first, err := c.loadARM64NonTemporalPairValue(f.view, left)
	if err != nil {
		return err
	}
	second, err := c.loadARM64NonTemporalPairValue(f.view, right)
	if err != nil {
		return err
	}
	constraints := "r,r,r,~{memory}"
	if f.view.simd {
		constraints = "w,w,r,~{memory}"
	}
	c.emitMachineStoreNativeIR("  call void asm sideeffect %q, %q(%s %s, %s %s, i64 %s)\n",
		"stnp "+operands, constraints, f.view.typ, first, f.view.typ, second, base)
	return nil
}

func (c *arm64Ctx) loadARM64NonTemporalPairValue(view arm64NonTemporalPairView, reg Reg) (string, error) {
	if view.bytes == 16 {
		return c.loadVReg(reg)
	}
	bits := view.bytes * 8
	if view.simd {
		return c.loadARM64ScalarFloatReg(reg, bits)
	}
	value, err := c.loadRegisterWidth(reg, bits)
	if err != nil || bits == 64 {
		return value, err
	}
	narrow := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", narrow, value)
	return "%" + narrow, nil
}

func (c *arm64Ctx) storeARM64NonTemporalPairValue(view arm64NonTemporalPairView, reg Reg, value string) error {
	if view.bytes == 16 {
		return c.storeVReg(reg, value)
	}
	if view.simd {
		return c.storeARM64ScalarFloatReg(reg, view.bytes*8, value)
	}
	if view.bytes == 4 {
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", wide, value)
		value = "%" + wide
	}
	return c.storeReg(reg, value)
}
