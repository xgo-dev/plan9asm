package plan9asm

import "fmt"

type arm64UnprivilegedTransferOp struct {
	mnemonic string
	bank     byte
}

// Indexed by size and opc. A register bank selects the architectural
// extension width independently of the bytes transferred in memory.
var arm64UnprivilegedTransferOps = [4][4]arm64UnprivilegedTransferOp{
	{{"sttrb", 'w'}, {"ldtrb", 'w'}, {"ldtrsb", 'x'}, {"ldtrsb", 'w'}},
	{{"sttrh", 'w'}, {"ldtrh", 'w'}, {"ldtrsh", 'x'}, {"ldtrsh", 'w'}},
	{{"sttr", 'w'}, {"ldtr", 'w'}, {"ldtrsw", 'x'}, {}},
	{{"sttr", 'x'}, {"ldtr", 'x'}, {}, {}},
}

type arm64UnprivilegedTransfer struct {
	op         arm64UnprivilegedTransferOp
	base, data int
	bytes      int
	offset     int64
	store      bool
}

func decodeARM64RawUnprivilegedTransfer(word uint32) (arm64UnprivilegedTransfer, bool) {
	if word&0x3f200c00 != 0x38000800 {
		return arm64UnprivilegedTransfer{}, false
	}
	size, opc := word>>30, word>>22&3
	op := arm64UnprivilegedTransferOps[size][opc]
	if op.mnemonic == "" {
		return arm64UnprivilegedTransfer{}, false
	}
	return arm64UnprivilegedTransfer{
		op: op, base: int(word >> 5 & 31), data: int(word & 31),
		bytes: 1 << size, offset: int64(int32(word<<11) >> 23), store: opc == 0,
	}, true
}

func (f arm64UnprivilegedTransfer) effects() arm64RawContinuationEffects {
	effects := arm64RawContinuationEffects{gpReads: arm64RawGPBit(f.base), readsSP: f.base == 31, stores: f.store}
	if f.store {
		effects.gpReads |= arm64RawGPBit(f.data)
	} else {
		effects.gpWrites = arm64RawGPBit(f.data)
	}
	return effects
}

func (f arm64UnprivilegedTransfer) baseRegister() Reg {
	if f.base == 31 {
		return SP
	}
	return Reg(fmt.Sprintf("R%d", f.base))
}

func (f arm64UnprivilegedTransfer) dataRegister() Reg {
	if f.data == 31 {
		return ZR
	}
	return Reg(fmt.Sprintf("R%d", f.data))
}

func (f arm64UnprivilegedTransfer) privateMemory() arm64RawPrivateMemoryForm {
	return arm64RawPrivateMemoryForm{
		memory:    Operand{Kind: OpMem, Mem: MemRef{Base: f.baseRegister(), Off: f.offset}},
		registers: []Reg{f.dataRegister()}, elementBytes: int64(f.bytes),
		store: f.store, gp: true,
	}
}

func (c *arm64Ctx) lowerARM64UnprivilegedTransfer(f arm64UnprivilegedTransfer) error {
	if f.base == 31 {
		// Rn=31 checks physical SP alignment and disables address tag checks.
		// Passing a shadow stack address in a GP register changes both rules.
		return fmt.Errorf("%w: ARM64 %s with SP requires a physical stack address", ErrProbeNeedsContext, f.op.mnemonic)
	}
	if !arm64ScalarConversionNativeTarget(c.targetTriple) {
		return fmt.Errorf("%w: ARM64 %s requires a native little-endian AArch64 target", ErrProbeNeedsContext, f.op.mnemonic)
	}
	base, err := c.loadReg(f.baseRegister())
	if err != nil {
		return err
	}
	assembly := fmt.Sprintf("%s ${0:%c}, [${1:x}, #%d]", f.op.mnemonic, f.op.bank, f.offset)
	if f.data == 31 {
		// A discard still performs the read and may fault. Encoding Rt=31
		// directly also preserves a zero source for stores.
		assembly = fmt.Sprintf("%s %czr, [${0:x}, #%d]", f.op.mnemonic, f.op.bank, f.offset)
		emit := c.emitMachineNeutralNativeIR
		if f.store {
			emit = c.emitMachineStoreNativeIR
		}
		emit("  call void asm sideeffect %q, %q(i64 %s)\n", assembly, "r,~{memory}", base)
		return nil
	}
	if f.store {
		value, err := c.loadRegisterWidth(f.dataRegister(), 8*f.bytes)
		if err != nil {
			return err
		}
		c.emitMachineStoreNativeIR("  call void asm sideeffect %q, %q(i64 %s, i64 %s)\n",
			assembly, "r,r,~{memory}", value, base)
		return nil
	}
	// A W output is a write to all 64 bits, with the high 32 cleared.
	result := c.newTmp()
	c.emitMachineNeutralNativeIR("  %%%s = call i64 asm sideeffect %q, %q(i64 %s)\n",
		result, assembly, "=r,r,~{memory}", base)
	return c.storeReg(f.dataRegister(), "%"+result)
}
