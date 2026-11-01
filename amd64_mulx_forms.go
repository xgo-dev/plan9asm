package plan9asm

import (
	"fmt"
	"strings"
)

type x86MULXForm struct {
	bits              int
	source, low, high Operand
}

var x86MULXWidths = map[Op]int{"MULXL": 32, "MULXQ": 64}

// Go's complete _yandnl shape is shared with ANDN/PDEP/PEXT, but MULX
// reads implicit DX and writes two destinations without touching FLAGS.
func x86MULXProperties(op Op, ins Instr, arch string) (x86MULXForm, bool, error) {
	name, _, dotted := strings.Cut(strings.ToUpper(string(op)), ".")
	bits, known := x86MULXWidths[Op(name)]
	form := x86MULXForm{bits: bits}
	if !known {
		return form, false, nil
	}
	if arch == "" {
		arch = "amd64"
	}
	fail := func() (x86MULXForm, bool, error) {
		return form, true, fmt.Errorf("%s %s outside Go MULX _yandnl grammar: %q", arch, op, ins.Raw)
	}
	if arch != "amd64" && arch != "386" || dotted || len(ins.Args) != 3 ||
		ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return fail()
	}
	form.source, form.low, form.high = ins.Args[0], ins.Args[1], ins.Args[2]
	for _, output := range []Operand{form.low, form.high} {
		if output.Kind != OpReg || !isX86YrlRegisterForArch(output.Reg, arch) {
			return fail()
		}
	}
	if form.source.Kind == OpReg {
		if !isX86YrlRegisterForArch(form.source.Reg, arch) {
			return fail()
		}
	} else if !x86ScalarCompareMemoryValid(form.source, arch) {
		return fail()
	}
	if arch == "386" && bits == 64 {
		// Go accepts the name, but physical VEX.WIG is dword. The default
		// raw decoder keeps its existing W1 rejection; a PC observer cannot
		// supply an ordinary qword source role.
		return form, true, fmt.Errorf("%w: mode32 MULXQ needs its physical WIG source role", ErrProbeNeedsContext)
	}
	return form, true, nil
}

func x86TypedMULXByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	if !x86ResultNamedPredicateInstruction(ins) {
		return x86TypedByteEffect{}, false, nil
	}
	form, known, err := x86MULXProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	width := int64(form.bits / 8)
	return x86TypedByteEffect{operands: []x86TypedByteOperand{
		{index: 0, operand: form.source, width: width, read: true},
		{index: -1, operand: Operand{Kind: OpReg, Reg: DX}, width: width, read: true},
		{index: 1, operand: form.low, width: width, write: true},
		{index: 2, operand: form.high, width: width, write: true},
	}}, true, nil
}

func x86RawMULXSource(ins Instr, arch string) bool {
	_, known, err := x86MULXProperties(ins.Op, ins, arch)
	return known && err == nil && x86RawOrdinaryVectorSource(ins, arch)
}

func (form x86MULXForm) needsNativeProof(ins Instr, arch string) bool {
	_, static := x86SBMemoryAddressRole(form.source, arch)
	frameSource := form.source.Kind == OpMem && !static &&
		(x86LogicalSourceFrameRegister(form.source.Mem.Base, arch) || x86LogicalSourceFrameRegister(form.source.Mem.Index, arch))
	return !x86ResultNamedPredicateInstruction(ins) || x86RegisterAddressedNativeMemoryOperand(form.source, arch) ||
		frameSource || x86LogicalSourceFrameRegister(form.low.Reg, arch) || x86LogicalSourceFrameRegister(form.high.Reg, arch)
}

func x86LoweredMULXResultStep(ins Instr, state *x86ResultState, owned []bool,
	resultOffset int64, arch string) (bool, bool) {
	form, known, err := x86MULXProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	local := ins
	if !x86ResultNamedPredicateInstruction(ins) {
		if !x86RawMULXSource(ins, arch) {
			return false, true
		}
		local.x86Encoded, local.x86SourceRaw = false, nil
	}
	if !x86RegisterAddressedNativeMemoryOperand(form.source, arch) {
		next := state.clone()
		next.loweredStaticReads, next.goReadOnlyRead = state.loweredStaticReads, state.goReadOnlyRead
		if x86ResultTransfer(local, &next, owned, resultOffset, arch) {
			*state = next
			return true, true
		}
		if form.needsNativeProof(ins, arch) {
			return false, true // Raw, physical-frame and native roles retain their strict input contract.
		}
		return x86MULXUnknownNumericalResults(local, state, owned, arch), true
	}
	effect, _, _ := x86TypedMULXByteEffect(local.Op, local, arch)
	// Consume both the effective address and numerical DX before replacing
	// either destination. An opaque DX address is not a numerical DX value.
	for _, input := range effect.operands {
		if input.read && !x86ResultReadWithNativeContinuation(local, input.operand, input.width, state, owned, arch, true) {
			return false, true
		}
	}
	for _, output := range effect.operands {
		if output.write && !x86ResultStore(output.operand, output.width, state, owned, resultOffset, arch) {
			return false, true
		}
	}
	return true, true
}

// Only the existing named, non-native, nontrapping numerical domain may
// leave scratch products unknown. Readable storage and pointer/NUM roles remain
// strict; both output dependencies must survive until any observable use.
func x86MULXUnknownNumericalResults(ins Instr, state *x86ResultState, owned []bool, arch string) bool {
	effect, known, err := x86TypedMULXByteEffect(ins.Op, ins, arch)
	if !known || err != nil {
		return false
	}
	unknown := false
	for _, input := range effect.operands {
		if !input.read {
			continue
		}
		if input.operand.Kind != OpReg {
			if !x86ResultRead(input.operand, input.width, state, owned, arch) {
				return false
			}
			continue
		}
		index, mask, valid := x86ResultGP(input.operand.Reg, input.width, arch)
		if !valid || state.pointerGP[index] {
			return false
		}
		unknown = unknown || state.gp[index]&mask != mask
	}
	if !unknown {
		return false // Some other strict failure must never become permission.
	}
	after := *state
	for _, output := range effect.operands {
		if !output.write {
			continue
		}
		index, mask, valid := x86ResultGP(output.operand.Reg, output.width, arch)
		if output.operand.Kind != OpReg || !valid {
			return false
		}
		after.gp[index] &^= mask
		after.canonicalGP[index] &^= mask
		if output.width == 4 {
			after.gp[index] |= 0xf0 // Only architectural upper32 are independently known zero.
			if arch == "amd64" {
				after.canonicalGP[index] |= 0xf0
			}
		}
		after.pointerGP[index] = false
	}
	*state = after
	return true
}

func (c *amd64Ctx) lowerMULX(op Op, ins Instr) (bool, bool, error) {
	form, known, err := x86MULXProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	if err := c.integerEffectResultInitialized("MULX"); err != nil {
		return true, false, err
	}
	return true, false, c.emitMULX(form, ins)
}

// Emission consumes already validated operands; it supplies no numerical,
// address or entry permission. The public lowerer retains those checks above.
func (c *amd64Ctx) emitMULX(form x86MULXForm, ins Instr) error {
	narrow := amd64IntegerTypeForBits(form.bits)
	wide := x86ScalarMultiplyDivideWideType(form.bits)
	source, err := c.evalSizedNativeGPSource(form.source, narrow, ins.x86AddressBits)
	if err != nil {
		return err
	}
	dx, err := c.evalIntSized(Operand{Kind: OpReg, Reg: DX}, narrow)
	if err != nil {
		return err
	}
	lhs := c.extendX86MulDivValue(dx, narrow, wide, false)
	rhs := c.extendX86MulDivValue(source, narrow, wide, false)
	product, low, shifted, high := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = mul %s %s, %s\n", product, wide, lhs, rhs)
	fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to %s\n", low, wide, product, narrow)
	fmt.Fprintf(c.b, "  %%%s = lshr %s %%%s, %d\n", shifted, wide, product, form.bits)
	fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to %s\n", high, wide, shifted, narrow)
	if err := c.storeRegSized(form.low.Reg, narrow, "%"+low); err != nil {
		return err
	}
	return c.storeRegSized(form.high.Reg, narrow, "%"+high)
}
