package plan9asm

import (
	"fmt"
	"strings"
)

type x86BLSKind uint8

const (
	x86BLSIsolate x86BLSKind = iota
	x86BLSMask
	x86BLSReset
)

type x86BLSSpec struct {
	bits  int
	kind  x86BLSKind
	digit byte
}

var x86BLSSpecs = map[Op]x86BLSSpec{
	"BLSIL":   {32, x86BLSIsolate, 3},
	"BLSIQ":   {64, x86BLSIsolate, 3},
	"BLSMSKL": {32, x86BLSMask, 2},
	"BLSMSKQ": {64, x86BLSMask, 2},
	"BLSRL":   {32, x86BLSReset, 1},
	"BLSRQ":   {64, x86BLSReset, 1},
}

type x86BLSForm struct {
	spec                x86BLSSpec
	source, destination Operand
}

// The complete Go Yml,Yrl family uses VEX.LZ/0F38/F3. W is ignored in
// mode32; retain the original Q spelling, but consume its physical width.
func x86BLSProperties(op Op, ins Instr, arch string) (x86BLSForm, bool, error) {
	name, _, dotted := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := x86BLSSpecs[Op(name)]
	form := x86BLSForm{spec: spec}
	if !known {
		return form, false, nil
	}
	fail := func() (x86BLSForm, bool, error) {
		return form, true, fmt.Errorf("%s %s outside complete Go BLS grammar: %q", arch, op, ins.Raw)
	}
	if arch != "386" && arch != "amd64" || dotted || len(ins.Args) != 2 ||
		ins.Op != "" && !strings.EqualFold(string(ins.Op), name) {
		return fail()
	}
	if arch == "386" {
		form.spec.bits = 32
	}
	form.source, form.destination = ins.Args[0], ins.Args[1]
	if form.source.Kind == OpReg {
		if !isX86YrlRegisterForArch(form.source.Reg, arch) {
			return fail()
		}
	} else if !isAMD64MemoryOperand(form.source) || !x86PackedShiftMemoryValid(form.source, arch) ||
		x86NamedMultiplyMemoryError(form.source, arch) != nil {
		return fail()
	}
	if form.destination.Kind != OpReg || !isX86YrlRegisterForArch(form.destination.Reg, arch) {
		return fail()
	}
	return form, true, nil
}

func x86TypedBLSByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	form, known, err := x86BLSProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	width := int64(form.spec.bits / 8)
	return x86TypedByteEffect{
		operands: []x86TypedByteOperand{
			{index: 0, operand: form.source, width: width, read: true},
			{index: 1, operand: form.destination, width: width, write: true},
		},
		flagsDefined:        x86ByteFlagCF | x86ByteFlagOF | x86ByteFlagZF | x86ByteFlagSF,
		flagsKilled:         x86ByteFlagsAll,
		requiresResultProof: true,
	}, true, nil
}

// Only the paired exact-width volatile emitter consumes this continuation.
// This creates no pointee, caller, frame or raw-entry capability.
func x86LoweredBLSNativeRead(ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) (bool, bool) {
	form, known, err := x86BLSProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	if form.source.Kind != OpMem || form.source.Mem.Sym != "" {
		return false, false
	}
	width := int64(form.spec.bits / 8)
	if !x86ResultReadWithNativeContinuation(ins, form.source, width, state, owned, arch, true) ||
		!x86ResultStore(form.destination, width, state, owned, resultOffset, arch) {
		return false, true
	}
	effect, _, _ := x86TypedBLSByteEffect(ins.Op, ins, arch)
	state.flags = state.flags&^effect.flagsKilled | effect.flagsDefined
	return true, true
}

func (c *amd64Ctx) evalBLSSource(ins Instr, form x86BLSForm, typ LLVMType) (string, error) {
	if form.source.Kind == OpFP && x86ResultNamedPredicateInstruction(ins) {
		if value, handled, err := c.loadIntegerFPBytesMode(form.source.FPOffset, typ, true); handled || err != nil {
			return value, err
		}
	}
	if isAMD64MemoryOperand(form.source) && form.source.Kind != OpFP &&
		(x86OrdinaryNativeMemoryOperand(form.source, c.goarch) ||
			x86CallerMemoryCertified(ins, 0) || c.fixedLocalMemoryCertified(ins, 0)) {
		if ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride {
			return "", fmt.Errorf("%w: BLS needs its original native address size", ErrProbeNeedsContext)
		}
		pointer, pointerType, _, err := c.packedVectorMemoryPointer(form.source)
		if err != nil {
			return "", err
		}
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load volatile %s, %s %s, align 1\n", value, typ, pointerType, pointer)
		return "%" + value, nil
	}
	return c.evalIntSized(form.source, typ)
}
