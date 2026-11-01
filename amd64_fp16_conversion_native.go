package plan9asm

import (
	"fmt"
	"strings"
)

func (c *amd64Ctx) emitNativeFP16Conversion(ins Instr, f x86FP16ConversionForm) error {
	source := ins.Args[0]
	if source.Kind == OpFP || ins.x86AddressBits != 0 || source.Kind == OpMem &&
		!x86OrdinaryNativeMemoryOperand(source, c.goarch) {
		return fmt.Errorf("%w: FP16 conversion needs original native backing", ErrProbeNeedsContext)
	}
	if f.spec.scalar {
		return c.emitNativeFP16ThreeOperand(ins, x86NativeFP16ThreeOperand{
			byteWidth: 16, lanes: 1, memoryBytes: f.memoryBytes, second: f.upper,
			destination: f.destination, mask: f.mask,
			controls: f.controls, sae: f.sae,
		})
	}
	mnemonic, _, _ := strings.Cut(strings.ToLower(string(ins.Op)), ".")
	if source.Kind != OpReg && f.spec.outputBits == 16 && !f.controls.broadcast && f.sourceBytes < 64 {
		mnemonic += map[int]string{16: "x", 32: "y"}[f.sourceBytes]
	}
	return c.emitNativePackedConversion(ins, x86NativePackedConversion{
		byteWidth: f.byteWidth, sourceBytes: f.sourceBytes, memoryBytes: f.memoryBytes,
		outputBits:  32, // Bit carrier only: the original opcode selects FP16/FP32.
		destination: f.destination, mask: f.mask, lanes: f.lanes, evex: true,
		broadcast: f.controls.broadcast, zeroing: f.controls.zeroing,
		rounding: f.controls.rounding, sae: f.sae, mnemonic: mnemonic,
	})
}

// Existing FP16 clients retain their own grammar and source permissions. Only
// the actual native operand transport is shared with other floating families.
type x86NativeFP16ThreeOperand = x86NativeFloatingOperands

func (c *amd64Ctx) emitNativeFP16ThreeOperand(ins Instr, f x86NativeFP16ThreeOperand) error {
	return c.emitNativeFloatingOperands(ins, f)
}
