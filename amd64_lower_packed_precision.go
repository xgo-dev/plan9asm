package plan9asm

import (
	"fmt"
	"strings"
)

func (c *amd64Ctx) lowerPackedPrecisionConvert(op Op, ins Instr) (bool, bool, error) {
	form, known, err := x86PackedPrecisionProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	ins.Op = op
	if !x86ScalarFloatIntegerNativeTarget(c.goarch, c.targetTriple) {
		return true, false, fmt.Errorf("%w: %s needs its matching native x86 MXCSR target", ErrProbeNeedsContext, op)
	}
	if c.fpScalarSource.x86SourceStack != nil || c.fpScalarSource.x86FixedLocal != nil {
		return true, false, fmt.Errorf("%w: %s retains its separate source/frame owner", ErrProbeNeedsContext, op)
	}
	source := ins.Args[0]
	if source.Kind == OpFP {
		if err := c.validateX86PackedShiftFPSpan(source.FPOffset, form.memoryBytes); err != nil {
			return true, false, err
		}
		for at := source.FPOffset; at < source.FPOffset+int64(form.memoryBytes); at++ {
			if slot, _, _ := c.fpVectorSlot(at); slot.Type == Ptr {
				return true, false, fmt.Errorf("%w: %s cannot use opaque pointer bits as floating input", ErrProbeNeedsContext, op)
			}
		}
	} else if form.memory >= 0 && !x86OrdinaryNativeMemoryOperand(source, c.goarch) {
		return true, false, fmt.Errorf("%w: %s needs its original native source address", ErrProbeNeedsContext, op)
	}
	base, _, _ := strings.Cut(strings.ToLower(string(op)), ".")
	mnemonic := base
	if base == "vcvtpd2psx" || base == "vcvtpd2psy" {
		mnemonic = "vcvtpd2ps"
		if form.memory >= 0 && source.Kind != OpFP && !form.properties.broadcast {
			// AT&T memory syntax needs the source VL, not the narrower
			// destination carrier, to distinguish X/m128 from Y/m256.
			mnemonic = base
		}
	}
	return true, false, c.emitNativePackedConversion(ins, x86NativePackedConversion{
		byteWidth: form.shape.destinationBytes, sourceBytes: form.shape.sourceBytes,
		memoryBytes: form.memoryBytes, outputBits: form.spec.destinationBits, logicalFPBits: form.spec.sourceBits,
		lanes: form.shape.lanes, destination: form.destination, mask: form.mask,
		legacy: form.spec.legacy, evex: form.evex, broadcast: form.properties.broadcast,
		zeroing: form.properties.zeroing, sae: form.properties.sae, rounding: form.properties.rounding, mnemonic: mnemonic,
	})
}

// Independent scalar FP fields supply only their checked little-endian value
// bytes. Fill unused register-container bytes with private zeros, or replicate
// one declared scalar for a broadcast; never invent a physical FP address.
func (c *amd64Ctx) loadPackedConversionFPValue(source Operand, sourceBytes, memoryBytes, bits int, broadcast bool) (string, error) {
	bytes, err := c.loadFPVectorBytes(source.FPOffset, memoryBytes)
	if err != nil {
		return "", err
	}
	if broadcast {
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to i%d\n", value, memoryBytes, bytes, bits)
		lanes := sourceBytes * 8 / bits
		splat := amd64SplatInteger(c, lanes, bits, "%"+value)
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x float>\n", out, lanes, bits, splat, sourceBytes/4)
		return "%" + out, nil
	}
	if memoryBytes != sourceBytes {
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i8> %s, <%d x i8> zeroinitializer, <%d x i32> %s\n",
			out, memoryBytes, bytes, memoryBytes, sourceBytes, llvmI32RangeMask(0, sourceBytes))
		bytes = "%" + out
	}
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to <%d x float>\n", value, sourceBytes, bytes, sourceBytes/4)
	return "%" + value, nil
}
