package plan9asm

import (
	"fmt"
	"strings"
)

type amd64PackedNumericKind uint8

const (
	amd64PackedNumericFloat amd64PackedNumericKind = iota
	amd64PackedNumericSigned
	amd64PackedNumericUnsigned
)

type amd64PackedNumericShape struct {
	sourceBytes      int
	destinationBytes int
	lanes            int
}

type amd64PackedNumericConversionSpec struct {
	sourceKind      amd64PackedNumericKind
	destinationKind amd64PackedNumericKind
	sourceBits      int
	destinationBits int
	truncate        bool
	explicit        string
	shapes          []amd64PackedNumericShape
}

var (
	amd64PackedNumericSame32 = []amd64PackedNumericShape{
		{sourceBytes: 16, destinationBytes: 16, lanes: 4},
		{sourceBytes: 32, destinationBytes: 32, lanes: 8},
		{sourceBytes: 64, destinationBytes: 64, lanes: 16},
	}
	amd64PackedNumericSame64 = []amd64PackedNumericShape{
		{sourceBytes: 16, destinationBytes: 16, lanes: 2},
		{sourceBytes: 32, destinationBytes: 32, lanes: 4},
		{sourceBytes: 64, destinationBytes: 64, lanes: 8},
	}
	amd64PackedNumericWiden32To64 = []amd64PackedNumericShape{
		{sourceBytes: 16, destinationBytes: 16, lanes: 2},
		{sourceBytes: 16, destinationBytes: 32, lanes: 4},
		{sourceBytes: 32, destinationBytes: 64, lanes: 8},
	}
)

// amd64PackedNumericConversionSpecs describes the complete Go 1.27 EVEX
// packed numeric-conversion family not covered by the legacy/VEX conversion
// handlers. Source/destination element types and physical width shapes remain
// independent axes, avoiding one lowerer per mnemonic and register width.
var amd64PackedNumericConversionSpecs = map[Op]amd64PackedNumericConversionSpec{
	"VCVTPD2QQ":    {sourceKind: amd64PackedNumericFloat, destinationKind: amd64PackedNumericSigned, sourceBits: 64, destinationBits: 64, explicit: "round", shapes: amd64PackedNumericSame64},
	"VCVTPD2UQQ":   {sourceKind: amd64PackedNumericFloat, destinationKind: amd64PackedNumericUnsigned, sourceBits: 64, destinationBits: 64, explicit: "round", shapes: amd64PackedNumericSame64},
	"VCVTTPD2QQ":   {sourceKind: amd64PackedNumericFloat, destinationKind: amd64PackedNumericSigned, sourceBits: 64, destinationBits: 64, truncate: true, explicit: "sae", shapes: amd64PackedNumericSame64},
	"VCVTTPD2UQQ":  {sourceKind: amd64PackedNumericFloat, destinationKind: amd64PackedNumericUnsigned, sourceBits: 64, destinationBits: 64, truncate: true, explicit: "sae", shapes: amd64PackedNumericSame64},
	"VCVTPS2UDQ":   {sourceKind: amd64PackedNumericFloat, destinationKind: amd64PackedNumericUnsigned, sourceBits: 32, destinationBits: 32, explicit: "round", shapes: amd64PackedNumericSame32},
	"VCVTTPS2UDQ":  {sourceKind: amd64PackedNumericFloat, destinationKind: amd64PackedNumericUnsigned, sourceBits: 32, destinationBits: 32, truncate: true, explicit: "sae", shapes: amd64PackedNumericSame32},
	"VCVTUDQ2PS":   {sourceKind: amd64PackedNumericUnsigned, destinationKind: amd64PackedNumericFloat, sourceBits: 32, destinationBits: 32, explicit: "round", shapes: amd64PackedNumericSame32},
	"VCVTQQ2PD":    {sourceKind: amd64PackedNumericSigned, destinationKind: amd64PackedNumericFloat, sourceBits: 64, destinationBits: 64, explicit: "round", shapes: amd64PackedNumericSame64},
	"VCVTUQQ2PD":   {sourceKind: amd64PackedNumericUnsigned, destinationKind: amd64PackedNumericFloat, sourceBits: 64, destinationBits: 64, explicit: "round", shapes: amd64PackedNumericSame64},
	"VCVTPS2QQ":    {sourceKind: amd64PackedNumericFloat, destinationKind: amd64PackedNumericSigned, sourceBits: 32, destinationBits: 64, explicit: "round", shapes: amd64PackedNumericWiden32To64},
	"VCVTPS2UQQ":   {sourceKind: amd64PackedNumericFloat, destinationKind: amd64PackedNumericUnsigned, sourceBits: 32, destinationBits: 64, explicit: "round", shapes: amd64PackedNumericWiden32To64},
	"VCVTTPS2QQ":   {sourceKind: amd64PackedNumericFloat, destinationKind: amd64PackedNumericSigned, sourceBits: 32, destinationBits: 64, truncate: true, explicit: "sae", shapes: amd64PackedNumericWiden32To64},
	"VCVTTPS2UQQ":  {sourceKind: amd64PackedNumericFloat, destinationKind: amd64PackedNumericUnsigned, sourceBits: 32, destinationBits: 64, truncate: true, explicit: "sae", shapes: amd64PackedNumericWiden32To64},
	"VCVTUDQ2PD":   {sourceKind: amd64PackedNumericUnsigned, destinationKind: amd64PackedNumericFloat, sourceBits: 32, destinationBits: 64, shapes: amd64PackedNumericWiden32To64},
	"VCVTPD2UDQX":  {sourceKind: amd64PackedNumericFloat, destinationKind: amd64PackedNumericUnsigned, sourceBits: 64, destinationBits: 32, shapes: []amd64PackedNumericShape{{sourceBytes: 16, destinationBytes: 16, lanes: 2}}},
	"VCVTPD2UDQY":  {sourceKind: amd64PackedNumericFloat, destinationKind: amd64PackedNumericUnsigned, sourceBits: 64, destinationBits: 32, shapes: []amd64PackedNumericShape{{sourceBytes: 32, destinationBytes: 16, lanes: 4}}},
	"VCVTPD2UDQ":   {sourceKind: amd64PackedNumericFloat, destinationKind: amd64PackedNumericUnsigned, sourceBits: 64, destinationBits: 32, explicit: "round", shapes: []amd64PackedNumericShape{{sourceBytes: 64, destinationBytes: 32, lanes: 8}}},
	"VCVTTPD2UDQX": {sourceKind: amd64PackedNumericFloat, destinationKind: amd64PackedNumericUnsigned, sourceBits: 64, destinationBits: 32, truncate: true, shapes: []amd64PackedNumericShape{{sourceBytes: 16, destinationBytes: 16, lanes: 2}}},
	"VCVTTPD2UDQY": {sourceKind: amd64PackedNumericFloat, destinationKind: amd64PackedNumericUnsigned, sourceBits: 64, destinationBits: 32, truncate: true, shapes: []amd64PackedNumericShape{{sourceBytes: 32, destinationBytes: 16, lanes: 4}}},
	"VCVTTPD2UDQ":  {sourceKind: amd64PackedNumericFloat, destinationKind: amd64PackedNumericUnsigned, sourceBits: 64, destinationBits: 32, truncate: true, explicit: "sae", shapes: []amd64PackedNumericShape{{sourceBytes: 64, destinationBytes: 32, lanes: 8}}},
	"VCVTQQ2PSX":   {sourceKind: amd64PackedNumericSigned, destinationKind: amd64PackedNumericFloat, sourceBits: 64, destinationBits: 32, shapes: []amd64PackedNumericShape{{sourceBytes: 16, destinationBytes: 16, lanes: 2}}},
	"VCVTQQ2PSY":   {sourceKind: amd64PackedNumericSigned, destinationKind: amd64PackedNumericFloat, sourceBits: 64, destinationBits: 32, shapes: []amd64PackedNumericShape{{sourceBytes: 32, destinationBytes: 16, lanes: 4}}},
	"VCVTQQ2PS":    {sourceKind: amd64PackedNumericSigned, destinationKind: amd64PackedNumericFloat, sourceBits: 64, destinationBits: 32, explicit: "round", shapes: []amd64PackedNumericShape{{sourceBytes: 64, destinationBytes: 32, lanes: 8}}},
	"VCVTUQQ2PSX":  {sourceKind: amd64PackedNumericUnsigned, destinationKind: amd64PackedNumericFloat, sourceBits: 64, destinationBits: 32, shapes: []amd64PackedNumericShape{{sourceBytes: 16, destinationBytes: 16, lanes: 2}}},
	"VCVTUQQ2PSY":  {sourceKind: amd64PackedNumericUnsigned, destinationKind: amd64PackedNumericFloat, sourceBits: 64, destinationBits: 32, shapes: []amd64PackedNumericShape{{sourceBytes: 32, destinationBytes: 16, lanes: 4}}},
	"VCVTUQQ2PS":   {sourceKind: amd64PackedNumericUnsigned, destinationKind: amd64PackedNumericFloat, sourceBits: 64, destinationBits: 32, explicit: "round", shapes: []amd64PackedNumericShape{{sourceBytes: 64, destinationBytes: 32, lanes: 8}}},
}

func (c *amd64Ctx) lowerPackedNumericConversion(op Op, ins Instr) (bool, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	if _, known := x86PackedConversionSpecification(Op(base)); !known {
		return false, false, nil
	}
	if !strings.EqualFold(string(op), string(ins.Op)) {
		return true, false, fmt.Errorf("packed conversion dispatch/source mismatch: %s/%s", op, ins.Op)
	}
	form, _, err := x86PackedConversionProperties(ins, c.goarch)
	if err != nil {
		return true, false, err
	}
	if form.mmx || !x86ScalarFloatIntegerNativeTarget(c.goarch, c.targetTriple) {
		return true, false, fmt.Errorf("%w: packed conversion lacks native target or physical MMX/x87 caller contract", ErrProbeNeedsContext)
	}
	source := ins.Args[0]
	if source.Kind == OpFP {
		if err := c.validateFPVectorSpan(source.FPOffset, form.memoryBytes); err != nil {
			return true, false, err
		}
		return true, false, fmt.Errorf("%w: packed FP conversion source lacks original native backing", ErrProbeNeedsContext)
	}
	if ins.x86AddressBits != 0 || source.Kind == OpMem &&
		!x86OrdinaryNativeMemoryOperand(source, c.goarch) && !c.fixedLocalMemoryCertified(ins, form.memory) {
		return true, false, fmt.Errorf("%w: packed conversion lacks original native address binding", ErrProbeNeedsContext)
	}
	base = strings.ToLower(base)
	mnemonic := strings.TrimSuffix(strings.TrimSuffix(base, "x"), "y")
	if form.spec.legacy {
		mnemonic = strings.ReplaceAll(base, "pl", "dq")
	}
	// Narrowing memory leaves X/Y source length ambiguous to an assembler:
	// encode the source vector length, not the destination carrier width.
	if form.memory >= 0 && !form.spec.legacy && !form.properties.broadcast &&
		form.spec.sourceBits > form.spec.destinationBits && form.shape.sourceBytes < 64 {
		mnemonic += map[int]string{16: "x", 32: "y"}[form.shape.sourceBytes]
	}
	return true, false, c.emitNativePackedConversion(ins, x86NativePackedConversion{
		byteWidth: form.shape.destinationBytes, sourceBytes: form.shape.sourceBytes,
		memoryBytes: form.memoryBytes, outputBits: form.spec.destinationBits,
		lanes:       form.shape.lanes,
		destination: form.destination, mask: form.mask, legacy: form.spec.legacy, evex: form.evex,
		broadcast: form.properties.broadcast, zeroing: form.properties.zeroing,
		rounding: form.properties.rounding, sae: form.properties.sae, mnemonic: mnemonic,
	})
}

func (c *amd64Ctx) packedNumericRoundingMode(rounding string) string {
	switch rounding {
	case "RN_SAE":
		return "0"
	case "RD_SAE":
		return "1"
	case "RU_SAE":
		return "2"
	case "RZ_SAE":
		return "3"
	default:
		mxcsr := c.loadMXCSR()
		shifted, mode := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr i32 %s, 13\n", shifted, mxcsr)
		fmt.Fprintf(c.b, "  %%%s = and i32 %%%s, 3\n", mode, shifted)
		return "%" + mode
	}
}
