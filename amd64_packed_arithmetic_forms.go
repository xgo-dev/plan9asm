package plan9asm

import (
	"fmt"
	"strings"
)

type x86PackedArithmeticFamily uint8

const (
	x86PackedArithmeticAdd x86PackedArithmeticFamily = 1 << iota
	x86PackedArithmeticSubtract
	x86PackedArithmeticLowMultiply
)

type x86PackedArithmeticMode uint8

const (
	x86PackedWrap x86PackedArithmeticMode = iota
	x86PackedSignedSaturating
	x86PackedUnsignedSaturating
)

type x86PackedArithmeticSpec struct {
	x86PackedBinarySpec
	laneBits int
	family   x86PackedArithmeticFamily
	mode     x86PackedArithmeticMode
}

// One catalog owns all add/sub/DQ-low-product source spellings. Width, encoding,
// saturation and broadcast are independent axes constrained by Go's tables.
// PADDD aliases PADDL; word products retain their separate MMX grammar.
var x86PackedArithmeticSpecs = map[Op]x86PackedArithmeticSpec{
	"PADDB":    {x86PackedBinarySpec{encoding: x86PackedLogicalLegacyInteger}, 8, x86PackedArithmeticAdd, x86PackedWrap},
	"PADDW":    {x86PackedBinarySpec{encoding: x86PackedLogicalLegacyInteger}, 16, x86PackedArithmeticAdd, x86PackedWrap},
	"PADDL":    {x86PackedBinarySpec{encoding: x86PackedLogicalLegacyInteger}, 32, x86PackedArithmeticAdd, x86PackedWrap},
	"PADDD":    {x86PackedBinarySpec{encoding: x86PackedLogicalLegacyInteger}, 32, x86PackedArithmeticAdd, x86PackedWrap},
	"PADDQ":    {x86PackedBinarySpec{encoding: x86PackedLogicalLegacyFP}, 64, x86PackedArithmeticAdd, x86PackedWrap},
	"PADDSB":   {x86PackedBinarySpec{encoding: x86PackedLogicalLegacyInteger}, 8, x86PackedArithmeticAdd, x86PackedSignedSaturating},
	"PADDSW":   {x86PackedBinarySpec{encoding: x86PackedLogicalLegacyInteger}, 16, x86PackedArithmeticAdd, x86PackedSignedSaturating},
	"PADDUSB":  {x86PackedBinarySpec{encoding: x86PackedLogicalLegacyInteger}, 8, x86PackedArithmeticAdd, x86PackedUnsignedSaturating},
	"PADDUSW":  {x86PackedBinarySpec{encoding: x86PackedLogicalLegacyInteger}, 16, x86PackedArithmeticAdd, x86PackedUnsignedSaturating},
	"VPADDB":   {x86PackedBinarySpec{encoding: x86PackedLogicalVEXOrEVEX, zeroing: true}, 8, x86PackedArithmeticAdd, x86PackedWrap},
	"VPADDW":   {x86PackedBinarySpec{encoding: x86PackedLogicalVEXOrEVEX, zeroing: true}, 16, x86PackedArithmeticAdd, x86PackedWrap},
	"VPADDD":   {x86PackedBinarySpec{encoding: x86PackedLogicalVEXOrEVEX, broadcastBytes: 4, zeroing: true}, 32, x86PackedArithmeticAdd, x86PackedWrap},
	"VPADDQ":   {x86PackedBinarySpec{encoding: x86PackedLogicalVEXOrEVEX, broadcastBytes: 8, zeroing: true}, 64, x86PackedArithmeticAdd, x86PackedWrap},
	"VPADDSB":  {x86PackedBinarySpec{encoding: x86PackedLogicalVEXOrEVEX, zeroing: true}, 8, x86PackedArithmeticAdd, x86PackedSignedSaturating},
	"VPADDSW":  {x86PackedBinarySpec{encoding: x86PackedLogicalVEXOrEVEX, zeroing: true}, 16, x86PackedArithmeticAdd, x86PackedSignedSaturating},
	"VPADDUSB": {x86PackedBinarySpec{encoding: x86PackedLogicalVEXOrEVEX, zeroing: true}, 8, x86PackedArithmeticAdd, x86PackedUnsignedSaturating},
	"VPADDUSW": {x86PackedBinarySpec{encoding: x86PackedLogicalVEXOrEVEX, zeroing: true}, 16, x86PackedArithmeticAdd, x86PackedUnsignedSaturating},

	"PSUBB":    {x86PackedBinarySpec{encoding: x86PackedLogicalLegacyFP}, 8, x86PackedArithmeticSubtract, x86PackedWrap},
	"PSUBW":    {x86PackedBinarySpec{encoding: x86PackedLogicalLegacyFP}, 16, x86PackedArithmeticSubtract, x86PackedWrap},
	"PSUBL":    {x86PackedBinarySpec{encoding: x86PackedLogicalLegacyFP}, 32, x86PackedArithmeticSubtract, x86PackedWrap},
	"PSUBQ":    {x86PackedBinarySpec{encoding: x86PackedLogicalLegacyFP}, 64, x86PackedArithmeticSubtract, x86PackedWrap},
	"PSUBSB":   {x86PackedBinarySpec{encoding: x86PackedLogicalLegacyFP}, 8, x86PackedArithmeticSubtract, x86PackedSignedSaturating},
	"PSUBSW":   {x86PackedBinarySpec{encoding: x86PackedLogicalLegacyFP}, 16, x86PackedArithmeticSubtract, x86PackedSignedSaturating},
	"PSUBUSB":  {x86PackedBinarySpec{encoding: x86PackedLogicalLegacyFP}, 8, x86PackedArithmeticSubtract, x86PackedUnsignedSaturating},
	"PSUBUSW":  {x86PackedBinarySpec{encoding: x86PackedLogicalLegacyFP}, 16, x86PackedArithmeticSubtract, x86PackedUnsignedSaturating},
	"VPSUBB":   {x86PackedBinarySpec{encoding: x86PackedLogicalVEXOrEVEX, zeroing: true}, 8, x86PackedArithmeticSubtract, x86PackedWrap},
	"VPSUBW":   {x86PackedBinarySpec{encoding: x86PackedLogicalVEXOrEVEX, zeroing: true}, 16, x86PackedArithmeticSubtract, x86PackedWrap},
	"VPSUBD":   {x86PackedBinarySpec{encoding: x86PackedLogicalVEXOrEVEX, broadcastBytes: 4, zeroing: true}, 32, x86PackedArithmeticSubtract, x86PackedWrap},
	"VPSUBQ":   {x86PackedBinarySpec{encoding: x86PackedLogicalVEXOrEVEX, broadcastBytes: 8, zeroing: true}, 64, x86PackedArithmeticSubtract, x86PackedWrap},
	"VPSUBSB":  {x86PackedBinarySpec{encoding: x86PackedLogicalVEXOrEVEX, zeroing: true}, 8, x86PackedArithmeticSubtract, x86PackedSignedSaturating},
	"VPSUBSW":  {x86PackedBinarySpec{encoding: x86PackedLogicalVEXOrEVEX, zeroing: true}, 16, x86PackedArithmeticSubtract, x86PackedSignedSaturating},
	"VPSUBUSB": {x86PackedBinarySpec{encoding: x86PackedLogicalVEXOrEVEX, zeroing: true}, 8, x86PackedArithmeticSubtract, x86PackedUnsignedSaturating},
	"VPSUBUSW": {x86PackedBinarySpec{encoding: x86PackedLogicalVEXOrEVEX, zeroing: true}, 16, x86PackedArithmeticSubtract, x86PackedUnsignedSaturating},

	"PMULLD":  {x86PackedBinarySpec{encoding: x86PackedLogicalLegacyFP}, 32, x86PackedArithmeticLowMultiply, x86PackedWrap},
	"VPMULLD": {x86PackedBinarySpec{encoding: x86PackedLogicalVEXOrEVEX, broadcastBytes: 4, zeroing: true}, 32, x86PackedArithmeticLowMultiply, x86PackedWrap},
	"VPMULLQ": {x86PackedBinarySpec{encoding: x86PackedLogicalEVEX, broadcastBytes: 8, zeroing: true}, 64, x86PackedArithmeticLowMultiply, x86PackedWrap},
}

type x86PackedArithmeticForm struct {
	x86PackedBinaryForm
	spec x86PackedArithmeticSpec
}

func x86PackedArithmeticSpecForOp(op Op, families x86PackedArithmeticFamily) (x86PackedArithmeticSpec, bool) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := x86PackedArithmeticSpecs[Op(base)]
	if !known || families != 0 && spec.family&families == 0 {
		return x86PackedArithmeticSpec{}, false
	}
	return spec, true
}

func x86PackedArithmeticProperties(op Op, ins Instr, arch string, families x86PackedArithmeticFamily) (x86PackedArithmeticForm, bool, error) {
	spec, known := x86PackedArithmeticSpecForOp(op, families)
	if !known {
		return x86PackedArithmeticForm{}, false, nil
	}
	return x86PackedArithmeticFormForSpec(op, ins, arch, spec)
}

// A validated shape supplies no initialized values, storage or caller facts.
// Legacy bank projection and decoder-only mode32 adaptation remain distinct.
func x86PackedArithmeticFormForSpec(op Op, ins Instr, arch string, spec x86PackedArithmeticSpec) (x86PackedArithmeticForm, bool, error) {
	low := spec.family == x86PackedArithmeticLowMultiply
	if ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		family := "arithmetic"
		if low {
			family = "low multiply"
		}
		return x86PackedArithmeticForm{}, true, fmt.Errorf("packed %s dispatch/source opcode mismatch: %s/%s", family, op, ins.Op)
	}
	if !low && (spec.encoding == x86PackedLogicalLegacyFP || spec.encoding == x86PackedLogicalLegacyInteger) {
		legacy, _, err := x86LegacyIntegerArithmeticProperties(op, ins, arch)
		if err == nil && spec.family == x86PackedArithmeticAdd {
			err = x86LegacyIntegerArithmeticEmitterContext(legacy, ins)
		}
		return x86PackedArithmeticForm{legacy.x86PackedBinaryForm, spec}, true, err
	}
	local := ins
	local.Op = op
	grammarArch := arch
	if low && arch == "386" && local.x86Encoded && spec.encoding != x86PackedLogicalLegacyFP {
		// Only the decoder owns this physical identity, not Go's named frontend.
		grammarArch = "amd64"
	}
	binary, err := x86PackedBinaryProperties(local, grammarArch, spec.x86PackedBinarySpec)
	if err == nil && grammarArch != arch && binary.memory >= 0 && !x86PackedShiftMemoryValid(local.Args[binary.memory], arch) {
		err = fmt.Errorf("386 %s physical source has an unbound address", op)
	}
	if err == nil {
		err = x86Mode32VectorRegisterContext(local, arch)
	}
	if err == nil && low && binary.memory >= 0 && (ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride) {
		err = fmt.Errorf("%w: packed low multiply has no bound address-size override", ErrProbeNeedsContext)
	}
	return x86PackedArithmeticForm{binary, spec}, true, err
}
