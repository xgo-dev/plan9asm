package plan9asm

import "strings"

type x86PackedPhysicalFamily string

const (
	x86PackedAverage      x86PackedPhysicalFamily = "packed average"
	x86PackedWordProduct  x86PackedPhysicalFamily = "packed word multiply"
	x86PackedMultiplyAdd  x86PackedPhysicalFamily = "packed multiply-add"
	x86PackedDwordProduct x86PackedPhysicalFamily = "dword product"
)

// A common shape does not make arithmetic lanes and memory accesses equal.
// Dword products read complete qwords before selecting their low dwords;
// multiply-add reads the full tuple even when all result lanes are masked off.
type x86PackedPhysicalSpec struct {
	x86PackedBinarySpec
	family                            x86PackedPhysicalFamily
	inputBits, outputBits, memoryBits int // memoryBits == 0 means an E4NF full-tuple read.
	mode                              amd64PackedWordMultiplyMode
	signed                            bool
	nativeOpcode                      string
}

type x86PackedPhysicalForm struct {
	x86PackedBinaryForm
	spec   x86PackedPhysicalSpec
	source Operand // Actual physical bank, not an initialized value or storage permission.
}

// The existing four family tables remain the only opcode membership authority.
// Normalize the name once, then share the physical grammar and its typed result
// among consumers; do not cache it on mutable instructions or across analyses.
func x86PackedPhysicalSpecForOp(op Op, family x86PackedPhysicalFamily) (x86PackedPhysicalSpec, bool) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	if spec, known := x86PackedAverageSpecs[Op(base)]; known && (family == "" || family == x86PackedAverage) {
		return x86PackedPhysicalSpec{
			x86PackedBinarySpec: spec.x86PackedBinarySpec, family: x86PackedAverage,
			inputBits: spec.laneBits, outputBits: spec.laneBits, memoryBits: spec.laneBits,
		}, true
	}
	if spec, known := x86PackedWordMultiplySpecs[Op(base)]; known && (family == "" || family == x86PackedWordProduct) {
		return x86PackedPhysicalSpec{
			x86PackedBinarySpec: x86PackedBinarySpec{encoding: spec.encoding, zeroing: spec.encoding == x86PackedLogicalVEXOrEVEX},
			family:              x86PackedWordProduct, inputBits: 16, outputBits: 16, memoryBits: 16,
			mode: spec.mode,
		}, true
	}
	if spec, known := x86PackedMultiplyAddSpecs[Op(base)]; known && (family == "" || family == x86PackedMultiplyAdd) {
		return x86PackedPhysicalSpec{
			x86PackedBinarySpec: spec.x86PackedBinarySpec, family: x86PackedMultiplyAdd,
			inputBits: spec.inputBits, outputBits: spec.outputBits, nativeOpcode: spec.nativeOpcode,
		}, true
	}
	if spec, known := x86DwordProductSpecs[Op(base)]; known && (family == "" || family == x86PackedDwordProduct) {
		return x86PackedPhysicalSpec{
			x86PackedBinarySpec: spec.x86PackedBinarySpec, family: x86PackedDwordProduct,
			inputBits: 32, outputBits: 64, memoryBits: 64,
			signed: spec.signed, nativeOpcode: spec.nativeOpcode,
		}, true
	}
	return x86PackedPhysicalSpec{}, false
}

// An empty family accepts this whole group. A family-specific consumer retains
// its original boundary, including a zero form before physical parsing starts.
func x86PackedPhysicalProperties(op Op, ins Instr, arch string, family x86PackedPhysicalFamily) (x86PackedPhysicalForm, bool, error) {
	spec, known := x86PackedPhysicalSpecForOp(op, family)
	if !known {
		return x86PackedPhysicalForm{}, false, nil
	}
	binary, source, started, err := x86PackedBinaryPhysicalSource(op, ins, arch, spec.x86PackedBinarySpec, string(spec.family))
	if !started {
		return x86PackedPhysicalForm{}, true, err
	}
	return x86PackedPhysicalForm{binary, spec, source}, true, err
}

func (c *amd64Ctx) lowerPackedPhysical(op Op, ins Instr, family x86PackedPhysicalFamily) (bool, bool, error) {
	form, known, err := x86PackedPhysicalProperties(op, ins, c.goarch, family)
	if !known || err != nil {
		return known, false, err
	}
	switch form.spec.family {
	case x86PackedAverage:
		return c.lowerPackedAverageForm(op, ins, form)
	case x86PackedWordProduct:
		return c.lowerPackedWordMultiplyForm(op, ins, form)
	case x86PackedMultiplyAdd:
		return c.lowerWordMultiplyAddForm(op, ins, form)
	case x86PackedDwordProduct:
		return c.lowerDwordToQwordMultiplyForm(op, ins, form)
	}
	panic("unregistered packed physical family")
}
