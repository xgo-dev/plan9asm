package plan9asm

type x86PackedAverageSpec struct {
	x86PackedBinarySpec
	laneBits int
}

// Go's complete unsigned rounded-average family: ymm/Py1 for legacy and
// _yvandnpd for VEX/EVEX. E4.nb has mask suppression but no broadcast or SAE.
var x86PackedAverageSpecs = map[Op]x86PackedAverageSpec{
	"PAVGB":  {x86PackedBinarySpec{encoding: x86PackedLogicalLegacyInteger}, 8},
	"PAVGW":  {x86PackedBinarySpec{encoding: x86PackedLogicalLegacyInteger}, 16},
	"VPAVGB": {x86PackedBinarySpec{encoding: x86PackedLogicalVEXOrEVEX, zeroing: true}, 8},
	"VPAVGW": {x86PackedBinarySpec{encoding: x86PackedLogicalVEXOrEVEX, zeroing: true}, 16},
}

type x86PackedAverageForm = x86PackedPhysicalForm

// A shape/effect observation supplies no input initialization, caller, frame
// or native storage authority. All consumers retain their own proof gates.
func x86PackedAverageProperties(op Op, ins Instr, arch string) (x86PackedAverageForm, bool, error) {
	return x86PackedPhysicalProperties(op, ins, arch, x86PackedAverage)
}

func x86ResultPackedAverageStep(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	form, known, err := x86PackedAverageProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	return x86ResultFixedVectorInputs(ins, form.x86PackedBinaryForm, false, state, owned, arch), true
}
