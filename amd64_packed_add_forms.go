package plan9asm

type x86PackedAddForm = x86PackedArithmeticForm
type x86PackedIntegerAddForm = x86PackedArithmeticForm

func x86PackedIntegerAddProperties(ins Instr, arch string) (x86PackedIntegerAddForm, bool, error) {
	return x86PackedArithmeticProperties(ins.Op, ins, arch, x86PackedArithmeticAdd)
}

// Shared syntax does not admit saturating adds into the private wrapping caller.
func x86PackedWrappingAddProperties(ins Instr, arch string) (x86PackedAddForm, bool, error) {
	spec, known := x86PackedArithmeticSpecForOp(ins.Op, x86PackedArithmeticAdd)
	if !known || spec.mode != x86PackedWrap {
		return x86PackedAddForm{}, false, nil
	}
	return x86PackedArithmeticFormForSpec(ins.Op, ins, arch, spec)
}
