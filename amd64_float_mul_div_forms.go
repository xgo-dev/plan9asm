package plan9asm

type x86FloatMulDivForm = x86FloatArithmeticForm

func x86FloatMulDivProperties(ins Instr, arch string) (x86FloatMulDivForm, bool, error) {
	return x86FloatArithmeticProperties(ins, arch, x86FloatMultiplyDivide)
}
