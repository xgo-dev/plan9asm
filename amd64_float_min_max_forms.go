package plan9asm

type x86FloatMinMaxForm = x86FloatArithmeticForm

func x86FloatMinMaxNativeEVEX(ins Instr, f x86FloatMinMaxForm) bool {
	if f.legacy {
		return false
	}
	if ins.x86FloatMinMaxEVEX || f.byteWidth == 64 || f.mask >= 0 || f.broadcast || f.sae {
		return true
	}
	for _, operand := range ins.Args {
		if index, valid := amd64VectorRegisterIndex(operand.Reg, f.byteWidth); operand.Kind == OpReg && valid && index >= 16 {
			return true
		}
	}
	return false
}

func x86FloatMinMaxProperties(ins Instr, arch string) (x86FloatMinMaxForm, bool, error) {
	return x86FloatArithmeticProperties(ins, arch, x86FloatMinimumMaximum)
}
