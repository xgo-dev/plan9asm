package plan9asm

import (
	"fmt"
	"strings"
)

func (c *amd64Ctx) lowerScalarPrecisionConvert(op Op, ins Instr) (bool, bool, error) {
	form, known, err := x86ScalarPrecisionProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	ins.Op = op
	if !x86ScalarFloatIntegerNativeTarget(c.goarch, c.targetTriple) {
		return true, false, fmt.Errorf("%w: %s needs its native x86 MXCSR target, not pure LLVM precision arithmetic", ErrProbeNeedsContext, op)
	}
	if form.memory >= 0 {
		memory := x86PackedBinaryForm{memory: 0, memoryBytes: form.memoryBytes}
		if err := c.validateConflictFunnelMemory(ins, memory); err != nil {
			return true, false, err
		}
	}
	return true, false, c.emitScalarPrecisionConvert(ins, form)
}

// Keep the original conversion, rather than ambient pure fpext/fptrunc:
// DAZ/FTZ, RC, status, unmasked exceptions and explicit ER/SAE are hardware
// effects. The memory operand remains on that same instruction, so native
// E3 suppression and exact m32/m64 faults survive dead-value elimination.
func (c *amd64Ctx) emitScalarPrecisionConvert(ins Instr, form x86ScalarPrecisionForm) error {
	const typ = "<4 x float>" // Bit-preserving 128-bit carrier, never arithmetic precision.
	load := func(index int) (string, error) {
		return c.loadFloatingVectorOperand(ins.Args[index], 16, 4, 32)
	}
	old := "zeroinitializer"
	var err error
	if form.legacy || form.mask >= 0 && !form.zeroing {
		old, err = load(form.destination)
		if err != nil {
			return err
		}
	}
	evex := x86ScalarPrecisionNativeEVEX(ins, form)
	register := "x"
	if evex {
		register = "v"
	}
	value, inputType, inputConstraint, err := c.scalarPrecisionNativeSource(ins.Args[0], form.spec.inputBits, register)
	if err != nil {
		return err
	}
	constraints, args := "="+register+",0", typ+" "+old
	inputIndex := 2
	operands := "$2, $0"
	if !form.legacy {
		upper, err := load(form.second)
		if err != nil {
			return err
		}
		constraints += "," + register
		args += ", " + typ + " " + upper
		inputIndex, operands = 3, "$3, $2, $0"
	}
	constraints += "," + inputConstraint
	args += ", " + inputType + " " + value
	mnemonic, _, _ := strings.Cut(strings.ToLower(string(ins.Op)), ".")
	if evex {
		mnemonic = "{evex} " + mnemonic
	}
	assembly := mnemonic + " "
	if form.sae {
		assembly += "{sae}, "
	} else if form.rounding != "" {
		assembly += "{" + strings.ToLower(strings.TrimSuffix(form.rounding, "_SAE")) + "-sae}, "
	}
	assembly += operands
	if form.mask >= 0 {
		mask, err := c.loadK(ins.Args[form.mask].Reg)
		if err != nil {
			return err
		}
		assembly = fmt.Sprintf("kmovw ${%d:k}, %%k1; ", inputIndex+1) + assembly + " {%k1}"
		if form.zeroing {
			assembly += " {z}"
		}
		constraints += ",r,~{k1}"
		args += ", i32 " + c.approximateMathMask32(mask)
	}
	result, bytes := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q(%s)\n", result, typ, assembly, constraints+",~{memory},~{fpsr}", args)
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", bytes, typ, result)
	if form.legacy {
		return c.storeLegacyXViews(ins.Args[form.destination].Reg, "%"+bytes)
	}
	return c.storePackedMoveOperand(ins.Args[form.destination], 16, "%"+bytes)
}

func (c *amd64Ctx) scalarPrecisionNativeSource(source Operand, bits int, register string) (value, typ, constraint string, err error) {
	const carrier = "<4 x float>"
	if source.Kind == OpReg {
		value, err = c.loadFloatingVectorOperand(source, 16, 4, 32)
		return value, carrier, register, err
	}
	if source.Kind == OpFP {
		value, err = c.loadScalarLaneFPBits(source.FPOffset, bits)
		if err != nil {
			return "", "", "", err
		}
		lanes := 128 / bits
		inserted, converted := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> zeroinitializer, i%d %s, i32 0\n", inserted, lanes, bits, bits, value)
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %%%s to %s\n", converted, lanes, bits, inserted, carrier)
		return "%" + converted, carrier, register, nil
	}
	pointer, pointerType, _, err := c.packedVectorMemoryPointer(source)
	return pointer, fmt.Sprintf("%s elementtype([%d x i8])", pointerType, bits/8), "*m", err
}
