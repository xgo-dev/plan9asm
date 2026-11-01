package plan9asm

import (
	"fmt"
	"strings"
)

// One complete native instruction preserves packed exception priority, ambient
// MXCSR, immediate exception controls, masked access and dead-result effects.
// A software value formula is not a replacement for any of those obligations.
func (c *amd64Ctx) lowerNativeFloatingHelper(op Op, ins Instr) (bool, bool, error) {
	if ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return true, false, fmt.Errorf("floating-helper dispatch/source mismatch: %s/%s", op, ins.Op)
	}
	ins.Op = op
	form, known, err := x86FloatingHelperProperties(ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	return true, false, c.emitNativeFloatingHelper(ins, form)
}

func (c *amd64Ctx) emitNativeFloatingHelper(ins Instr, form x86FloatingHelperForm) error {
	first := ins.Args[form.first]
	if ins.x86AddressBits != 0 || first.Kind == OpFP && !form.spec.scalar || first.Kind == OpMem &&
		!x86OrdinaryNativeMemoryOperand(first, c.goarch) && !c.fixedLocalMemoryCertified(ins, form.first) {
		return fmt.Errorf("%w: %s needs its original native source backing", ErrProbeNeedsContext, ins.Op)
	}
	if form.spec.maskResult {
		return c.emitNativeFloatingClass(ins, form)
	}
	typ := amd64FloatingVectorType(form.byteWidth*8/form.spec.bits, form.spec.bits)
	load := func(index int) (string, error) {
		bytes, err := c.loadPackedCompareBytes(ins.Args[index], form.byteWidth)
		if err != nil {
			return "", err
		}
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to %s\n", value, form.byteWidth, bytes, typ)
		return "%" + value, nil
	}
	old := "zeroinitializer"
	if form.spec.readDestination || form.mask >= 0 && !form.properties.zeroing {
		var err error
		old, err = load(form.destination)
		if err != nil {
			return err
		}
	}
	mask := ""
	if form.mask >= 0 {
		var err error
		mask, err = c.loadK(ins.Args[form.mask].Reg)
		if err != nil {
			return err
		}
	}
	input, inputType, inputConstraint, inputTemplate, err := c.nativeFloatingCompareSource(first,
		x86FloatCompareForm{x86FloatBinaryForm: x86FloatBinaryForm{
			bits: form.spec.bits, byteWidth: form.byteWidth, memoryBytes: form.memoryBytes, scalar: form.spec.scalar,
		}}, typ, mask)
	if err != nil {
		return err
	}
	// Source helper's $1 refers to its own first explicit argument. Here
	// operand one is the tied old destination, and the source is operand two.
	inputTemplate = strings.ReplaceAll(inputTemplate, "$1", "$2")
	args := fmt.Sprintf("%s %s, %s %s", typ, old, inputType, input)
	constraints := "=v,0," + inputConstraint
	operands := inputTemplate
	maskOrdinal := 3
	if form.second >= 0 {
		second, err := load(form.second)
		if err != nil {
			return err
		}
		args += ", " + typ + " " + second
		constraints += ",v"
		operands += ", $3"
		maskOrdinal++
	}
	if form.properties.broadcast {
		operands = strings.Replace(operands, inputTemplate,
			inputTemplate+fmt.Sprintf(" {1to%d}", form.byteWidth*8/form.spec.bits), 1)
	}
	assembly := "{evex} " + form.nativeMnemonic(ins) + " "
	if form.spec.immediate {
		assembly += fmt.Sprintf("$$%d, ", form.immediate)
	}
	if form.properties.sae {
		assembly += "{sae}, "
	} else if form.properties.rounding != "" {
		assembly += "{" + strings.ToLower(strings.TrimSuffix(form.properties.rounding, "_SAE")) + "-sae}, "
	}
	assembly += operands + ", $0"
	if form.mask >= 0 {
		assembly = fmt.Sprintf("kmovw ${%d:k}, %%k1; ", maskOrdinal) + assembly + " {%k1}"
		if form.properties.zeroing {
			assembly += " {z}"
		}
		constraints += ",r,~{k1}"
		args += ", i32 " + c.approximateMathMask32(mask)
	}
	result, bytes := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q(%s)\n", result, typ, assembly,
		constraints+",~{memory},~{fpsr}", args)
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <%d x i8>\n", bytes, typ, result, form.byteWidth)
	return c.storePackedMoveOperand(ins.Args[form.destination], form.byteWidth, "%"+bytes)
}

func (c *amd64Ctx) emitNativeFloatingClass(ins Instr, form x86FloatingHelperForm) error {
	typ := amd64FloatingVectorType(form.byteWidth*8/form.spec.bits, form.spec.bits)
	mask := ""
	if form.mask >= 0 {
		var err error
		mask, err = c.loadK(ins.Args[form.mask].Reg)
		if err != nil {
			return err
		}
	}
	input, inputType, inputConstraint, inputTemplate, err := c.nativeFloatingCompareSource(ins.Args[form.first],
		x86FloatCompareForm{x86FloatBinaryForm: x86FloatBinaryForm{
			bits: form.spec.bits, byteWidth: form.byteWidth, memoryBytes: form.memoryBytes, scalar: form.spec.scalar,
		}}, typ, mask)
	if err != nil {
		return err
	}
	if form.properties.broadcast {
		inputTemplate += fmt.Sprintf(" {1to%d}", form.byteWidth*8/form.spec.bits)
	}
	args := inputType + " " + input
	constraints := "=r," + inputConstraint
	assembly := fmt.Sprintf("{evex} %s $$%d, %s, %%k1", form.nativeMnemonic(ins), form.immediate, inputTemplate)
	if form.mask >= 0 {
		assembly = "kmovw ${2:k}, %k2; " + assembly + " {%k2}"
		constraints += ",r,~{k2}"
		args += ", i32 " + c.approximateMathMask32(mask)
	}
	assembly += "; kmovw %k1, ${0:k}"
	result, wide := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call i32 asm sideeffect %q, %q(%s)\n", result, assembly,
		constraints+",~{k1},~{memory},~{fpsr}", args)
	fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", wide, result)
	return c.storeK(ins.Args[form.destination].Reg, "%"+wide)
}
