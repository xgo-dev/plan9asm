package plan9asm

import (
	"fmt"
	"strings"
)

func (c *amd64Ctx) lowerVectorScalarFlagCompare(op Op, ins Instr) (ok bool, terminated bool, err error) {
	name, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	if _, known := x86COMISpecs[Op(name)]; !known {
		return false, false, nil
	}
	if !strings.EqualFold(string(op), string(ins.Op)) {
		return true, false, fmt.Errorf("scalar flag comparison dispatch/source mismatch")
	}
	form, known, err := x86COMIProperties(ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	if !x86ScalarFloatIntegerNativeTarget(c.goarch, c.targetTriple) {
		return true, false, fmt.Errorf("%w: scalar flag comparison requires its native x86 MXCSR target", ErrProbeNeedsContext)
	}
	if ins.x86AddressBits != 0 {
		return true, false, fmt.Errorf("%w: scalar flag comparison needs original address-size binding", ErrProbeNeedsContext)
	}
	return true, false, c.emitNativeCOMI(ins, form)
}

// A relation-only LLVM fcmp neither distinguishes COMI/UCOMI signaling nor
// preserves exceptions after FLAGS die. Keep one whole native comparison and
// capture CF/ZF/PF before compiler-generated instructions can overwrite them.
func (c *amd64Ctx) emitNativeCOMI(ins Instr, form x86COMIForm) error {
	destination, err := c.evalScalarFloatForInteger(ins.Args[1], form.spec.bits)
	if err != nil {
		return err
	}
	typ := string(amd64FloatingTypeForBits(form.spec.bits))
	registerConstraint := "x"
	if form.evex {
		registerConstraint = "v"
	}
	source := ins.Args[0]
	var value, sourceType, constraint, operand string
	if source.Kind == OpReg || source.Kind == OpFP {
		value, err = c.evalScalarFloatForInteger(source, form.spec.bits)
		sourceType, constraint, operand = typ, registerConstraint, "$3"
	} else {
		var pointerType string
		value, pointerType, _, err = c.packedVectorMemoryPointer(source)
		sourceType = fmt.Sprintf("%s elementtype([%d x i8])", pointerType, form.spec.bits/8)
		constraint, operand = "*m", "$3"
		if pointerType == "ptr addrspace(256)" {
			operand = "%gs:" + operand
		} else if pointerType == "ptr addrspace(257)" {
			operand = "%fs:" + operand
		}
	}
	if err != nil {
		return err
	}
	assembly := strings.ToLower(form.name)
	if form.evex {
		assembly = "{evex} " + assembly
	}
	if form.sae {
		assembly += " {sae},"
	}
	assembly += " " + operand + ", $4; setb $0; sete $1; setp $2"
	result := c.newTmp()
	constraints := "=q,=q,=q," + constraint + "," + registerConstraint + ",~{flags},~{fpsr},~{memory}"
	fmt.Fprintf(c.b, "  %%%s = call { i8, i8, i8 } asm sideeffect %q, %q(%s %s, %s %s)\n",
		result, assembly, constraints, sourceType, value, typ, destination)
	for index, slot := range []string{c.flagsCFSlot, c.flagsZSlot, c.flagsPFSlot} {
		byteValue, boolean := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractvalue { i8, i8, i8 } %%%s, %d\n", byteValue, result, index)
		fmt.Fprintf(c.b, "  %%%s = icmp ne i8 %%%s, 0\n", boolean, byteValue)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", boolean, slot)
	}
	for _, slot := range []string{c.flagsSltSlot, c.flagsOFSlot, c.flagsAFSlot} {
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", slot)
	}
	return nil
}
