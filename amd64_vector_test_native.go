package plan9asm

import (
	"fmt"
	"strings"
)

// Keep one original memory instruction, including its complete access and
// fault envelope when FLAGS are discarded. Capturing CF/ZF in the same asm
// prevents intervening compiler instructions from replacing their values.
func (c *amd64Ctx) emitVectorTestNativeMemory(ins Instr, form x86VectorTestForm, arch string) error {
	if !x86ScalarFloatIntegerNativeTarget(arch, c.targetTriple) {
		return fmt.Errorf("%w: vector-test memory needs its original x86 target", ErrProbeNeedsContext)
	}
	value, err := c.loadPackedCompareBytes(ins.Args[1], form.byteWidth)
	if err != nil {
		return err
	}
	pointer, pointerType, _, err := c.packedVectorMemoryPointer(ins.Args[0])
	if err != nil {
		return err
	}
	operand := "$2"
	switch pointerType {
	case "ptr addrspace(256)":
		operand = "%gs:" + operand
	case "ptr addrspace(257)":
		operand = "%fs:" + operand
	}
	assembly := strings.ToLower(string(ins.Op)) + " " + operand + ", $3; setb $0; sete $1"
	// A bitcast-only floating carrier needs AVX, not AVX2, for a Y input.
	// No floating arithmetic or conversion can change the source bits.
	carrier, result := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to <%d x float>\n", carrier, form.byteWidth, value, form.byteWidth/4)
	fmt.Fprintf(c.b, "  %%%s = call { i8, i8 } asm sideeffect %q, %q(%s elementtype([%d x i8]) %s, <%d x float> %%%s)\n",
		result, assembly, "=q,=q,*m,x,~{flags},~{fpsr},~{memory}", pointerType, form.byteWidth,
		pointer, form.byteWidth/4, carrier)
	for index, slot := range []string{c.flagsCFSlot, c.flagsZSlot} {
		byteValue, boolean := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractvalue { i8, i8 } %%%s, %d\n", byteValue, result, index)
		fmt.Fprintf(c.b, "  %%%s = icmp ne i8 %%%s, 0\n", boolean, byteValue)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", boolean, slot)
	}
	c.clearX86StatusFlags(x86StatusAll &^ (x86StatusCF | x86StatusZF))
	return nil
}
