package plan9asm

import (
	"fmt"
	"strings"
)

func (c *amd64Ctx) lowerFourSource(op Op, ins Instr) (bool, bool, error) {
	form, known, err := x86FourSourceProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	if !x86ScalarFloatIntegerNativeTarget(c.goarch, c.targetTriple) || form.memory.Kind == OpFP {
		return true, false, fmt.Errorf("%w: %s needs original x86 four-source memory and exception behavior", ErrProbeNeedsContext, op)
	}
	if err := c.validateConflictFunnelMemory(ins, x86PackedBinaryForm{memory: 0, memoryBytes: 16}); err != nil {
		return true, false, err
	}
	return true, false, c.emitNativeFourSource(op, ins, form)
}

// Snapshot the complete logical source block and old accumulator before the
// write. A private fixed 0..3 block plus accumulator4 is only an inline-asm
// transport: source/destination aliasing in the original register file remains
// modeled by the caller's byte values and the final single writeback.
//
// Keep one original opcode rather than four LLVM FMA/dot expressions. Each
// floating iteration has ambient MXCSR rounding and ordered exceptions, and
// the original mask suppresses either the whole m128 access or none of it.
// Even a dead result retains those exact native effects.
func (c *amd64Ctx) emitNativeFourSource(op Op, ins Instr, form amd64FourSourceForm) error {
	width := form.byteWidth()
	typ := amd64FloatingVectorType(width/4, 32) // Bit-preserving transport, including integer dot products.
	load := func(operand Operand) (string, error) {
		return c.loadFloatingVectorOperand(operand, width, width/4, 32)
	}
	old, err := load(form.destination)
	if err != nil {
		return err
	}
	bank := "zmm"
	if form.spec.scalar {
		bank = "xmm"
	}
	constraints := "={" + bank + "4},0"
	arguments := typ + " " + old
	for position := 0; position < 4; position++ {
		source, err := load(form.source(position))
		if err != nil {
			return err
		}
		constraints += fmt.Sprintf(",{%s%d}", bank, position)
		arguments += ", " + typ + " " + source
	}
	pointer, pointerType, _, err := c.packedVectorMemoryPointer(form.memory)
	if err != nil {
		return err
	}
	segment := ""
	if pointerType == "ptr addrspace(256)" {
		segment = "%gs:"
	} else if pointerType == "ptr addrspace(257)" {
		segment = "%fs:"
	}
	constraints += ",r"
	arguments += ", " + pointerType + " " + pointer
	mnemonic, _, _ := strings.Cut(strings.ToLower(string(op)), ".")
	assembly := fmt.Sprintf("%s %s($6), %%%s0, %%%s4", mnemonic, segment, bank, bank)
	if form.maskIndex >= 0 {
		mask, err := c.loadK(ins.Args[form.maskIndex].Reg)
		if err != nil {
			return err
		}
		assembly = "kmovw ${7:k}, %k1; " + assembly + " {%k1}"
		if form.zeroing {
			assembly += " {z}"
		}
		constraints += ",r,~{k1}"
		arguments += ", i32 " + c.approximateMathMask32(mask)
	}
	constraints += ",~{memory}"
	if form.spec.mode == amd64FourSourceFMA {
		constraints += ",~{fpsr}"
	}
	result, bytes := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q(%s)\n", result, typ, assembly, constraints, arguments)
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <%d x i8>\n", bytes, typ, result, width)
	return c.storePackedMoveOperand(form.destination, width, "%"+bytes)
}
