package plan9asm

import (
	"fmt"
	"strings"
)

var amd64BoundOperandBits = map[Op]int{
	"BOUNDW": 16,
	"BOUNDL": 32,
}

func x86BoundProperties(op Op, ins Instr, arch string) (int64, bool, error) {
	raw := strings.ToUpper(string(op))
	base := raw
	if dot := strings.IndexByte(raw, '.'); dot >= 0 {
		base = raw[:dot]
	}
	bits, recognized := amd64BoundOperandBits[Op(base)]
	if !recognized {
		return 0, false, nil
	}
	if raw != base {
		return 0, true, fmt.Errorf("%s %s does not accept instruction suffixes: %q", arch, base, ins.Raw)
	}
	if arch != "386" {
		return 0, true, fmt.Errorf("%s %s is unavailable outside 32-bit x86 mode: %q", arch, base, ins.Raw)
	}
	if len(ins.Args) != 2 {
		return 0, true, fmt.Errorf("386 %s expects GP register and bounds memory: %q", base, ins.Raw)
	}
	if ins.Args[0].Kind != OpReg || !isX86YrlRegisterForArch(ins.Args[0].Reg, arch) {
		return 0, true, fmt.Errorf("386 %s source is outside Go's Yrl class: %q", base, ins.Raw)
	}
	if !isAMD64MemoryOperand(ins.Args[1]) {
		return 0, true, fmt.Errorf("386 %s second operand must be Go Ym memory: %q", base, ins.Raw)
	}
	return int64(bits / 8), true, nil
}

func x86TypedBoundByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	width, known, err := x86BoundProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	return x86TypedByteEffect{operands: []x86TypedByteOperand{
		{index: 0, operand: ins.Args[0], width: width, read: true},
		{index: 1, operand: ins.Args[1], width: 2 * width, read: true},
	}}, true, nil
}

// BOUND retains its exact native read and fault. The caller may supply the
// bounds through initialized local bytes or through a defined native address.
func x86LoweredBoundStep(ins Instr, state *x86ResultState, owned []bool, arch, triple string) (bool, bool) {
	width, known, err := x86BoundProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	return x86ScalarFloatIntegerNativeTarget(arch, triple) && x86ResultNamedPredicateInstruction(ins) &&
		ins.Args[0].Reg != SP && x86ResultRead(ins.Args[0], width, state, owned, arch) &&
		x86ResultReadWithNativeContinuation(ins, ins.Args[1], 2*width, state, owned, arch, true), true
}

// The exact faulting opcode is available only on a matching x86 backend.
func (c *amd64Ctx) lowerBound(op Op, ins Instr) (ok bool, terminated bool, err error) {
	width, known, err := x86BoundProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	typeName := I32
	if width == 2 {
		typeName = I16
	}
	value, err := c.evalIntSized(ins.Args[0], typeName)
	if err != nil {
		return true, false, err
	}
	pointer, pointerType, err := c.x86DescriptorMemoryPointer(ins.Args[1])
	if err != nil {
		return true, false, err
	}
	// LLVM 22's integrated assembler no longer recognizes the BOUND mnemonic,
	// even for an i386 triple. Constrain the value and bounds pointer to AX/CX
	// and emit 62 /r with ModRM 00:000:001. The 66 prefix selects BOUNDW.
	encoding := ".byte 0x62, 0x01"
	if width == 2 {
		encoding = ".byte 0x66, 0x62, 0x01"
	}
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(%s %s, %s %s)\n",
		encoding, "{ax},{cx},~{memory},~{dirflag},~{fpsr},~{flags}", typeName, value, pointerType, pointer)
	return true, false, nil
}
