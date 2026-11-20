package plan9asm

import (
	"fmt"
	"strings"
)

var amd64BoundOperandBits = map[Op]int{
	"BOUNDW": 16,
	"BOUNDL": 32,
}

// lowerBound implements Go 1.27's complete yrl_m family. BOUND is valid only
// in 16/32-bit x86 modes, so plan9asm preserves the exact faulting instruction
// as constrained inline assembly rather than approximating its exception.
func (c *amd64Ctx) lowerBound(op Op, ins Instr) (ok bool, terminated bool, err error) {
	raw := strings.ToUpper(string(op))
	base := raw
	if dot := strings.IndexByte(raw, '.'); dot >= 0 {
		base = raw[:dot]
	}
	bits, recognized := amd64BoundOperandBits[Op(base)]
	if !recognized {
		return false, false, nil
	}
	if raw != base {
		return true, false, fmt.Errorf("%s %s does not accept instruction suffixes: %q", c.goarch, base, ins.Raw)
	}
	if c.goarch != "386" {
		return true, false, fmt.Errorf("%s %s is unavailable outside 32-bit x86 mode: %q", c.goarch, base, ins.Raw)
	}
	if len(ins.Args) != 2 {
		return true, false, fmt.Errorf("386 %s expects GP register and bounds memory: %q", base, ins.Raw)
	}
	if ins.Args[0].Kind != OpReg || !isX86YrlRegisterForArch(ins.Args[0].Reg, c.goarch) {
		return true, false, fmt.Errorf("386 %s source is outside Go 1.27's Yrl class: %q", base, ins.Raw)
	}
	if !isAMD64MemoryOperand(ins.Args[1]) {
		return true, false, fmt.Errorf("386 %s second operand must be Go 1.27 Ym memory: %q", base, ins.Raw)
	}
	typeName := I32
	if bits == 16 {
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
	if bits == 16 {
		encoding = ".byte 0x66, 0x62, 0x01"
	}
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(%s %s, %s %s)\n",
		encoding, "{ax},{cx},~{memory},~{dirflag},~{fpsr},~{flags}", typeName, value, pointerType, pointer)
	return true, false, nil
}
