package plan9asm

import (
	"fmt"
	"strings"
)

var x86EnqueueOps = map[string]byte{
	"ENQCMD":  0xf2,
	"ENQCMDS": 0xf3,
}

// Keep the 64-byte device enqueue operation in hardware. An ordinary memory
// copy cannot implement PASID handling, atomic submission, or retry status.
func (c *amd64Ctx) lowerEnqueue(op Op, ins Instr) (bool, bool, error) {
	form, known, err := x86EnqueueProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	source := form.source
	assemblySource := "$1"
	if source.Kind == OpMem && source.Mem.Segment != "" {
		switch source.Mem.Segment {
		case FS, GS:
			// LLVM inline-asm memory operands do not preserve the pointer's
			// segment address space. Spell the prefix explicitly and pass
			// its offset, not an ordinary unsegmented effective address.
			assemblySource = "%" + strings.ToLower(string(source.Mem.Segment)) + ":$1"
			source.Mem.Segment = ""
		default:
			return true, false, fmt.Errorf("unsupported enqueue source segment %s", source.Mem.Segment)
		}
	}
	ptr, ptrType, err := c.x86DescriptorMemoryPointer(source)
	if err != nil {
		return true, false, err
	}
	wordType := amd64IntegerTypeForBits(form.wordBits)
	destination, err := c.evalIntSized(form.destination, wordType)
	if err != nil {
		return true, false, err
	}
	if bits := form.addressBits; bits != form.wordBits {
		// Truncate the effective offset before hardware applies any explicit
		// source-segment override.
		address := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ptrtoint %s %s to i%d\n", address, ptrType, ptr, bits)
		wrapped := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = inttoptr i%d %%%s to %s\n", wrapped, bits, address, ptrType)
		ptr = "%" + wrapped
		low, extended := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc %s %s to i%d\n", low, wordType, destination, bits)
		fmt.Fprintf(c.b, "  %%%s = zext i%d %%%s to %s\n", extended, bits, low, wordType)
		destination = "%" + extended
	}

	status := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call i8 asm sideeffect %q, %q(%s elementtype([64 x i8]) %s, %s %s)\n",
		status, form.native+" "+assemblySource+", $2; sete $0",
		"=q,*m,r,~{memory},~{dirflag},~{fpsr},~{flags}", ptrType, ptr, wordType, destination)
	c.storeSegmentQueryZF("%" + status)
	c.clearX86StatusFlags(x86StatusAll &^ x86StatusZF)
	return true, false, nil
}
