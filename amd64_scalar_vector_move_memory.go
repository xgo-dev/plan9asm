package plan9asm

import "fmt"

// Only the scalar move emitter's exact four/eight-byte register-addressed
// native access participates. This supplies no FP/AUTO/static backing, segment
// input, extent, alignment, pointer validity or source continuation permission.
func x86ScalarVectorMoveOrdinaryMemory(operand Operand, bits int, arch string) bool {
	return (bits == 32 || bits == 64) && operand.Kind == OpMem &&
		operand.Mem.Sym == "" && operand.Mem.Segment == "" &&
		x86OrdinaryNativeMemoryOperand(operand, arch)
}

func (c *amd64Ctx) loadScalarVectorMoveNativeMemory(source Operand, bits int) (string, error) {
	pointer, pointerType, _, err := c.packedVectorMemoryPointer(source)
	if err != nil {
		return "", err
	}
	loaded := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load volatile i%d, %s %s, align 1\n", loaded, bits, pointerType, pointer)
	return "%" + loaded, nil
}
