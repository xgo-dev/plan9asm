package plan9asm

import "fmt"

type amd64UnalignedLoadSpec struct {
	maxBytes int
	vector   bool
}

// amd64UnalignedLoadSpecs is the complete Go 1.27 ylddqu/_yvlddqu grammar.
// Both instructions are load-only; legacy LDDQU is X-width, while VLDDQU
// adds the VEX Y-width row.
var amd64UnalignedLoadSpecs = map[Op]amd64UnalignedLoadSpec{
	"LDDQU":  {maxBytes: 16},
	"VLDDQU": {maxBytes: 32, vector: true},
}

func (c *amd64Ctx) lowerUnalignedVectorLoad(op Op, ins Instr) (ok bool, terminated bool, err error) {
	form, known, err := x86UnalignedLoadProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	if !x86ScalarFloatIntegerNativeTarget(c.goarch, c.targetTriple) || ins.Args[0].Kind == OpFP {
		return true, false, fmt.Errorf("%w: LDDQU needs its original x86 native access, not logical FP storage", ErrProbeNeedsContext)
	}
	// Share only the native vector transport. No alignment assumption is
	// introduced: the actual opcode retains its wider/repeated reads and #AC.
	move := amd64PackedVectorMoveForm{byteWidth: form.byteWidth, memory: 0, destination: 1, mask: -1}
	return true, false, c.lowerNativeAlignedVectorMemory(ins, move, !form.spec.vector)
}
