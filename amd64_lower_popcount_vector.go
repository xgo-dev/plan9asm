package plan9asm

import "fmt"

type amd64PackedBitCountKind uint8

const (
	amd64PackedPopulationCount amd64PackedBitCountKind = iota
	amd64PackedLeadingZeroCount
)

type amd64PackedBitCountSpec struct {
	laneBits  int
	kind      amd64PackedBitCountKind
	broadcast bool
}

// amd64PackedBitCountSpecs models the complete Go 1.27 _yvexpandpd grammar
// for packed population-count and leading-zero-count instructions.
var amd64PackedBitCountSpecs = map[Op]amd64PackedBitCountSpec{
	"VPOPCNTB": {laneBits: 8, kind: amd64PackedPopulationCount},
	"VPOPCNTW": {laneBits: 16, kind: amd64PackedPopulationCount},
	"VPOPCNTD": {laneBits: 32, kind: amd64PackedPopulationCount, broadcast: true},
	"VPOPCNTQ": {laneBits: 64, kind: amd64PackedPopulationCount, broadcast: true},
	"VPLZCNTD": {laneBits: 32, kind: amd64PackedLeadingZeroCount, broadcast: true},
	"VPLZCNTQ": {laneBits: 64, kind: amd64PackedLeadingZeroCount, broadcast: true},
}

// lowerPackedBitCount implements X/Y/Z register or memory sources, K1-K7
// merge and .Z, and each opcode's scalar-memory broadcast forms.
func (c *amd64Ctx) lowerPackedBitCount(op Op, ins Instr) (ok bool, terminated bool, err error) {
	form, known, err := x86PackedBitCountProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	spec, byteWidth := form.spec, form.byteWidth
	source, destination := ins.Args[form.first], ins.Args[form.destination]
	mask := ""
	if form.mask >= 0 {
		mask, err = c.loadK(ins.Args[form.mask].Reg)
		if err != nil {
			return true, false, err
		}
	}

	lanes := byteWidth * 8 / spec.laneBits
	// E4 suppresses inactive native lanes; enabled reads remain observable
	// even when the computed count is dead. FP fields keep their full span.
	sourceValue, err := c.loadX86PackedShiftLanes(source, byteWidth, spec.laneBits, form.broadcast, mask)
	if err != nil {
		return true, false, err
	}
	computed := c.newTmp()
	if spec.kind == amd64PackedLeadingZeroCount {
		fmt.Fprintf(c.b, "  %%%s = call <%d x i%d> @llvm.ctlz.v%di%d(<%d x i%d> %s, i1 false)\n",
			computed, lanes, spec.laneBits, lanes, spec.laneBits, lanes, spec.laneBits, sourceValue)
	} else {
		fmt.Fprintf(c.b, "  %%%s = call <%d x i%d> @llvm.ctpop.v%di%d(<%d x i%d> %s)\n",
			computed, lanes, spec.laneBits, lanes, spec.laneBits, lanes, spec.laneBits, sourceValue)
	}
	result := "%" + computed
	if form.mask >= 0 {
		oldBytes, err := c.loadPackedCompareBytes(destination, byteWidth)
		if err != nil {
			return true, false, err
		}
		old := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, spec.laneBits, oldBytes)
		result = amd64ApplyIntegerLaneMask(c, lanes, spec.laneBits, result, old, mask, form.zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, spec.laneBits, result, byteWidth)
	return true, false, c.storePackedMoveOperand(destination, byteWidth, "%"+out)
}
