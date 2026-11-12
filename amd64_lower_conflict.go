package plan9asm

import (
	"fmt"
)

type amd64PackedConflictSpec struct {
	laneBits int
}

// amd64PackedConflictSpecs is the complete Go 1.27 VPCONFLICTD/Q grammar.
// Both instructions use _yvexpandpd: EVEX X/Y/Z register-or-memory sources,
// optional K1-K7 merge/.Z masking, and scalar-memory broadcast.
var amd64PackedConflictSpecs = map[Op]amd64PackedConflictSpec{
	"VPCONFLICTD": {laneBits: 32},
	"VPCONFLICTQ": {laneBits: 64},
}

func (c *amd64Ctx) lowerPackedConflict(op Op, ins Instr) (ok bool, terminated bool, err error) {
	form, known, err := x86PackedConflictProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	if err := c.validateConflictFunnelMemory(ins, form.x86PackedBinaryForm); err != nil {
		return true, false, err
	}
	spec, byteWidth := form.spec, form.byteWidth
	destination := ins.Args[form.destination]
	mask := ""
	if form.mask >= 0 {
		mask, err = c.loadK(ins.Args[form.mask].Reg)
		if err != nil {
			return true, false, err
		}
	}
	lanes := byteWidth * 8 / spec.laneBits
	// Intel's current E4NF class retains the entire source tuple (or the
	// independent m32/m64 broadcast), including zero masks and dead results.
	values, err := c.loadX86PackedShiftLanes(ins.Args[form.first], byteWidth, spec.laneBits, form.broadcast, "")
	if err != nil {
		return true, false, err
	}
	computed := c.emitPackedConflict(values, lanes, spec.laneBits)
	result := computed
	if form.mask >= 0 {
		old := "zeroinitializer"
		if !form.zeroing {
			oldBytes, err := c.loadPackedCompareBytes(destination, byteWidth)
			if err != nil {
				return true, false, err
			}
			old = c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, spec.laneBits, oldBytes)
		}
		result = amd64ApplyIntegerLaneMask(c, lanes, spec.laneBits, computed, old, mask, form.zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, spec.laneBits, result, byteWidth)
	return true, false, c.storePackedMoveOperand(destination, byteWidth, "%"+out)
}

func (c *amd64Ctx) emitPackedConflict(values string, lanes, laneBits int) string {
	elements := make([]string, lanes)
	for lane := 0; lane < lanes; lane++ {
		extracted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %s, i32 %d\n", extracted, lanes, laneBits, values, lane)
		elements[lane] = "%" + extracted
	}
	result := "zeroinitializer"
	for lane := 0; lane < lanes; lane++ {
		conflicts := "0"
		for prior := 0; prior < lane; prior++ {
			equal := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp eq i%d %s, %s\n", equal, laneBits, elements[lane], elements[prior])
			bit := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d %d, i%d 0\n", bit, equal, laneBits, uint64(1)<<prior, laneBits)
			merged := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = or i%d %s, %%%s\n", merged, laneBits, conflicts, bit)
			conflicts = "%" + merged
		}
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> %s, i%d %s, i32 %d\n", inserted, lanes, laneBits, result, laneBits, conflicts, lane)
		result = "%" + inserted
	}
	return result
}
