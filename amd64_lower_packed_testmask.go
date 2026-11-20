package plan9asm

import (
	"fmt"
)

type amd64PackedTestMaskSpec struct {
	laneBits int
	testZero bool
}

var amd64PackedTestMaskSpecs = map[string]amd64PackedTestMaskSpec{
	"VPTESTMB":  {laneBits: 8},
	"VPTESTMW":  {laneBits: 16},
	"VPTESTMD":  {laneBits: 32},
	"VPTESTMQ":  {laneBits: 64},
	"VPTESTNMB": {laneBits: 8, testZero: true},
	"VPTESTNMW": {laneBits: 16, testZero: true},
	"VPTESTNMD": {laneBits: 32, testZero: true},
	"VPTESTNMQ": {laneBits: 64, testZero: true},
}

// lowerPackedTestMask implements the complete Go 1.27 _yvpshufbitqmb
// operand table shared by VPTESTM{B,W,D,Q} and VPTESTNM{B,W,D,Q}.
// VPTESTM sets each K bit when the corresponding source-lane intersection is
// nonzero; VPTESTNM sets it when that intersection is zero.
func (c *amd64Ctx) lowerPackedTestMask(op Op, ins Instr) (ok bool, terminated bool, err error) {
	form, known, err := x86PackedTestMaskProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	spec, byteWidth := form.spec, form.byteWidth
	first, second := form.source, ins.Args[form.second]
	destination := ins.Args[form.destination]
	writeMask := ""
	if form.mask >= 0 {
		writeMask, err = c.loadK(ins.Args[form.mask].Reg)
		if err != nil {
			return true, false, err
		}
	}
	firstValue, err := c.loadX86PackedShiftLanes(first, byteWidth, spec.laneBits, form.broadcast, writeMask)
	if err != nil {
		return true, false, err
	}
	secondValue, err := c.loadPackedCompareLanes(second, byteWidth, spec.laneBits, false)
	if err != nil {
		return true, false, err
	}
	lanes := byteWidth * 8 / spec.laneBits
	vectorType := fmt.Sprintf("<%d x i%d>", lanes, spec.laneBits)
	intersection := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and %s %s, %s\n", intersection, vectorType, firstValue, secondValue)
	predicate := "ne"
	if spec.testZero {
		predicate = "eq"
	}
	tested := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp %s %s %%%s, zeroinitializer\n", tested, predicate, vectorType, intersection)
	packedType := fmt.Sprintf("i%d", lanes)
	packed := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i1> %%%s to %s\n", packed, lanes, tested, packedType)
	result := "%" + packed
	if lanes < 64 {
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext %s %s to i64\n", wide, packedType, result)
		result = "%" + wide
	}
	if writeMask != "" {
		masked := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %s, %s\n", masked, result, writeMask)
		result = "%" + masked
	}
	return true, false, c.storeK(destination.Reg, result)
}
