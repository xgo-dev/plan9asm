package plan9asm

import (
	"fmt"
	"strings"
)

type amd64ImmediatePackedCompareSpec struct {
	laneBits int
	unsigned bool
}

var amd64ImmediatePackedCompareSpecs = map[string]amd64ImmediatePackedCompareSpec{
	"VPCMPB":  {laneBits: 8},
	"VPCMPW":  {laneBits: 16},
	"VPCMPD":  {laneBits: 32},
	"VPCMPQ":  {laneBits: 64},
	"VPCMPUB": {laneBits: 8, unsigned: true},
	"VPCMPUW": {laneBits: 16, unsigned: true},
	"VPCMPUD": {laneBits: 32, unsigned: true},
	"VPCMPUQ": {laneBits: 64, unsigned: true},
}

// lowerImmediatePackedCompare implements the complete Go 1.27 _yvpcmpb
// operand table and all eight signed/unsigned element-width mnemonics.
func (c *amd64Ctx) lowerImmediatePackedCompare(op Op, ins Instr) (ok bool, terminated bool, err error) {
	form, known, err := x86ImmediatePackedCompareProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	writeMask := ""
	if form.mask >= 0 {
		writeMask, err = c.loadK(ins.Args[form.mask].Reg)
		if err != nil {
			return true, false, err
		}
	}
	// Use the existing E4 lane reader: active native reads remain volatile
	// even for constant predicates/dead K outputs, and actual inactive mask
	// lanes alone suppress their accesses. FP spans stay independently checked.
	if form.source.Kind == OpFP {
		if err := c.validateX86PackedShiftFPSpan(form.source.FPOffset, form.memoryBytes); err != nil {
			return true, false, err
		}
	}
	firstValue, err := c.loadX86PackedShiftLanes(form.source, form.byteWidth, form.spec.laneBits, form.broadcast, writeMask)
	if err != nil {
		return true, false, err
	}
	secondValue, err := c.loadPackedCompareLanes(ins.Args[form.second], form.byteWidth, form.spec.laneBits, false)
	if err != nil {
		return true, false, err
	}
	lanes := form.byteWidth * 8 / form.spec.laneBits
	compared := c.emitImmediatePackedComparePredicate(lanes, form.spec.laneBits, secondValue, firstValue, form.predicate, form.unsigned)
	packedType := fmt.Sprintf("i%d", lanes)
	packed := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i1> %s to %s\n", packed, lanes, compared, packedType)
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
	return true, false, c.storeK(ins.Args[form.destination].Reg, result)
}

func (c *amd64Ctx) emitImmediatePackedComparePredicate(lanes, laneBits int, left, right string, immediate uint8, unsigned bool) string {
	switch immediate & 7 {
	case 3:
		return "zeroinitializer"
	case 7:
		return llvmAllTrueI1VectorValue(lanes)
	}
	predicates := [8]string{"eq", "slt", "sle", "", "ne", "sge", "sgt", ""}
	if unsigned {
		predicates = [8]string{"eq", "ult", "ule", "", "ne", "uge", "ugt", ""}
	}
	compared := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp %s <%d x i%d> %s, %s\n", compared, predicates[immediate&7], lanes, laneBits, left, right)
	return "%" + compared
}

func llvmAllTrueI1VectorValue(lanes int) string {
	var value strings.Builder
	value.WriteByte('<')
	for lane := 0; lane < lanes; lane++ {
		if lane != 0 {
			value.WriteString(", ")
		}
		value.WriteString("i1 true")
	}
	value.WriteByte('>')
	return value.String()
}
