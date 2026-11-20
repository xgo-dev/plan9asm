package plan9asm

import "fmt"

type amd64IndexedPermuteMode uint8

const (
	amd64IndexedPermuteSingle amd64IndexedPermuteMode = iota
	amd64IndexedPermuteI2
	amd64IndexedPermuteT2
)

type amd64IndexedPermuteSpec struct {
	laneBits  int
	mode      amd64IndexedPermuteMode
	broadcast bool
}

// amd64IndexedPermuteSpecs models the complete Go 1.27 _yvblendmpd grammar
// for the single-table VPERMB/W and both two-table VPERMI2*/VPERMT2*
// families. Broadcast capability is an opcode property, not a consequence of
// lane width alone.
var amd64IndexedPermuteSpecs = map[Op]amd64IndexedPermuteSpec{
	"VPERMB":    {laneBits: 8, mode: amd64IndexedPermuteSingle},
	"VPERMW":    {laneBits: 16, mode: amd64IndexedPermuteSingle},
	"VPERMI2B":  {laneBits: 8, mode: amd64IndexedPermuteI2},
	"VPERMI2W":  {laneBits: 16, mode: amd64IndexedPermuteI2},
	"VPERMI2D":  {laneBits: 32, mode: amd64IndexedPermuteI2, broadcast: true},
	"VPERMI2PS": {laneBits: 32, mode: amd64IndexedPermuteI2, broadcast: true},
	"VPERMI2Q":  {laneBits: 64, mode: amd64IndexedPermuteI2, broadcast: true},
	"VPERMI2PD": {laneBits: 64, mode: amd64IndexedPermuteI2, broadcast: true},
	"VPERMT2B":  {laneBits: 8, mode: amd64IndexedPermuteT2},
	"VPERMT2W":  {laneBits: 16, mode: amd64IndexedPermuteT2},
	"VPERMT2D":  {laneBits: 32, mode: amd64IndexedPermuteT2, broadcast: true},
	"VPERMT2PS": {laneBits: 32, mode: amd64IndexedPermuteT2, broadcast: true},
	"VPERMT2Q":  {laneBits: 64, mode: amd64IndexedPermuteT2, broadcast: true},
	"VPERMT2PD": {laneBits: 64, mode: amd64IndexedPermuteT2, broadcast: true},
}

// lowerIndexedPermute implements Go 1.27's complete single- and two-table
// indexed-permute family.
func (c *amd64Ctx) lowerIndexedPermute(op Op, ins Instr) (ok bool, terminated bool, err error) {
	form, spec, known, err := x86IndexedPermuteProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	destination := ins.Args[form.destination]
	first, second, byteWidth := ins.Args[form.first], ins.Args[form.second], form.byteWidth
	mask := ""
	if form.mask >= 0 {
		mask, err = c.loadK(ins.Args[form.mask].Reg)
		if err != nil {
			return true, false, err
		}
	}

	lanes := byteWidth * 8 / spec.laneBits
	// Indexed table reads are E4NF, not destination-lane masked loads. Keep
	// the complete tuple/broadcast even for zero masks or unused tables.
	firstValue, err := c.loadX86PackedShiftLanes(first, byteWidth, spec.laneBits, form.broadcast, "")
	if err != nil {
		return true, false, err
	}
	secondValue, err := c.loadPackedCompareLanes(second, byteWidth, spec.laneBits, false)
	if err != nil {
		return true, false, err
	}
	oldBytes, err := c.loadPackedCompareBytes(destination, byteWidth)
	if err != nil {
		return true, false, err
	}
	old := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, spec.laneBits, oldBytes)
	computed := ""
	switch spec.mode {
	case amd64IndexedPermuteSingle:
		// Plan 9 lists Intel's r/m table first and its index vector second.
		computed = c.emitSingleTablePermute(lanes, spec.laneBits, firstValue, secondValue)
	case amd64IndexedPermuteI2:
		// VPERMI2 gets indices from the old destination. Intel calls the
		// Plan 9 second operand table 0 and the first operand table 1.
		computed = c.emitTwoTablePermute(lanes, spec.laneBits, secondValue, firstValue, old)
	case amd64IndexedPermuteT2:
		// VPERMT2 gets indices from the Plan 9 second operand. The old
		// destination is table 0 and the Plan 9 first operand is table 1.
		computed = c.emitTwoTablePermute(lanes, spec.laneBits, old, firstValue, secondValue)
	}
	if form.mask >= 0 {
		computed = amd64ApplyIntegerLaneMask(c, lanes, spec.laneBits, computed, old, mask, form.zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, spec.laneBits, computed, byteWidth)
	return true, false, c.storePackedMoveOperand(destination, byteWidth, "%"+out)
}

func (c *amd64Ctx) emitSingleTablePermute(lanes, laneBits int, table, indices string) string {
	result := "zeroinitializer"
	for lane := 0; lane < lanes; lane++ {
		indexValue := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %s, i32 %d\n", indexValue, lanes, laneBits, indices, lane)
		bounded := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i%d %%%s, %d\n", bounded, laneBits, indexValue, lanes-1)
		indexI32 := "%" + bounded
		if laneBits < 32 {
			converted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i%d %%%s to i32\n", converted, laneBits, bounded)
			indexI32 = "%" + converted
		} else if laneBits > 32 {
			converted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i%d %%%s to i32\n", converted, laneBits, bounded)
			indexI32 = "%" + converted
		}
		selected := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %s, i32 %s\n", selected, lanes, laneBits, table, indexI32)
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> %s, i%d %%%s, i32 %d\n", inserted, lanes, laneBits, result, laneBits, selected, lane)
		result = "%" + inserted
	}
	return result
}

func (c *amd64Ctx) emitTwoTablePermute(lanes, laneBits int, table0, table1, indices string) string {
	result := "zeroinitializer"
	for lane := 0; lane < lanes; lane++ {
		indexValue := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %s, i32 %d\n", indexValue, lanes, laneBits, indices, lane)
		bounded := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i%d %%%s, %d\n", bounded, laneBits, indexValue, 2*lanes-1)
		useTable1 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp uge i%d %%%s, %d\n", useTable1, laneBits, bounded, lanes)
		withinTable := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i%d %%%s, %d\n", withinTable, laneBits, bounded, lanes-1)
		indexI32 := "%" + withinTable
		if laneBits < 32 {
			converted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i%d %%%s to i32\n", converted, laneBits, withinTable)
			indexI32 = "%" + converted
		} else if laneBits > 32 {
			converted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i%d %%%s to i32\n", converted, laneBits, withinTable)
			indexI32 = "%" + converted
		}
		fromTable0 := c.newTmp()
		fromTable1 := c.newTmp()
		selected := c.newTmp()
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %s, i32 %s\n", fromTable0, lanes, laneBits, table0, indexI32)
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %s, i32 %s\n", fromTable1, lanes, laneBits, table1, indexI32)
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d %%%s, i%d %%%s\n", selected, useTable1, laneBits, fromTable1, laneBits, fromTable0)
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> %s, i%d %%%s, i32 %d\n", inserted, lanes, laneBits, result, laneBits, selected, lane)
		result = "%" + inserted
	}
	return result
}
