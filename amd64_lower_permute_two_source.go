package plan9asm

import (
	"fmt"
	"strings"
)

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

type amd64TwoSourcePermuteSuffixes struct {
	broadcast bool
	zeroing   bool
}

func amd64ParseTwoSourcePermuteSuffixes(rawOp, baseOp string) (amd64TwoSourcePermuteSuffixes, error) {
	var suffixes amd64TwoSourcePermuteSuffixes
	dot := strings.IndexByte(rawOp, '.')
	if dot < 0 {
		return suffixes, nil
	}
	parts := strings.Split(rawOp[dot+1:], ".")
	for index, part := range parts {
		switch part {
		case "BCST":
			if suffixes.broadcast || suffixes.zeroing || index != 0 {
				return suffixes, fmt.Errorf("amd64 %s has invalid or duplicate .BCST suffix", baseOp)
			}
			suffixes.broadcast = true
		case "Z":
			if suffixes.zeroing || index != len(parts)-1 {
				return suffixes, fmt.Errorf("amd64 %s has invalid or duplicate .Z suffix", baseOp)
			}
			suffixes.zeroing = true
		default:
			return suffixes, fmt.Errorf("amd64 %s has unsupported suffix .%s", baseOp, part)
		}
	}
	return suffixes, nil
}

// lowerIndexedPermute implements Go 1.27's complete single- and two-table
// indexed-permute family.
func (c *amd64Ctx) lowerIndexedPermute(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	spec, ok := amd64IndexedPermuteSpecs[Op(baseOp)]
	if !ok {
		return false, false, nil
	}
	suffixes, err := amd64ParseTwoSourcePermuteSuffixes(rawOp, baseOp)
	if err != nil {
		return true, false, fmt.Errorf("%w: %q", err, ins.Raw)
	}
	if suffixes.broadcast && !spec.broadcast {
		return true, false, fmt.Errorf("amd64 %s does not enable broadcast in Go 1.27: %q", baseOp, ins.Raw)
	}
	if len(ins.Args) != 3 && len(ins.Args) != 4 {
		return true, false, fmt.Errorf("amd64 %s expects first source, second source, [K mask,] destination: %q", baseOp, ins.Raw)
	}
	masked := len(ins.Args) == 4
	if masked && c.goarch == "386" {
		return true, false, fmt.Errorf("386 %s masked form exceeds the Go assembler frontend's operand limit: %q", baseOp, ins.Raw)
	}
	if suffixes.zeroing && !masked {
		return true, false, fmt.Errorf("amd64 %s .Z requires a K1-K7 mask: %q", baseOp, ins.Raw)
	}

	destination := ins.Args[len(ins.Args)-1]
	byteWidth := 0
	if destination.Kind == OpReg {
		byteWidth = amd64VectorByteWidth(destination.Reg)
	}
	if byteWidth == 0 || !c.isGoPackedVectorMoveRegister(destination, byteWidth) {
		return true, false, fmt.Errorf("amd64 %s expects an in-range X, Y, or Z destination: %q", baseOp, ins.Raw)
	}
	second := ins.Args[1]
	if !c.isGoPackedVectorMoveRegister(second, byteWidth) {
		return true, false, fmt.Errorf("amd64 %s second source must match the destination width: %q", baseOp, ins.Raw)
	}
	first := ins.Args[0]
	if first.Kind == OpReg {
		if !c.isGoPackedVectorMoveRegister(first, byteWidth) {
			return true, false, fmt.Errorf("amd64 %s first source register must match the destination width: %q", baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(first) {
		return true, false, fmt.Errorf("amd64 %s first source must be a matching vector register or memory: %q", baseOp, ins.Raw)
	}
	if suffixes.broadcast && !isAMD64MemoryOperand(first) {
		return true, false, fmt.Errorf("amd64 %s.BCST requires a memory first source: %q", baseOp, ins.Raw)
	}

	mask := ""
	if masked {
		maskArg := ins.Args[2]
		if maskArg.Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s masked form expects K1-K7: %q", baseOp, ins.Raw)
		}
		maskIndex, validMask := amd64ParseKReg(maskArg.Reg)
		if !validMask || maskIndex == 0 {
			return true, false, fmt.Errorf("amd64 %s masked form expects K1-K7: %q", baseOp, ins.Raw)
		}
		mask, err = c.loadK(maskArg.Reg)
		if err != nil {
			return true, false, err
		}
	}

	lanes := byteWidth * 8 / spec.laneBits
	firstValue, err := c.loadPackedCompareLanes(first, byteWidth, spec.laneBits, suffixes.broadcast)
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
	if masked {
		computed = amd64ApplyIntegerLaneMask(c, lanes, spec.laneBits, computed, old, mask, suffixes.zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, spec.laneBits, computed, byteWidth)
	return true, false, c.storeVectorBytes(destination.Reg, byteWidth, "%"+out)
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
