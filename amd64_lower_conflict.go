package plan9asm

import (
	"fmt"
	"strings"
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
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	suffix := ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	spec, recognized := amd64PackedConflictSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	broadcast, zeroing := false, false
	switch suffix {
	case "":
	case "Z":
		zeroing = true
	case "BCST":
		broadcast = true
	case "BCST.Z":
		broadcast, zeroing = true, true
	default:
		return true, false, fmt.Errorf("%s %s has a suffix outside Go 1.27's _yvexpandpd form: %q", c.goarch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 2 && len(ins.Args) != 3 {
		return true, false, fmt.Errorf("%s %s expects source, [K1-K7,] destination: %q", c.goarch, baseOp, ins.Raw)
	}
	masked := len(ins.Args) == 3
	if zeroing && !masked {
		return true, false, fmt.Errorf("%s %s.Z requires a K1-K7 mask: %q", c.goarch, baseOp, ins.Raw)
	}

	destination := ins.Args[len(ins.Args)-1]
	if destination.Kind != OpReg {
		return true, false, fmt.Errorf("%s %s requires an X, Y, or Z destination: %q", c.goarch, baseOp, ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(destination.Reg)
	if byteWidth == 0 || !c.isGoEVEXVectorRegister(destination, byteWidth) {
		return true, false, fmt.Errorf("%s %s destination is outside Go's EVEX register range: %q", c.goarch, baseOp, ins.Raw)
	}
	source := ins.Args[0]
	if broadcast {
		if !isAMD64MemoryOperand(source) {
			return true, false, fmt.Errorf("%s %s.BCST requires a scalar memory source: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(source) && !c.isGoEVEXVectorRegister(source, byteWidth) {
		return true, false, fmt.Errorf("%s %s source must be a matching X/Y/Z register or memory: %q", c.goarch, baseOp, ins.Raw)
	}

	mask := ""
	if masked {
		maskArg := ins.Args[1]
		maskIndex, valid := amd64ParseKReg(maskArg.Reg)
		if maskArg.Kind != OpReg || !valid || maskIndex == 0 {
			return true, false, fmt.Errorf("%s %s masked form requires K1-K7: %q", c.goarch, baseOp, ins.Raw)
		}
		mask, err = c.loadK(maskArg.Reg)
		if err != nil {
			return true, false, err
		}
	}

	lanes := byteWidth * 8 / spec.laneBits
	values, err := c.loadPackedCompareLanes(source, byteWidth, spec.laneBits, broadcast)
	if err != nil {
		return true, false, err
	}
	computed := c.emitPackedConflict(values, lanes, spec.laneBits)
	result := computed
	if masked {
		oldBytes, err := c.loadPackedCompareBytes(destination, byteWidth)
		if err != nil {
			return true, false, err
		}
		old := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, spec.laneBits, oldBytes)
		result = amd64ApplyIntegerLaneMask(c, lanes, spec.laneBits, computed, old, mask, zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, spec.laneBits, result, byteWidth)
	return true, false, c.storeVectorBytes(destination.Reg, byteWidth, "%"+out)
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
