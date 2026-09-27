package plan9asm

import (
	"fmt"
	"strings"
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
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	suffix := ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	spec, ok := amd64PackedTestMaskSpecs[baseOp]
	if !ok {
		return false, false, nil
	}
	broadcast := suffix == "BCST"
	if suffix != "" && !broadcast {
		return true, false, fmt.Errorf("%s %s accepts only the .BCST suffix supported by Go 1.27: %q", c.goarch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 3 && len(ins.Args) != 4 {
		return true, false, fmt.Errorf("%s %s expects first source, second source, [K mask,] K destination: %q", c.goarch, baseOp, ins.Raw)
	}
	if c.goarch == "386" && len(ins.Args) == 4 && !ins.x86Encoded {
		return true, false, fmt.Errorf("386 %s write-mask forms exceed the Go assembler frontend's three-operand limit: %q", baseOp, ins.Raw)
	}

	second := ins.Args[1]
	byteWidth, validWidth := amd64PackedCompareWidth(second)
	if !validWidth || !c.isGoPackedVectorMoveRegister(second, byteWidth) {
		return true, false, fmt.Errorf("%s %s second source must be an in-range X, Y, or Z register: %q", c.goarch, baseOp, ins.Raw)
	}
	first := ins.Args[0]
	if first.Kind == OpReg {
		if !c.isGoPackedVectorMoveRegister(first, byteWidth) {
			return true, false, fmt.Errorf("%s %s register sources must have matching widths and be in range: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(first) {
		return true, false, fmt.Errorf("%s %s first source must be a matching vector register or memory: %q", c.goarch, baseOp, ins.Raw)
	}
	if broadcast {
		if spec.laneBits != 32 && spec.laneBits != 64 {
			return true, false, fmt.Errorf("%s %s does not enable broadcast in Go 1.27: %q", c.goarch, baseOp, ins.Raw)
		}
		if !isAMD64MemoryOperand(first) {
			return true, false, fmt.Errorf("%s %s.BCST requires a memory first source: %q", c.goarch, baseOp, ins.Raw)
		}
	}

	destination := ins.Args[len(ins.Args)-1]
	if destination.Kind != OpReg {
		return true, false, fmt.Errorf("%s %s destination must be K0-K7: %q", c.goarch, baseOp, ins.Raw)
	}
	if _, validDestination := amd64ParseKReg(destination.Reg); !validDestination {
		return true, false, fmt.Errorf("%s %s destination must be K0-K7: %q", c.goarch, baseOp, ins.Raw)
	}

	writeMask := ""
	if len(ins.Args) == 4 {
		mask := ins.Args[2]
		if mask.Kind != OpReg {
			return true, false, fmt.Errorf("%s %s write mask must be K1-K7: %q", c.goarch, baseOp, ins.Raw)
		}
		maskIndex, validMask := amd64ParseKReg(mask.Reg)
		if !validMask || maskIndex == 0 {
			return true, false, fmt.Errorf("%s %s write mask must be K1-K7: %q", c.goarch, baseOp, ins.Raw)
		}
		writeMask, err = c.loadK(mask.Reg)
		if err != nil {
			return true, false, err
		}
	}

	firstValue, err := c.loadPackedCompareLanes(first, byteWidth, spec.laneBits, broadcast)
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
