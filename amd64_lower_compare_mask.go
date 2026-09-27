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
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	broadcast := false
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
		if rawOp[dot+1:] != "BCST" {
			if _, known := amd64ImmediatePackedCompareSpecs[baseOp]; known {
				return true, false, fmt.Errorf("amd64 %s accepts only the .BCST suffix: %q", baseOp, ins.Raw)
			}
			return false, false, nil
		}
		broadcast = true
	}
	spec, ok := amd64ImmediatePackedCompareSpecs[baseOp]
	if !ok {
		return false, false, nil
	}
	// cmd/asm's 386 parser cannot represent the four- and five-operand
	// spellings used by this shared x86 table.
	if c.goarch == "386" {
		return true, false, fmt.Errorf("386 %s exceeds the Go assembler frontend's operand limit: %q", baseOp, ins.Raw)
	}
	if len(ins.Args) != 4 && len(ins.Args) != 5 {
		return true, false, fmt.Errorf("amd64 %s expects $imm8, first source, second source, [K mask,] K destination: %q", baseOp, ins.Raw)
	}
	if ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" || ins.Args[0].Imm < 0 || ins.Args[0].Imm > 255 {
		return true, false, fmt.Errorf("amd64 %s expects an unsigned-byte immediate: %q", baseOp, ins.Raw)
	}

	second := ins.Args[2]
	byteWidth, validWidth := amd64PackedCompareWidth(second)
	if !validWidth || !c.isGoPackedVectorMoveRegister(second, byteWidth) {
		return true, false, fmt.Errorf("amd64 %s second source must be an in-range X, Y, or Z register: %q", baseOp, ins.Raw)
	}
	first := ins.Args[1]
	if first.Kind == OpReg {
		if !c.isGoPackedVectorMoveRegister(first, byteWidth) {
			return true, false, fmt.Errorf("amd64 %s register sources must have matching widths: %q", baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(first) {
		return true, false, fmt.Errorf("amd64 %s first source must be a matching vector register or memory: %q", baseOp, ins.Raw)
	}
	if broadcast {
		if spec.laneBits != 32 && spec.laneBits != 64 {
			return true, false, fmt.Errorf("amd64 %s does not enable broadcast in Go 1.27: %q", baseOp, ins.Raw)
		}
		if !isAMD64MemoryOperand(first) {
			return true, false, fmt.Errorf("amd64 %s.BCST requires a memory first source: %q", baseOp, ins.Raw)
		}
	}

	destination := ins.Args[len(ins.Args)-1]
	if destination.Kind != OpReg {
		return true, false, fmt.Errorf("amd64 %s destination must be K0-K7: %q", baseOp, ins.Raw)
	}
	if _, validDestination := amd64ParseKReg(destination.Reg); !validDestination {
		return true, false, fmt.Errorf("amd64 %s destination must be K0-K7: %q", baseOp, ins.Raw)
	}

	writeMask := ""
	if len(ins.Args) == 5 {
		mask := ins.Args[3]
		if mask.Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s write mask must be K1-K7: %q", baseOp, ins.Raw)
		}
		maskIndex, validMask := amd64ParseKReg(mask.Reg)
		if !validMask || maskIndex == 0 {
			return true, false, fmt.Errorf("amd64 %s write mask must be K1-K7: %q", baseOp, ins.Raw)
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
	compared := c.emitImmediatePackedComparePredicate(lanes, spec.laneBits, secondValue, firstValue, uint8(ins.Args[0].Imm), spec.unsigned)
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
	return true, false, c.storeK(destination.Reg, result)
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
