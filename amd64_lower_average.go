package plan9asm

import (
	"fmt"
	"strings"
)

// lowerPackedUnsignedAverage implements Go 1.27's complete PAVG/VPAVG family.
// Each unsigned B/W lane computes (a+b+1)>>1. Legacy forms use the ymm table
// (MMX and XMM); VEX/EVEX forms use _yvandnpd without broadcast.
func (c *amd64Ctx) lowerPackedUnsignedAverage(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp, suffix := rawOp, ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	laneBits, vector, recognized := amd64PackedUnsignedAverageProperties(baseOp)
	if !recognized {
		return false, false, nil
	}
	if !vector {
		if suffix != "" {
			return true, false, fmt.Errorf("%s %s does not accept instruction suffixes: %q", c.goarch, baseOp, ins.Raw)
		}
		return c.lowerLegacyPackedUnsignedAverage(baseOp, laneBits, ins)
	}
	return c.lowerVectorPackedUnsignedAverage(baseOp, suffix, laneBits, ins)
}

func amd64PackedUnsignedAverageProperties(op string) (laneBits int, vector, ok bool) {
	switch op {
	case "PAVGB":
		return 8, false, true
	case "PAVGW":
		return 16, false, true
	case "VPAVGB":
		return 8, true, true
	case "VPAVGW":
		return 16, true, true
	default:
		return 0, false, false
	}
}

func (c *amd64Ctx) lowerLegacyPackedUnsignedAverage(baseOp string, laneBits int, ins Instr) (bool, bool, error) {
	if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("%s %s expects MMX/m64, MMX or X/m128, X: %q", c.goarch, baseOp, ins.Raw)
	}
	destination := ins.Args[1].Reg
	if _, mmx := amd64ParseMReg(destination); mmx {
		if ins.Args[0].Kind == OpReg {
			if _, ok := amd64ParseMReg(ins.Args[0].Reg); !ok {
				return true, false, fmt.Errorf("%s %s MMX form requires an MMX source: %q", c.goarch, baseOp, ins.Raw)
			}
		} else if !isAMD64MemoryOperand(ins.Args[0]) {
			return true, false, fmt.Errorf("%s %s MMX form requires MMX or memory source: %q", c.goarch, baseOp, ins.Raw)
		}
		firstBits, err := c.loadLegacyMMXPackedSource(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		secondBits, err := c.loadReg(destination)
		if err != nil {
			return true, false, err
		}
		lanes := 64 / laneBits
		first := c.bitcastI64ToIntegerLanes(lanes, laneBits, firstBits)
		second := c.bitcastI64ToIntegerLanes(lanes, laneBits, secondBits)
		result := c.emitPackedUnsignedAverage(lanes, laneBits, first, second)
		bits := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to i64\n", bits, lanes, laneBits, result)
		return true, false, c.storeReg(destination, "%"+bits)
	}

	if !c.isGoLegacyXReg(destination) {
		return true, false, fmt.Errorf("%s %s destination must be an in-range MMX or X register: %q", c.goarch, baseOp, ins.Raw)
	}
	if ins.Args[0].Kind == OpReg && !c.isGoLegacyXReg(ins.Args[0].Reg) {
		return true, false, fmt.Errorf("%s %s XMM form requires an in-range X source: %q", c.goarch, baseOp, ins.Raw)
	}
	if ins.Args[0].Kind != OpReg && !isAMD64MemoryOperand(ins.Args[0]) {
		return true, false, fmt.Errorf("%s %s XMM form requires X or memory source: %q", c.goarch, baseOp, ins.Raw)
	}
	firstBytes, err := c.loadXVecOperand(ins.Args[0])
	if err != nil {
		return true, false, err
	}
	secondBytes, err := c.loadX(destination)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / laneBits
	first := c.bitcastVectorBytesToIntegerLanes(16, lanes, laneBits, firstBytes)
	second := c.bitcastVectorBytesToIntegerLanes(16, lanes, laneBits, secondBytes)
	result := c.emitPackedUnsignedAverage(lanes, laneBits, first, second)
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <16 x i8>\n", out, lanes, laneBits, result)
	return true, false, c.storeX(destination, "%"+out)
}

func (c *amd64Ctx) lowerVectorPackedUnsignedAverage(baseOp, suffix string, laneBits int, ins Instr) (bool, bool, error) {
	zeroing := false
	switch suffix {
	case "":
	case "Z":
		zeroing = true
	default:
		return true, false, fmt.Errorf("%s %s suffix is absent from Go 1.27's _yvandnpd table: %q", c.goarch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 3 && len(ins.Args) != 4 {
		return true, false, fmt.Errorf("%s %s expects source2, source1, [K mask,] destination: %q", c.goarch, baseOp, ins.Raw)
	}
	masked := len(ins.Args) == 4
	if c.goarch == "386" && masked {
		return true, false, fmt.Errorf("386 %s mask forms exceed the Go assembler frontend's three-operand limit: %q", baseOp, ins.Raw)
	}
	if zeroing && !masked {
		return true, false, fmt.Errorf("%s %s zeroing requires a K1-K7 mask: %q", c.goarch, baseOp, ins.Raw)
	}
	if masked && !amd64NonzeroKOperand(ins.Args[2]) {
		return true, false, fmt.Errorf("%s %s masked form expects K1-K7 as its third operand: %q", c.goarch, baseOp, ins.Raw)
	}

	destination := ins.Args[len(ins.Args)-1]
	if destination.Kind != OpReg {
		return true, false, fmt.Errorf("%s %s destination must be X, Y, or Z: %q", c.goarch, baseOp, ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(destination.Reg)
	if byteWidth != 16 && byteWidth != 32 && byteWidth != 64 ||
		!c.isGoPackedVectorMoveRegister(destination, byteWidth) ||
		!c.isGoPackedVectorMoveRegister(ins.Args[1], byteWidth) {
		return true, false, fmt.Errorf("%s %s source1 and destination must be matching Go vector registers: %q", c.goarch, baseOp, ins.Raw)
	}
	firstArg := ins.Args[0]
	if firstArg.Kind == OpReg {
		if !c.isGoPackedVectorMoveRegister(firstArg, byteWidth) {
			return true, false, fmt.Errorf("%s %s source2 register must match the destination width: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(firstArg) {
		return true, false, fmt.Errorf("%s %s source2 must be a matching vector register or memory: %q", c.goarch, baseOp, ins.Raw)
	}

	firstBytes, err := c.loadPackedCompareBytes(firstArg, byteWidth)
	if err != nil {
		return true, false, err
	}
	secondBytes, err := c.loadPackedCompareBytes(ins.Args[1], byteWidth)
	if err != nil {
		return true, false, err
	}
	lanes := byteWidth * 8 / laneBits
	first := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, laneBits, firstBytes)
	second := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, laneBits, secondBytes)
	result := c.emitPackedUnsignedAverage(lanes, laneBits, first, second)
	if masked {
		mask, err := c.loadK(ins.Args[2].Reg)
		if err != nil {
			return true, false, err
		}
		oldBytes, err := c.loadPackedCompareBytes(destination, byteWidth)
		if err != nil {
			return true, false, err
		}
		old := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, laneBits, oldBytes)
		result = amd64ApplyIntegerLaneMask(c, lanes, laneBits, result, old, mask, zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, laneBits, result, byteWidth)
	return true, false, c.storeVectorBytes(destination.Reg, byteWidth, "%"+out)
}

func (c *amd64Ctx) emitPackedUnsignedAverage(lanes, laneBits int, first, second string) string {
	narrowType := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
	wideBits := laneBits * 2
	wideType := fmt.Sprintf("<%d x i%d>", lanes, wideBits)
	firstWide := c.newTmp()
	secondWide := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext %s %s to %s\n", firstWide, narrowType, first, wideType)
	fmt.Fprintf(c.b, "  %%%s = zext %s %s to %s\n", secondWide, narrowType, second, wideType)
	sum := c.newTmp()
	rounded := c.newTmp()
	average := c.newTmp()
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %%%s\n", sum, wideType, firstWide, secondWide)
	fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %s\n", rounded, wideType, sum, llvmSplatSignedInteger(lanes, wideBits, 1))
	fmt.Fprintf(c.b, "  %%%s = lshr %s %%%s, %s\n", average, wideType, rounded, llvmSplatSignedInteger(lanes, wideBits, 1))
	fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to %s\n", result, wideType, average, narrowType)
	return "%" + result
}
