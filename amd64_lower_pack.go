package plan9asm

import (
	"fmt"
	"strings"
)

type amd64PackedNarrowMode uint8

const (
	amd64PackedNarrowSigned amd64PackedNarrowMode = iota
	amd64PackedNarrowUnsigned
)

// lowerPackedSaturatingNarrow implements Go 1.27's complete saturating pack
// family. The legacy dword-to-word spelling is PACKSSLW; its VEX/EVEX
// counterpart follows Intel spelling and is VPACKSSDW.
func (c *amd64Ctx) lowerPackedSaturatingNarrow(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	suffix := ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	inputBits, outputBits, mode, vector, recognized := amd64PackedNarrowProperties(baseOp)
	if !recognized {
		return false, false, nil
	}
	if !vector {
		return c.lowerLegacyPackedSaturatingNarrow(baseOp, suffix, inputBits, outputBits, mode, ins)
	}
	return c.lowerVectorPackedSaturatingNarrow(baseOp, suffix, inputBits, outputBits, mode, ins)
}

func amd64PackedNarrowProperties(op string) (inputBits, outputBits int, mode amd64PackedNarrowMode, vector, ok bool) {
	switch op {
	case "PACKSSLW":
		return 32, 16, amd64PackedNarrowSigned, false, true
	case "PACKSSWB":
		return 16, 8, amd64PackedNarrowSigned, false, true
	case "PACKUSDW":
		return 32, 16, amd64PackedNarrowUnsigned, false, true
	case "PACKUSWB":
		return 16, 8, amd64PackedNarrowUnsigned, false, true
	case "VPACKSSDW":
		return 32, 16, amd64PackedNarrowSigned, true, true
	case "VPACKSSWB":
		return 16, 8, amd64PackedNarrowSigned, true, true
	case "VPACKUSDW":
		return 32, 16, amd64PackedNarrowUnsigned, true, true
	case "VPACKUSWB":
		return 16, 8, amd64PackedNarrowUnsigned, true, true
	default:
		return 0, 0, 0, false, false
	}
}

func (c *amd64Ctx) lowerLegacyPackedSaturatingNarrow(baseOp, suffix string, inputBits, outputBits int, mode amd64PackedNarrowMode, ins Instr) (bool, bool, error) {
	if suffix != "" {
		return true, false, fmt.Errorf("amd64 %s has no instruction suffixes in Go 1.27's legacy optab: %q", baseOp, ins.Raw)
	}
	if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("amd64 %s expects packed source, packed destination: %q", baseOp, ins.Raw)
	}
	dst := ins.Args[1].Reg
	if _, mmx := amd64ParseMReg(dst); mmx {
		if baseOp == "PACKUSDW" {
			return true, false, fmt.Errorf("amd64 PACKUSDW has no MMX form in Go 1.27's yxm_q4 table: %q", ins.Raw)
		}
		if ins.Args[0].Kind == OpReg {
			if _, ok := amd64ParseMReg(ins.Args[0].Reg); !ok {
				return true, false, fmt.Errorf("amd64 %s MMX form requires an MMX source: %q", baseOp, ins.Raw)
			}
		} else if !isAMD64MemoryOperand(ins.Args[0]) {
			return true, false, fmt.Errorf("amd64 %s MMX form requires MMX or memory source: %q", baseOp, ins.Raw)
		}
		firstBits, err := c.loadLegacyMMXPackedSource(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		secondBits, err := c.loadReg(dst)
		if err != nil {
			return true, false, err
		}
		inputLanes := 64 / inputBits
		first := c.bitcastI64ToIntegerLanes(inputLanes, inputBits, firstBits)
		second := c.bitcastI64ToIntegerLanes(inputLanes, inputBits, secondBits)
		result := c.emitPackedSaturatingNarrow(8, inputBits, outputBits, mode, first, second)
		bits := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to i64\n", bits, 64/outputBits, outputBits, result)
		return true, false, c.storeReg(dst, "%"+bits)
	}

	if !c.isGoLegacyXReg(dst) {
		return true, false, fmt.Errorf("amd64 %s destination is outside Go 1.27's X-register class for %s: %q", baseOp, c.goarch, ins.Raw)
	}
	if ins.Args[0].Kind == OpReg {
		if !c.isGoLegacyXReg(ins.Args[0].Reg) {
			return true, false, fmt.Errorf("amd64 %s XMM form requires an X source valid for %s: %q", baseOp, c.goarch, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(ins.Args[0]) {
		return true, false, fmt.Errorf("amd64 %s XMM form requires X or memory source: %q", baseOp, ins.Raw)
	}
	firstBytes, err := c.loadPackedCompareBytes(ins.Args[0], 16)
	if err != nil {
		return true, false, err
	}
	secondBytes, err := c.loadX(dst)
	if err != nil {
		return true, false, err
	}
	inputLanes := 128 / inputBits
	first := c.bitcastVectorBytesToIntegerLanes(16, inputLanes, inputBits, firstBytes)
	second := c.bitcastVectorBytesToIntegerLanes(16, inputLanes, inputBits, secondBytes)
	result := c.emitPackedSaturatingNarrow(16, inputBits, outputBits, mode, first, second)
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <16 x i8>\n", out, 128/outputBits, outputBits, result)
	return true, false, c.storeX(dst, "%"+out)
}

func (c *amd64Ctx) lowerVectorPackedSaturatingNarrow(baseOp, suffix string, inputBits, outputBits int, mode amd64PackedNarrowMode, ins Instr) (bool, bool, error) {
	if c.goarch != "amd64" {
		return true, false, fmt.Errorf("%s %s is absent from Go 1.27's 386 assembler forms: %q", c.goarch, baseOp, ins.Raw)
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
		return true, false, fmt.Errorf("amd64 %s suffix is absent from its Go 1.27 VEX/EVEX table: %q", baseOp, ins.Raw)
	}
	if broadcast && inputBits != 32 {
		return true, false, fmt.Errorf("amd64 %s does not enable EVEX broadcast: %q", baseOp, ins.Raw)
	}
	if len(ins.Args) != 3 && len(ins.Args) != 4 {
		return true, false, fmt.Errorf("amd64 %s expects src1, src2, [K mask,] destination: %q", baseOp, ins.Raw)
	}
	dstArg := ins.Args[len(ins.Args)-1]
	if dstArg.Kind != OpReg {
		return true, false, fmt.Errorf("amd64 %s destination must be X, Y, or Z: %q", baseOp, ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(dstArg.Reg)
	if byteWidth != 16 && byteWidth != 32 && byteWidth != 64 {
		return true, false, fmt.Errorf("amd64 %s destination must be X, Y, or Z: %q", baseOp, ins.Raw)
	}
	if !amd64EVEXVectorRegister(ins.Args[1], byteWidth) {
		return true, false, fmt.Errorf("amd64 %s second source must match the destination width: %q", baseOp, ins.Raw)
	}
	if ins.Args[0].Kind == OpReg {
		if !amd64EVEXVectorRegister(ins.Args[0], byteWidth) {
			return true, false, fmt.Errorf("amd64 %s first source must match the destination width: %q", baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(ins.Args[0]) {
		return true, false, fmt.Errorf("amd64 %s first source must be a vector register or memory: %q", baseOp, ins.Raw)
	}
	if broadcast && !isAMD64MemoryOperand(ins.Args[0]) {
		return true, false, fmt.Errorf("amd64 %s.BCST requires a memory first source: %q", baseOp, ins.Raw)
	}

	masked := len(ins.Args) == 4
	if zeroing && !masked {
		return true, false, fmt.Errorf("amd64 %s zeroing requires a K1-K7 mask: %q", baseOp, ins.Raw)
	}
	var mask string
	if masked {
		maskArg := ins.Args[2]
		if maskArg.Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s masked form expects K1-K7: %q", baseOp, ins.Raw)
		}
		index, ok := amd64ParseKReg(maskArg.Reg)
		if !ok || index == 0 {
			return true, false, fmt.Errorf("amd64 %s masked form expects K1-K7: %q", baseOp, ins.Raw)
		}
		var err error
		mask, err = c.loadK(maskArg.Reg)
		if err != nil {
			return true, false, err
		}
	}

	evex := masked || suffix != "" || byteWidth == 64 || !amd64VEXVectorRegister(dstArg, byteWidth) || !amd64VEXVectorRegister(ins.Args[1], byteWidth)
	if ins.Args[0].Kind == OpReg && !amd64VEXVectorRegister(ins.Args[0], byteWidth) {
		evex = true
	}
	if !evex {
		if byteWidth == 64 {
			return true, false, fmt.Errorf("amd64 %s has no 512-bit VEX form: %q", baseOp, ins.Raw)
		}
	} else if !amd64EVEXVectorRegister(dstArg, byteWidth) {
		return true, false, fmt.Errorf("amd64 %s EVEX destination is invalid: %q", baseOp, ins.Raw)
	}

	inputLanes := byteWidth * 8 / inputBits
	var first string
	var err error
	if broadcast {
		first, err = c.evalIntSized(ins.Args[0], amd64IntegerTypeForBits(inputBits))
		if err == nil {
			first = amd64SplatInteger(c, inputLanes, inputBits, first)
		}
	} else {
		var firstBytes string
		firstBytes, err = c.loadPackedCompareBytes(ins.Args[0], byteWidth)
		if err == nil {
			first = c.bitcastVectorBytesToIntegerLanes(byteWidth, inputLanes, inputBits, firstBytes)
		}
	}
	if err != nil {
		return true, false, err
	}
	secondBytes, err := c.loadPackedCompareBytes(ins.Args[1], byteWidth)
	if err != nil {
		return true, false, err
	}
	second := c.bitcastVectorBytesToIntegerLanes(byteWidth, inputLanes, inputBits, secondBytes)
	result := c.emitPackedSaturatingNarrow(byteWidth, inputBits, outputBits, mode, first, second)
	outputLanes := byteWidth * 8 / outputBits
	if masked {
		oldBytes, err := c.loadPackedCompareBytes(dstArg, byteWidth)
		if err != nil {
			return true, false, err
		}
		old := c.bitcastVectorBytesToIntegerLanes(byteWidth, outputLanes, outputBits, oldBytes)
		result = amd64ApplyIntegerLaneMask(c, outputLanes, outputBits, result, old, mask, zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, outputLanes, outputBits, result, byteWidth)
	return true, false, c.storeVectorBytes(dstArg.Reg, byteWidth, "%"+out)
}

func (c *amd64Ctx) emitPackedSaturatingNarrow(byteWidth, inputBits, outputBits int, mode amd64PackedNarrowMode, first, second string) string {
	inputLanes := byteWidth * 8 / inputBits
	outputLanes := byteWidth * 8 / outputBits
	chunkBits := 128
	if byteWidth < 16 {
		chunkBits = byteWidth * 8
	}
	inputLanesPerChunk := chunkBits / inputBits
	outputLanesPerChunk := chunkBits / outputBits
	chunks := byteWidth * 8 / chunkBits
	result := "zeroinitializer"
	for chunk := 0; chunk < chunks; chunk++ {
		for sourceHalf, source := range []string{second, first} {
			for lane := 0; lane < inputLanesPerChunk; lane++ {
				inputIndex := chunk*inputLanesPerChunk + lane
				outputIndex := chunk*outputLanesPerChunk + sourceHalf*inputLanesPerChunk + lane
				value := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %s, i32 %d\n", value, inputLanes, inputBits, source, inputIndex)
				narrowed := c.saturatePackedInteger("%"+value, inputBits, outputBits, mode)
				inserted := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> %s, i%d %s, i32 %d\n", inserted, outputLanes, outputBits, result, outputBits, narrowed, outputIndex)
				result = "%" + inserted
			}
		}
	}
	return result
}

func (c *amd64Ctx) saturatePackedInteger(value string, inputBits, outputBits int, mode amd64PackedNarrowMode) string {
	minValue := -(int64(1) << (outputBits - 1))
	maxValue := (int64(1) << (outputBits - 1)) - 1
	clamped := value
	if mode == amd64PackedNarrowUnsigned {
		minValue = 0
		maxValue = (int64(1) << outputBits) - 1
		below := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp slt i%d %s, 0\n", below, inputBits, clamped)
		nonnegative := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d 0, i%d %s\n", nonnegative, below, inputBits, inputBits, clamped)
		clamped = "%" + nonnegative
	}
	above := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp sgt i%d %s, %d\n", above, inputBits, clamped, maxValue)
	capped := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d %d, i%d %s\n", capped, above, inputBits, maxValue, inputBits, clamped)
	clamped = "%" + capped
	if mode == amd64PackedNarrowSigned {
		below := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp slt i%d %s, %d\n", below, inputBits, clamped, minValue)
		floored := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d %d, i%d %s\n", floored, below, inputBits, minValue, inputBits, clamped)
		clamped = "%" + floored
	}
	narrowed := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i%d %s to i%d\n", narrowed, inputBits, clamped, outputBits)
	return "%" + narrowed
}
