package plan9asm

import (
	"fmt"
	"strings"
)

// lowerPackedByteShuffle implements all Go 1.27 PSHUFB/VPSHUFB forms.
// VPSHUFB applies the byte shuffle independently to each 128-bit lane; EVEX
// writemasks operate at byte granularity.
func (c *amd64Ctx) lowerPackedByteShuffle(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	suffix := ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	switch baseOp {
	case "PSHUFB":
		return c.lowerLegacyPackedByteShuffle(suffix, ins)
	case "VPSHUFB":
		return c.lowerVectorPackedByteShuffle(suffix, ins)
	default:
		return false, false, nil
	}
}

func (c *amd64Ctx) lowerLegacyPackedByteShuffle(suffix string, ins Instr) (bool, bool, error) {
	if suffix != "" {
		return true, false, fmt.Errorf("%s PSHUFB has no instruction suffixes in Go 1.27's ymshufb table: %q", c.goarch, ins.Raw)
	}
	if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg || !c.isGoLegacyXReg(ins.Args[1].Reg) {
		return true, false, fmt.Errorf("%s PSHUFB expects X/m128, X: %q", c.goarch, ins.Raw)
	}
	if ins.Args[0].Kind == OpReg {
		if !c.isGoLegacyXReg(ins.Args[0].Reg) {
			return true, false, fmt.Errorf("%s PSHUFB source is outside Go 1.27's legacy X class: %q", c.goarch, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(ins.Args[0]) {
		return true, false, fmt.Errorf("%s PSHUFB source must be X or memory: %q", c.goarch, ins.Raw)
	}
	control, err := c.loadPackedCompareBytes(ins.Args[0], 16)
	if err != nil {
		return true, false, err
	}
	data, err := c.loadX(ins.Args[1].Reg)
	if err != nil {
		return true, false, err
	}
	result := c.emitPackedByteShuffle(16, data, control)
	return true, false, c.storeX(ins.Args[1].Reg, result)
}

func (c *amd64Ctx) lowerVectorPackedByteShuffle(suffix string, ins Instr) (bool, bool, error) {
	zeroing := false
	switch suffix {
	case "":
	case "Z":
		zeroing = true
	default:
		return true, false, fmt.Errorf("%s VPSHUFB suffix is absent from Go 1.27's _yvandnpd table: %q", c.goarch, ins.Raw)
	}
	if len(ins.Args) != 3 && len(ins.Args) != 4 {
		return true, false, fmt.Errorf("%s VPSHUFB expects control, data, [K mask,] destination: %q", c.goarch, ins.Raw)
	}
	masked := len(ins.Args) == 4
	if c.goarch == "386" && masked {
		return true, false, fmt.Errorf("386 VPSHUFB mask forms exceed the Go assembler frontend's three-operand limit: %q", ins.Raw)
	}
	if zeroing && !masked {
		return true, false, fmt.Errorf("%s VPSHUFB zeroing requires a K1-K7 mask: %q", c.goarch, ins.Raw)
	}
	if masked && !amd64NonzeroKOperand(ins.Args[2]) {
		return true, false, fmt.Errorf("%s VPSHUFB masked form expects K1-K7: %q", c.goarch, ins.Raw)
	}

	destination := ins.Args[len(ins.Args)-1]
	if destination.Kind != OpReg {
		return true, false, fmt.Errorf("%s VPSHUFB destination must be X, Y, or Z: %q", c.goarch, ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(destination.Reg)
	if byteWidth != 16 && byteWidth != 32 && byteWidth != 64 || !c.isGoVPSHUFBRegister(destination, byteWidth) {
		return true, false, fmt.Errorf("%s VPSHUFB destination is outside Go 1.27's vector-register class: %q", c.goarch, ins.Raw)
	}
	if !c.isGoVPSHUFBRegister(ins.Args[1], byteWidth) {
		return true, false, fmt.Errorf("%s VPSHUFB data source must match the destination width: %q", c.goarch, ins.Raw)
	}
	if ins.Args[0].Kind == OpReg {
		if !c.isGoVPSHUFBRegister(ins.Args[0], byteWidth) {
			return true, false, fmt.Errorf("%s VPSHUFB control source must match the destination width: %q", c.goarch, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(ins.Args[0]) {
		return true, false, fmt.Errorf("%s VPSHUFB control source must be a vector register or memory: %q", c.goarch, ins.Raw)
	}

	data, err := c.loadPackedCompareBytes(ins.Args[1], byteWidth)
	if err != nil {
		return true, false, err
	}
	var result string
	if ins.x86RIPLiteral && len(ins.x86RIPLiteralData) == byteWidth {
		result = c.emitPackedByteShuffleLiteral(byteWidth, data, ins.x86RIPLiteralData)
	} else {
		control, err := c.loadPackedCompareBytes(ins.Args[0], byteWidth)
		if err != nil {
			return true, false, err
		}
		result = c.emitPackedByteShuffle(byteWidth, data, control)
	}
	if masked {
		mask, err := c.loadK(ins.Args[2].Reg)
		if err != nil {
			return true, false, err
		}
		old, err := c.loadPackedCompareBytes(destination, byteWidth)
		if err != nil {
			return true, false, err
		}
		result = amd64ApplyIntegerLaneMask(c, byteWidth, 8, result, old, mask, zeroing)
	}
	return true, false, c.storeVectorBytes(destination.Reg, byteWidth, result)
}

func (c *amd64Ctx) emitPackedByteShuffleLiteral(byteWidth int, data string, control []byte) string {
	indices := make([]int, byteWidth)
	for index, selected := range control {
		if selected&0x80 != 0 {
			indices[index] = byteWidth // Select a zero from the second vector.
		} else {
			indices[index] = index/16*16 + int(selected&0x0f)
		}
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i8> %s, <%d x i8> zeroinitializer, <%d x i32> %s\n",
		result, byteWidth, data, byteWidth, byteWidth, llvmI32Mask(indices))
	return "%" + result
}

func (c *amd64Ctx) isGoVPSHUFBRegister(arg Operand, byteWidth int) bool {
	if !amd64EVEXVectorRegister(arg, byteWidth) {
		return false
	}
	if c.goarch == "386" && byteWidth == 64 {
		index, _ := amd64VectorRegisterIndex(arg.Reg, byteWidth)
		return index < 8
	}
	return true
}

func (c *amd64Ctx) emitPackedByteShuffle(byteWidth int, data, control string) string {
	if byteWidth == 16 {
		call := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call <16 x i8> @llvm.x86.ssse3.pshuf.b.128(<16 x i8> %s, <16 x i8> %s)\n", call, data, control)
		return "%" + call
	}

	parts := make([]string, 0, byteWidth/16)
	for lane := 0; lane < byteWidth/16; lane++ {
		dataLane := c.newTmp()
		controlLane := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i8> %s, <%d x i8> poison, <16 x i32> %s\n", dataLane, byteWidth, data, byteWidth, llvmI32RangeMask(lane*16, 16))
		fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i8> %s, <%d x i8> poison, <16 x i32> %s\n", controlLane, byteWidth, control, byteWidth, llvmI32RangeMask(lane*16, 16))
		call := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call <16 x i8> @llvm.x86.ssse3.pshuf.b.128(<16 x i8> %%%s, <16 x i8> %%%s)\n", call, dataLane, controlLane)
		parts = append(parts, "%"+call)
	}
	partWidth := 16
	for len(parts) > 1 {
		combined := make([]string, 0, len(parts)/2)
		for i := 0; i < len(parts); i += 2 {
			joined := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i8> %s, <%d x i8> %s, <%d x i32> %s\n", joined, partWidth, parts[i], partWidth, parts[i+1], partWidth*2, llvmI32RangeMask(0, partWidth*2))
			combined = append(combined, "%"+joined)
		}
		parts = combined
		partWidth *= 2
	}
	return parts[0]
}
