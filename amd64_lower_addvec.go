package plan9asm

import (
	"fmt"
	"strings"
)

type amd64PackedAddMode uint8

const (
	amd64PackedAddWrap amd64PackedAddMode = iota
	amd64PackedAddSignedSaturating
	amd64PackedAddUnsignedSaturating
)

type amd64PackedAddForm uint8

const (
	// amd64PackedAddLegacyYMM is Go's ymm table: MMX/m64 and XMM/m128.
	// Go only exposes the MMX rows in amd64 mode.
	amd64PackedAddLegacyYMM amd64PackedAddForm = iota
	// amd64PackedAddLegacyYXM is Go's yxm table: XMM/m128 only.
	amd64PackedAddLegacyYXM
	// amd64PackedAddVEXEVEX is Go's _yvandnpd table: X/Y/Z sources,
	// optional EVEX masking, and opt-in D/Q memory broadcast.
	amd64PackedAddVEXEVEX
)

type amd64PackedAddSpec struct {
	canonical      Op
	form           amd64PackedAddForm
	laneBits       int
	mode           amd64PackedAddMode
	allowBroadcast bool
}

// amd64PackedAddSpecs is the complete typed grammar for Go 1.27's packed-add
// instruction family. Keep aliases here rather than duplicating lowering:
// cmd/asm maps PADDD to APADDL, while its VEX spelling remains VPADDD.
var amd64PackedAddSpecs = map[Op]amd64PackedAddSpec{
	"PADDB":    {canonical: "PADDB", form: amd64PackedAddLegacyYMM, laneBits: 8, mode: amd64PackedAddWrap},
	"PADDW":    {canonical: "PADDW", form: amd64PackedAddLegacyYMM, laneBits: 16, mode: amd64PackedAddWrap},
	"PADDL":    {canonical: "PADDL", form: amd64PackedAddLegacyYMM, laneBits: 32, mode: amd64PackedAddWrap},
	"PADDD":    {canonical: "PADDL", form: amd64PackedAddLegacyYMM, laneBits: 32, mode: amd64PackedAddWrap},
	"PADDQ":    {canonical: "PADDQ", form: amd64PackedAddLegacyYXM, laneBits: 64, mode: amd64PackedAddWrap},
	"PADDSB":   {canonical: "PADDSB", form: amd64PackedAddLegacyYMM, laneBits: 8, mode: amd64PackedAddSignedSaturating},
	"PADDSW":   {canonical: "PADDSW", form: amd64PackedAddLegacyYMM, laneBits: 16, mode: amd64PackedAddSignedSaturating},
	"PADDUSB":  {canonical: "PADDUSB", form: amd64PackedAddLegacyYMM, laneBits: 8, mode: amd64PackedAddUnsignedSaturating},
	"PADDUSW":  {canonical: "PADDUSW", form: amd64PackedAddLegacyYMM, laneBits: 16, mode: amd64PackedAddUnsignedSaturating},
	"VPADDB":   {canonical: "VPADDB", form: amd64PackedAddVEXEVEX, laneBits: 8, mode: amd64PackedAddWrap},
	"VPADDW":   {canonical: "VPADDW", form: amd64PackedAddVEXEVEX, laneBits: 16, mode: amd64PackedAddWrap},
	"VPADDD":   {canonical: "VPADDD", form: amd64PackedAddVEXEVEX, laneBits: 32, mode: amd64PackedAddWrap, allowBroadcast: true},
	"VPADDQ":   {canonical: "VPADDQ", form: amd64PackedAddVEXEVEX, laneBits: 64, mode: amd64PackedAddWrap, allowBroadcast: true},
	"VPADDSB":  {canonical: "VPADDSB", form: amd64PackedAddVEXEVEX, laneBits: 8, mode: amd64PackedAddSignedSaturating},
	"VPADDSW":  {canonical: "VPADDSW", form: amd64PackedAddVEXEVEX, laneBits: 16, mode: amd64PackedAddSignedSaturating},
	"VPADDUSB": {canonical: "VPADDUSB", form: amd64PackedAddVEXEVEX, laneBits: 8, mode: amd64PackedAddUnsignedSaturating},
	"VPADDUSW": {canonical: "VPADDUSW", form: amd64PackedAddVEXEVEX, laneBits: 16, mode: amd64PackedAddUnsignedSaturating},
}

// lowerPackedIntegerAdd implements the complete Go 1.27 packed-integer add
// family: the legacy ymm/yxm tables and the _yvandnpd VEX/EVEX table.
func (c *amd64Ctx) lowerPackedIntegerAdd(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	suffix := ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	spec, recognized := amd64PackedAddSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	if spec.form != amd64PackedAddVEXEVEX {
		if suffix != "" {
			return true, false, fmt.Errorf("amd64 %s does not accept instruction suffixes: %q", baseOp, ins.Raw)
		}
		return c.lowerLegacyPackedIntegerAdd(baseOp, spec, ins)
	}
	return c.lowerVectorPackedIntegerAdd(baseOp, suffix, spec, ins)
}

func (c *amd64Ctx) lowerLegacyPackedIntegerAdd(baseOp string, spec amd64PackedAddSpec, ins Instr) (bool, bool, error) {
	if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("amd64 %s expects MMX/m64, MMX or X/m128, X: %q", baseOp, ins.Raw)
	}
	dst := ins.Args[1].Reg
	if _, ok := amd64ParseMReg(dst); ok {
		if c.goarch == "386" {
			return true, false, fmt.Errorf("386 %s MMX forms are illegal in 32-bit mode: %q", baseOp, ins.Raw)
		}
		if spec.form != amd64PackedAddLegacyYMM {
			return true, false, fmt.Errorf("amd64 PADDQ has no MMX form in Go 1.27's yxm table: %q", ins.Raw)
		}
		firstBits, err := c.loadLegacyMMXPackedSource(ins.Args[0])
		if err != nil {
			return true, false, fmt.Errorf("amd64 %s MMX source: %w", baseOp, err)
		}
		secondBits, err := c.loadReg(dst)
		if err != nil {
			return true, false, err
		}
		lanes := 64 / spec.laneBits
		first := c.bitcastI64ToIntegerLanes(lanes, spec.laneBits, firstBits)
		second := c.bitcastI64ToIntegerLanes(lanes, spec.laneBits, secondBits)
		result := c.emitPackedIntegerAdd(lanes, spec.laneBits, first, second, spec.mode)
		bits := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to i64\n", bits, lanes, spec.laneBits, result)
		return true, false, c.storeReg(dst, "%"+bits)
	}
	if !c.isGoLegacyXReg(dst) {
		return true, false, fmt.Errorf("%s %s destination must be an in-range MMX or X register: %q", c.goarch, baseOp, ins.Raw)
	}
	if ins.Args[0].Kind == OpReg && !c.isGoLegacyXReg(ins.Args[0].Reg) {
		return true, false, fmt.Errorf("%s %s XMM form requires an in-range X source: %q", c.goarch, baseOp, ins.Raw)
	}
	if ins.Args[0].Kind == OpMem && !x86MemoryRegistersValidForArch(ins.Args[0].Mem, c.goarch) {
		return true, false, fmt.Errorf("%s %s source uses an out-of-range address register: %q", c.goarch, baseOp, ins.Raw)
	}
	firstBytes, err := c.loadXVecOperand(ins.Args[0])
	if err != nil {
		return true, false, err
	}
	secondBytes, err := c.loadX(dst)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / spec.laneBits
	first := c.bitcastVectorBytesToIntegerLanes(16, lanes, spec.laneBits, firstBytes)
	second := c.bitcastVectorBytesToIntegerLanes(16, lanes, spec.laneBits, secondBytes)
	result := c.emitPackedIntegerAdd(lanes, spec.laneBits, first, second, spec.mode)
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <16 x i8>\n", out, lanes, spec.laneBits, result)
	return true, false, c.storeX(dst, "%"+out)
}

func (c *amd64Ctx) loadLegacyMMXPackedSource(src Operand) (string, error) {
	if src.Kind == OpReg {
		if _, ok := amd64ParseMReg(src.Reg); !ok {
			return "", fmt.Errorf("expected MMX register or memory, got %s", src.String())
		}
		return c.loadReg(src.Reg)
	}
	if !isAMD64MemoryOperand(src) {
		return "", fmt.Errorf("expected MMX register or memory, got %s", src.String())
	}
	return c.evalIntSized(src, I64)
}

func (c *amd64Ctx) bitcastI64ToIntegerLanes(lanes, laneBits int, value string) string {
	cast := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast i64 %s to <%d x i%d>\n", cast, value, lanes, laneBits)
	return "%" + cast
}

func (c *amd64Ctx) lowerVectorPackedIntegerAdd(baseOp, suffix string, spec amd64PackedAddSpec, ins Instr) (bool, bool, error) {
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
		return true, false, fmt.Errorf("amd64 %s has a suffix absent from its Go 1.27 optab: %q", baseOp, ins.Raw)
	}
	if broadcast && !spec.allowBroadcast {
		return true, false, fmt.Errorf("amd64 %s does not enable EVEX broadcast: %q", baseOp, ins.Raw)
	}
	if len(ins.Args) != 3 && len(ins.Args) != 4 {
		return true, false, fmt.Errorf("amd64 %s expects src1, src2, [K mask,] destination: %q", baseOp, ins.Raw)
	}
	dstArg := ins.Args[len(ins.Args)-1]
	if dstArg.Kind != OpReg {
		return true, false, fmt.Errorf("amd64 %s expects an X, Y, or Z destination: %q", baseOp, ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(dstArg.Reg)
	if byteWidth == 0 {
		return true, false, fmt.Errorf("amd64 %s expects an X, Y, or Z destination: %q", baseOp, ins.Raw)
	}
	if !amd64VectorRegisterHasWidth(ins.Args[1], byteWidth) {
		return true, false, fmt.Errorf("amd64 %s second source must match its destination width: %q", baseOp, ins.Raw)
	}
	if broadcast {
		if !isAMD64MemoryOperand(ins.Args[0]) {
			return true, false, fmt.Errorf("amd64 %s.BCST requires a memory first source: %q", baseOp, ins.Raw)
		}
	} else if ins.Args[0].Kind == OpReg && !amd64VectorRegisterHasWidth(ins.Args[0], byteWidth) {
		return true, false, fmt.Errorf("amd64 %s first source must match its destination width: %q", baseOp, ins.Raw)
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
		maskIndex, ok := amd64ParseKReg(maskArg.Reg)
		if !ok || maskIndex == 0 {
			return true, false, fmt.Errorf("amd64 %s masked form expects K1-K7: %q", baseOp, ins.Raw)
		}
		var err error
		mask, err = c.loadK(maskArg.Reg)
		if err != nil {
			return true, false, err
		}
	}

	lanes := byteWidth * 8 / spec.laneBits
	var first string
	var err error
	if broadcast {
		first, err = c.evalIntSized(ins.Args[0], amd64IntegerTypeForBits(spec.laneBits))
		if err == nil {
			first = amd64SplatInteger(c, lanes, spec.laneBits, first)
		}
	} else {
		var firstBytes string
		firstBytes, err = c.loadPackedCompareBytes(ins.Args[0], byteWidth)
		if err == nil {
			first = c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, spec.laneBits, firstBytes)
		}
	}
	if err != nil {
		return true, false, err
	}
	secondBytes, err := c.loadPackedCompareBytes(ins.Args[1], byteWidth)
	if err != nil {
		return true, false, err
	}
	second := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, spec.laneBits, secondBytes)
	result := c.emitPackedIntegerAdd(lanes, spec.laneBits, first, second, spec.mode)
	if masked {
		oldBytes, err := c.loadPackedCompareBytes(dstArg, byteWidth)
		if err != nil {
			return true, false, err
		}
		old := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, spec.laneBits, oldBytes)
		result = amd64ApplyIntegerLaneMask(c, lanes, spec.laneBits, result, old, mask, zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, spec.laneBits, result, byteWidth)
	return true, false, c.storeVectorBytes(dstArg.Reg, byteWidth, "%"+out)
}

func (c *amd64Ctx) emitPackedIntegerAdd(lanes, laneBits int, first, second string, mode amd64PackedAddMode) string {
	vecType := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
	if mode == amd64PackedAddWrap {
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add %s %s, %s\n", result, vecType, second, first)
		return "%" + result
	}

	wideBits := laneBits * 2
	wideType := fmt.Sprintf("<%d x i%d>", lanes, wideBits)
	firstWide := c.newTmp()
	secondWide := c.newTmp()
	extend := "sext"
	if mode == amd64PackedAddUnsignedSaturating {
		extend = "zext"
	}
	fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", firstWide, extend, vecType, first, wideType)
	fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", secondWide, extend, vecType, second, wideType)
	sum := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %%%s\n", sum, wideType, secondWide, firstWide)

	max := int64((uint64(1) << laneBits) - 1)
	predicate := "ugt"
	if mode == amd64PackedAddSignedSaturating {
		max = int64((uint64(1) << (laneBits - 1)) - 1)
		predicate = "sgt"
	}
	above := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp %s %s %%%s, %s\n", above, predicate, wideType, sum, llvmSplatSignedInteger(lanes, wideBits, max))
	capped := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %s, %s %%%s\n", capped, lanes, above, wideType, llvmSplatSignedInteger(lanes, wideBits, max), wideType, sum)
	clamped := "%" + capped
	if mode == amd64PackedAddSignedSaturating {
		min := -int64(uint64(1) << (laneBits - 1))
		below := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp slt %s %s, %s\n", below, wideType, clamped, llvmSplatSignedInteger(lanes, wideBits, min))
		bounded := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %s, %s %s\n", bounded, lanes, below, wideType, llvmSplatSignedInteger(lanes, wideBits, min), wideType, clamped)
		clamped = "%" + bounded
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc %s %s to %s\n", result, wideType, clamped, vecType)
	return "%" + result
}

func llvmSplatSignedInteger(lanes, bits int, value int64) string {
	var b strings.Builder
	b.WriteByte('<')
	for lane := 0; lane < lanes; lane++ {
		if lane != 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "i%d %d", bits, value)
	}
	b.WriteByte('>')
	return b.String()
}
