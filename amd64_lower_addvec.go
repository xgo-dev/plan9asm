package plan9asm

import (
	"fmt"
	"strconv"
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
	return c.lowerPackedIntegerAddForm(op, ins)
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
	return llvmSplatIntegerText(lanes, bits, strconv.FormatInt(value, 10))
}
