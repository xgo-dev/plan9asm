package plan9asm

import "fmt"

type arm64RawRDMASpec struct {
	base      uint32
	mask      uint32
	intrinsic string
	scalar    bool
	byElement bool
}

// Go names the SVE ZSQRDMLAH/ZSQRDMLSH forms, but exposes all fixed-width
// FEAT_RDM forms only through WORD. Arm DDI 0602 defines the same register,
// size, and indexed-lane fields for both operations and all four shapes.
var arm64RawRDMASpecs = [...]arm64RawRDMASpec{
	{0x2e008400, 0xbf20fc00, "sqrdmlah", false, false},
	{0x2e008c00, 0xbf20fc00, "sqrdmlsh", false, false},
	{0x7e008400, 0xff20fc00, "sqrdmlah", true, false},
	{0x7e008c00, 0xff20fc00, "sqrdmlsh", true, false},
	{0x2f00d000, 0xbf00f400, "sqrdmlah", false, true},
	{0x2f00f000, 0xbf00f400, "sqrdmlsh", false, true},
	{0x7f00d000, 0xff00f400, "sqrdmlah", true, true},
	{0x7f00f000, 0xff00f400, "sqrdmlsh", true, true},
}

type arm64RawRDMA struct {
	arm64RawSQDMULH
	intrinsic string
}

func decodeARM64RawRDMA(word uint32) (arm64RawRDMA, bool) {
	for _, spec := range arm64RawRDMASpecs {
		if word&spec.mask != spec.base {
			continue
		}
		operands, ok := decodeARM64MultiplyHighOperands(word, arm64RawSQDMULH{
			scalar: spec.scalar, byElement: spec.byElement, element: -1,
		})
		if ok {
			return arm64RawRDMA{arm64RawSQDMULH: operands, intrinsic: spec.intrinsic}, true
		}
	}
	return arm64RawRDMA{}, false
}

func (c *arm64Ctx) lowerRawRDMA(form arm64RawRDMA) error {
	arrangement := form.arrangement
	accumulator, err := c.loadRawARM64VectorOperand(form.destination, arrangement, 0, form.scalar)
	if err != nil {
		return err
	}
	first, err := c.loadRawARM64VectorOperand(form.first, arrangement, 0, form.scalar)
	if err != nil {
		return err
	}
	secondLane := 0
	if form.byElement {
		secondLane = form.element
	}
	second, err := c.loadRawARM64VectorOperand(form.second, arrangement, secondLane, form.scalar || form.byElement)
	if err != nil {
		return err
	}
	if form.scalar {
		return c.lowerRawRDMAScalar(form, accumulator, first, second)
	}
	vectorType := fmt.Sprintf("<%d x i%d>", arrangement.lanes, arrangement.elementBits)
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.neon.%s.v%di%d(%s %s, %s %s, %s %s)\n",
		result, vectorType, form.intrinsic, arrangement.lanes, arrangement.elementBits,
		vectorType, accumulator, vectorType, first, vectorType, second)
	return c.storeRawARM64VectorResult(form.destination, arrangement, "%"+result, form.scalar)
}

// LLVM 22 cannot legalize the overloaded intrinsic on i16/i32 scalar values.
// Use a wider integer than 2*elementBits so the shifted accumulator, doubled
// product, and rounding addition remain exact even at the saturation edges.
func (c *arm64Ctx) lowerRawRDMAScalar(form arm64RawRDMA, accumulator, first, second string) error {
	bits := form.arrangement.elementBits
	wideBits := bits * 4
	wideType := fmt.Sprintf("i%d", wideBits)
	values := []string{accumulator, first, second}
	for index, value := range values {
		extracted := c.newTmp()
		extended := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <1 x i%d> %s, i32 0\n", extracted, bits, value)
		fmt.Fprintf(c.b, "  %%%s = sext i%d %%%s to %s\n", extended, bits, extracted, wideType)
		values[index] = "%" + extended
	}
	shiftedAccumulator := c.newTmp()
	product := c.newTmp()
	doubled := c.newTmp()
	combined := c.newTmp()
	rounded := c.newTmp()
	shifted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shl %s %s, %d\n", shiftedAccumulator, wideType, values[0], bits)
	fmt.Fprintf(c.b, "  %%%s = mul %s %s, %s\n", product, wideType, values[1], values[2])
	fmt.Fprintf(c.b, "  %%%s = shl %s %%%s, 1\n", doubled, wideType, product)
	operation := "add"
	if form.intrinsic == "sqrdmlsh" {
		operation = "sub"
	}
	fmt.Fprintf(c.b, "  %%%s = %s %s %%%s, %%%s\n", combined, operation, wideType, shiftedAccumulator, doubled)
	fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %d\n", rounded, wideType, combined, int64(1)<<(bits-1))
	fmt.Fprintf(c.b, "  %%%s = ashr %s %%%s, %d\n", shifted, wideType, rounded, bits)

	maximum := (int64(1) << (bits - 1)) - 1
	minimum := -(int64(1) << (bits - 1))
	above := c.newTmp()
	below := c.newTmp()
	clampedAbove := c.newTmp()
	clamped := c.newTmp()
	narrowed := c.newTmp()
	inserted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp sgt %s %%%s, %d\n", above, wideType, shifted, maximum)
	fmt.Fprintf(c.b, "  %%%s = icmp slt %s %%%s, %d\n", below, wideType, shifted, minimum)
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s %d, %s %%%s\n", clampedAbove, above, wideType, maximum, wideType, shifted)
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s %d, %s %%%s\n", clamped, below, wideType, minimum, wideType, clampedAbove)
	fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to i%d\n", narrowed, wideType, clamped, bits)
	fmt.Fprintf(c.b, "  %%%s = insertelement <1 x i%d> poison, i%d %%%s, i32 0\n", inserted, bits, bits, narrowed)
	return c.storeRawARM64VectorResult(form.destination, form.arrangement, "%"+inserted, true)
}
