package plan9asm

import "fmt"

type armRawNEONMultiplyLongLane struct {
	kind        string
	unsigned    bool
	elementBits int
	destination int
	lhs         int
	scalar      int
	lane        int
}

// decodeARMRawNEONMultiplyLongLane covers A32 VMULL/VMLAL/VMLSL signed and
// unsigned 16-/32-bit scalar-lane forms. Every form widens a D-register
// product into an even-numbered D pair representing a Q destination.
func decodeARMRawNEONMultiplyLongLane(word uint32) (armRawNEONMultiplyLongLane, bool) {
	kind := ""
	switch word & 0xfe800e50 {
	case 0xf2800a40:
		kind = "mul"
	case 0xf2800240:
		kind = "mla"
	case 0xf2800640:
		kind = "mls"
	default:
		return armRawNEONMultiplyLongLane{}, false
	}
	encodedSize := int(word >> 20 & 3)
	if encodedSize != 1 && encodedSize != 2 {
		return armRawNEONMultiplyLongLane{}, false
	}
	destination := int(word>>12)&15 | int(word>>22&1)*16
	if destination&1 != 0 {
		return armRawNEONMultiplyLongLane{}, false
	}
	scalar := int(word) & 15
	lane := int(word>>5) & 1
	if encodedSize == 1 {
		scalar &= 7
		lane = int(word>>3)&1 | int(word>>5&1)*2
	}
	return armRawNEONMultiplyLongLane{
		kind:        kind,
		unsigned:    word>>24&1 != 0,
		elementBits: 8 << encodedSize,
		destination: destination,
		lhs:         int(word>>16)&15 | int(word>>7&1)*16,
		scalar:      scalar,
		lane:        lane,
	}, true
}

func (c *armCtx) lowerRawNEONMultiplyLongLane(form armRawNEONMultiplyLongLane) error {
	narrowType := fmt.Sprintf("i%d", form.elementBits)
	wideBits := form.elementBits * 2
	wideType := fmt.Sprintf("i%d", wideBits)
	lhs, lanes, err := c.loadARMRawNEONVector(form.lhs, form.elementBits, false, narrowType)
	if err != nil {
		return err
	}
	scalars, scalarLanes, err := c.loadARMRawNEONVector(form.scalar, form.elementBits, false, narrowType)
	if err != nil {
		return err
	}
	extend := "sext"
	if form.unsigned {
		extend = "zext"
	}
	lhsWide := c.newTmp()
	scalar := c.newTmp()
	scalarWide := c.newTmp()
	inserted := c.newTmp()
	broadcast := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s <%d x %s> %s to <%d x %s>\n",
		lhsWide, extend, lanes, narrowType, lhs, lanes, wideType)
	fmt.Fprintf(c.b, "  %%%s = extractelement <%d x %s> %s, i32 %d\n",
		scalar, scalarLanes, narrowType, scalars, form.lane)
	fmt.Fprintf(c.b, "  %%%s = %s %s %%%s to %s\n",
		scalarWide, extend, narrowType, scalar, wideType)
	fmt.Fprintf(c.b, "  %%%s = insertelement <%d x %s> poison, %s %%%s, i32 0\n",
		inserted, lanes, wideType, wideType, scalarWide)
	fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x %s> %%%s, <%d x %s> poison, <%d x i32> zeroinitializer\n",
		broadcast, lanes, wideType, inserted, lanes, wideType, lanes)
	return c.lowerARMRawNEONWideningProduct(
		form.kind, form.elementBits, form.destination, "%"+lhsWide, "%"+broadcast,
	)
}

func (c *armCtx) lowerARMRawNEONWideningProduct(
	kind string, elementBits, destination int, lhsWide, rhsWide string,
) error {
	lanes := 64 / elementBits
	wideBits := elementBits * 2
	wideType := fmt.Sprintf("i%d", wideBits)
	product := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = mul <%d x %s> %s, %s\n",
		product, lanes, wideType, lhsWide, rhsWide)
	result := "%" + product
	if kind != "mul" {
		accumulator, _, err := c.loadARMRawNEONVector(
			destination, wideBits, true, wideType,
		)
		if err != nil {
			return err
		}
		operation := "add"
		if kind == "mls" {
			operation = "sub"
		}
		combined := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s <%d x %s> %s, %%%s\n",
			combined, operation, lanes, wideType, accumulator, product)
		result = "%" + combined
	}
	return c.storeARMRawNEONVector(
		destination, wideBits, true, wideType, result,
	)
}
