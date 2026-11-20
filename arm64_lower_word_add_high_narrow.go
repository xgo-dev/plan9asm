package plan9asm

import "fmt"

type arm64RawAddHighNarrow struct {
	subtract               bool
	rounded                bool
	highHalf               bool
	sourceArrangement      arm64VectorArrangement
	destinationArrangement arm64VectorArrangement
	first                  int
	second                 int
	destination            int
}

func decodeARM64RawAddHighNarrow(word uint32) (arm64RawAddHighNarrow, bool) {
	const (
		registerBits = uint32(0x001f03ff)
		sizeBits     = uint32(0x00c00000)
	)
	base := word &^ (registerBits | sizeBits)
	if base != 0x0e204000 && base != 0x4e204000 &&
		base != 0x2e204000 && base != 0x6e204000 &&
		base != 0x0e206000 && base != 0x4e206000 &&
		base != 0x2e206000 && base != 0x6e206000 {
		return arm64RawAddHighNarrow{}, false
	}

	size := int(word>>22) & 3
	if size == 3 {
		return arm64RawAddHighNarrow{}, false
	}
	sourceBits := 16 << size
	sourceLanes := 128 / sourceBits
	highHalf := word&(1<<30) != 0
	destinationLanes := sourceLanes
	if highHalf {
		destinationLanes *= 2
	}

	return arm64RawAddHighNarrow{
		subtract:               word&(1<<13) != 0,
		rounded:                word&(1<<29) != 0,
		highHalf:               highHalf,
		sourceArrangement:      arm64VectorArrangement{elementBits: sourceBits, lanes: sourceLanes},
		destinationArrangement: arm64VectorArrangement{elementBits: sourceBits / 2, lanes: destinationLanes},
		first:                  int(word>>5) & 31,
		second:                 int(word>>16) & 31,
		destination:            int(word) & 31,
	}, true
}

func (c *arm64Ctx) lowerRawAddHighNarrow(form arm64RawAddHighNarrow) error {
	firstReg := Reg(fmt.Sprintf("V%d", form.first))
	secondReg := Reg(fmt.Sprintf("V%d", form.second))
	destinationReg := Reg(fmt.Sprintf("V%d", form.destination))

	first, err := c.loadARM64VectorInteger(firstReg, form.sourceArrangement)
	if err != nil {
		return err
	}
	second, err := c.loadARM64VectorInteger(secondReg, form.sourceArrangement)
	if err != nil {
		return err
	}

	sourceType := fmt.Sprintf("<%d x i%d>", form.sourceArrangement.lanes, form.sourceArrangement.elementBits)
	operation := "add"
	if form.subtract {
		operation = "sub"
	}
	combined := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s %s %s, %s\n", combined, operation, sourceType, first, second)
	value := "%" + combined
	if form.rounded {
		rounded := c.newTmp()
		rounding := int64(1) << (form.destinationArrangement.elementBits - 1)
		fmt.Fprintf(c.b, "  %%%s = add %s %s, %s\n",
			rounded, sourceType, value, arm64VectorIntegerSplat(form.sourceArrangement, rounding))
		value = "%" + rounded
	}

	shifted := c.newTmp()
	shift := arm64VectorIntegerSplat(form.sourceArrangement, int64(form.destinationArrangement.elementBits))
	fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %s\n", shifted, sourceType, value, shift)
	narrowType := fmt.Sprintf("<%d x i%d>", form.sourceArrangement.lanes, form.destinationArrangement.elementBits)
	narrowed := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to %s\n", narrowed, sourceType, shifted, narrowType)
	if !form.highHalf {
		return c.storeARM64VectorInteger(destinationReg, form.destinationArrangement, "%"+narrowed)
	}

	result, err := c.loadARM64VectorInteger(destinationReg, form.destinationArrangement)
	if err != nil {
		return err
	}
	fullDestinationType := fmt.Sprintf("<%d x i%d>",
		form.destinationArrangement.lanes,
		form.destinationArrangement.elementBits,
	)
	for lane := 0; lane < form.sourceArrangement.lanes; lane++ {
		element := c.newTmp()
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %%%s, i32 %d\n", element, narrowType, narrowed, lane)
		fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, i%d %%%s, i32 %d\n",
			inserted,
			fullDestinationType,
			result,
			form.destinationArrangement.elementBits,
			element,
			form.sourceArrangement.lanes+lane,
		)
		result = "%" + inserted
	}
	return c.storeARM64VectorInteger(destinationReg, form.destinationArrangement, result)
}
