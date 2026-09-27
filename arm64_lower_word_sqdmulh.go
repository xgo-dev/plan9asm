package plan9asm

import "fmt"

// arm64RawSQDMULH describes every Advanced SIMD SQDMULH encoding. Go 1.27
// exposes only the SVE ZSQDMULH mnemonic, so ecosystem code that needs the
// fixed-width instruction still carries these encodings in WORD directives.
type arm64RawSQDMULH struct {
	scalar      bool
	byElement   bool
	arrangement arm64VectorArrangement
	destination int
	first       int
	second      int
	element     int
}

func decodeARM64RawSQDMULH(word uint32) (arm64RawSQDMULH, bool) {
	form := arm64RawSQDMULH{element: -1}
	switch {
	case word&0xff20fc00 == 0x5e20b400: // scalar, three same
		form.scalar = true
	case word&0xbf20fc00 == 0x0e20b400: // vector, three same
	case word&0xff00f400 == 0x5f00c000: // scalar, by element
		form.scalar = true
		form.byElement = true
	case word&0xbf00f400 == 0x0f00c000: // vector, by element
		form.byElement = true
	default:
		return arm64RawSQDMULH{}, false
	}
	return decodeARM64MultiplyHighOperands(word, form)
}

// All fixed-width saturating multiply-high forms share these size, register
// and indexed-lane fields. H is the high index bit, not the low one; M is
// either the low H-lane index bit or the high S-source register bit.
func decodeARM64MultiplyHighOperands(word uint32, form arm64RawSQDMULH) (arm64RawSQDMULH, bool) {
	size := int(word>>22) & 3
	if size != 1 && size != 2 {
		return arm64RawSQDMULH{}, false
	}
	bits := 8 << size
	lanes := 1
	if !form.scalar {
		vectorBits := 64
		if word&(1<<30) != 0 {
			vectorBits = 128
		}
		lanes = vectorBits / bits
	}
	form.arrangement = arm64VectorArrangement{elementBits: bits, lanes: lanes}
	form.destination = int(word & 31)
	form.first = int(word>>5) & 31
	form.second = int(word>>16) & 31
	if form.byElement {
		element := decodeARM64MultiplyIndexedElement(word, bits)
		form.second, form.element = element.register, element.lane
	}
	return form, true
}

func (c *arm64Ctx) lowerRawSQDMULH(form arm64RawSQDMULH) error {
	return c.lowerRawSaturatingDoublingMultiplyHigh(form, false)
}

func (c *arm64Ctx) lowerRawSaturatingDoublingMultiplyHigh(form arm64RawSQDMULH, rounding bool) error {
	first, err := c.loadRawARM64VectorOperand(form.first, form.arrangement, 0, form.scalar)
	if err != nil {
		return err
	}
	secondLane := 0
	if form.byElement {
		secondLane = form.element
	}
	second, err := c.loadRawARM64VectorOperand(form.second, form.arrangement, secondLane, form.scalar || form.byElement)
	if err != nil {
		return err
	}

	narrow := form.arrangement
	wide := arm64VectorArrangement{elementBits: narrow.elementBits * 2, lanes: narrow.lanes}
	narrowType := fmt.Sprintf("<%d x i%d>", narrow.lanes, narrow.elementBits)
	wideType := fmt.Sprintf("<%d x i%d>", wide.lanes, wide.elementBits)
	wideFirst := c.newTmp()
	wideSecond := c.newTmp()
	product := c.newTmp()
	productValue := ""
	shifted := c.newTmp()
	truncated := c.newTmp()
	firstMinimum := c.newTmp()
	secondMinimum := c.newTmp()
	overflow := c.newTmp()
	result := c.newTmp()
	minimum := -(int64(1) << (narrow.elementBits - 1))
	maximum := (int64(1) << (narrow.elementBits - 1)) - 1

	fmt.Fprintf(c.b, "  %%%s = sext %s %s to %s\n", wideFirst, narrowType, first, wideType)
	fmt.Fprintf(c.b, "  %%%s = sext %s %s to %s\n", wideSecond, narrowType, second, wideType)
	fmt.Fprintf(c.b, "  %%%s = mul %s %%%s, %%%s\n", product, wideType, wideFirst, wideSecond)
	productValue = "%" + product
	if rounding {
		rounded := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add %s %s, %s\n", rounded, wideType, productValue, arm64VectorIntegerSplat(wide, int64(1)<<(narrow.elementBits-2)))
		productValue = "%" + rounded
	}
	fmt.Fprintf(c.b, "  %%%s = ashr %s %s, %s\n", shifted, wideType, productValue, arm64VectorIntegerSplat(wide, int64(narrow.elementBits-1)))
	fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to %s\n", truncated, wideType, shifted, narrowType)
	fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, %s\n", firstMinimum, narrowType, first, arm64VectorIntegerSplat(narrow, minimum))
	fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, %s\n", secondMinimum, narrowType, second, arm64VectorIntegerSplat(narrow, minimum))
	fmt.Fprintf(c.b, "  %%%s = and <%d x i1> %%%s, %%%s\n", overflow, narrow.lanes, firstMinimum, secondMinimum)
	fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %s, %s %%%s\n",
		result, narrow.lanes, overflow, narrowType, arm64VectorIntegerSplat(narrow, maximum), narrowType, truncated)
	return c.storeRawARM64VectorResult(form.destination, narrow, "%"+result, form.scalar)
}

func (c *arm64Ctx) loadRawARM64VectorOperand(index int, arrangement arm64VectorArrangement, lane int, scalarOrLane bool) (string, error) {
	reg := Reg(fmt.Sprintf("V%d", index))
	if !scalarOrLane {
		return c.loadARM64VectorInteger(Reg(fmt.Sprintf("V%d.%s", index, arm64VectorArrangementName(arrangement))), arrangement)
	}
	element, err := c.arm64VDUPExtractLane(reg, arrangement.elementBits, lane)
	if err != nil {
		return "", err
	}
	if arrangement.lanes == 1 {
		seed := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <1 x i%d> poison, i%d %s, i32 0\n", seed, arrangement.elementBits, arrangement.elementBits, element)
		return "%" + seed, nil
	}
	return c.arm64VDUPSplat(arrangement, element), nil
}

func (c *arm64Ctx) storeRawARM64VectorResult(index int, arrangement arm64VectorArrangement, value string, scalar bool) error {
	reg := Reg(fmt.Sprintf("V%d", index))
	if !scalar {
		return c.storeARM64VectorInteger(Reg(fmt.Sprintf("V%d.%s", index, arm64VectorArrangementName(arrangement))), arrangement, value)
	}
	element := c.newTmp()
	physicalLanes := 128 / arrangement.elementBits
	inserted := c.newTmp()
	bytes := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractelement <1 x i%d> %s, i32 0\n", element, arrangement.elementBits, value)
	fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> zeroinitializer, i%d %%%s, i32 0\n",
		inserted, physicalLanes, arrangement.elementBits, arrangement.elementBits, element)
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %%%s to <16 x i8>\n", bytes, physicalLanes, arrangement.elementBits, inserted)
	return c.storeVReg(reg, "%"+bytes)
}
