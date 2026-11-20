package plan9asm

import "fmt"

// Go 1.27's VADDP optab has seven three-register vector arrangements. Arm's
// scalar ADDP Dd,Vn.2D has no named Go spelling and appears only in WORD.
var arm64PairwiseAddArrangements = map[arm64VectorArrangement]bool{
	{elementBits: 8, lanes: 8}:  true,
	{elementBits: 8, lanes: 16}: true,
	{elementBits: 16, lanes: 4}: true,
	{elementBits: 16, lanes: 8}: true,
	{elementBits: 32, lanes: 2}: true,
	{elementBits: 32, lanes: 4}: true,
	{elementBits: 64, lanes: 2}: true,
}

type arm64RawScalarADDP struct {
	source      int
	destination int
}

func decodeARM64RawScalarADDP(word uint32) (arm64RawScalarADDP, bool) {
	if word&0xfffffc00 != 0x5ef1b800 {
		return arm64RawScalarADDP{}, false
	}
	return arm64RawScalarADDP{source: int(word>>5) & 31, destination: int(word & 31)}, true
}

func (c *arm64Ctx) lowerRawScalarADDP(form arm64RawScalarADDP) error {
	arrangement := arm64VectorArrangement{elementBits: 64, lanes: 2}
	source, err := c.loadARM64VectorInteger(Reg(fmt.Sprintf("V%d.D2", form.source)), arrangement)
	if err != nil {
		return err
	}
	first := c.newTmp()
	second := c.newTmp()
	sum := c.newTmp()
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %s, i32 0\n", first, source)
	fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %s, i32 1\n", second, source)
	fmt.Fprintf(c.b, "  %%%s = add i64 %%%s, %%%s\n", sum, first, second)
	fmt.Fprintf(c.b, "  %%%s = insertelement <1 x i64> poison, i64 %%%s, i32 0\n", result, sum)
	return c.storeRawARM64VectorResult(form.destination, arm64VectorArrangement{elementBits: 64, lanes: 1}, "%"+result, true)
}

func (c *arm64Ctx) lowerARM64VectorADDP(ins Instr) error {
	if len(ins.Args) != 3 {
		return fmt.Errorf("arm64 VADDP expects three same-arrangement vector registers: %q", ins.Raw)
	}
	var arrangement arm64VectorArrangement
	for index, operand := range ins.Args {
		if operand.Kind != OpReg {
			return fmt.Errorf("arm64 VADDP expects vector registers: %q", ins.Raw)
		}
		parsed, ok := parseARM64VectorArrangement(operand.Reg)
		if !ok || !arm64PairwiseAddArrangements[parsed] {
			return fmt.Errorf("arm64 VADDP has invalid arrangement: %q", ins.Raw)
		}
		if index == 0 {
			arrangement = parsed
		} else if arrangement != parsed {
			return fmt.Errorf("arm64 VADDP arrangements must match: %q", ins.Raw)
		}
	}

	// Go syntax is Vm,Vn,Vd. Architecturally the low result lanes come from
	// adjacent pairs of Vn, followed by pairs of Vm.
	m, err := c.loadARM64VectorInteger(ins.Args[0].Reg, arrangement)
	if err != nil {
		return err
	}
	n, err := c.loadARM64VectorInteger(ins.Args[1].Reg, arrangement)
	if err != nil {
		return err
	}
	lanes := arrangement.lanes
	even := make([]int, 0, lanes)
	odd := make([]int, 0, lanes)
	for source := 0; source < 2; source++ {
		for pair := 0; pair < lanes/2; pair++ {
			even = append(even, source*lanes+2*pair)
			odd = append(odd, source*lanes+2*pair+1)
		}
	}
	vectorType := fmt.Sprintf("<%d x i%d>", lanes, arrangement.elementBits)
	left := c.newTmp()
	right := c.newTmp()
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector %s %s, %s %s, %s\n", left, vectorType, n, vectorType, m, arm64IntegerShuffleMask(even))
	fmt.Fprintf(c.b, "  %%%s = shufflevector %s %s, %s %s, %s\n", right, vectorType, n, vectorType, m, arm64IntegerShuffleMask(odd))
	fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %%%s\n", result, vectorType, left, right)
	return c.storeARM64VectorInteger(ins.Args[2].Reg, arrangement, "%"+result)
}

func arm64IntegerShuffleMask(indices []int) string {
	mask := fmt.Sprintf("<%d x i32> <", len(indices))
	for index, lane := range indices {
		if index != 0 {
			mask += ", "
		}
		mask += fmt.Sprintf("i32 %d", lane)
	}
	return mask + ">"
}
