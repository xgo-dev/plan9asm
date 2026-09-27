package plan9asm

import (
	"fmt"
	"strings"
)

type arm64HalvingAddSubSpec struct {
	signed   bool
	rounding bool
	subtract bool
}

func (c *arm64Ctx) lowerARM64VectorHalvingAdd(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, handled := map[Op]arm64HalvingAddSubSpec{
		"VSHADD":  {signed: true},
		"VSRHADD": {signed: true, rounding: true},
		"VUHADD":  {},
		"VURHADD": {rounding: true},
	}[op]
	if !handled {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects three same-arrangement vector registers and no suffix: %q", op, ins.Raw)
	}
	var arrangement arm64VectorArrangement
	for i, arg := range ins.Args {
		if arg.Kind != OpReg {
			return true, false, fmt.Errorf("arm64 %s accepts only vector registers: %q", op, ins.Raw)
		}
		parsed, valid := parseARM64VectorArrangement(arg.Reg)
		if !valid || parsed.elementBits == 64 && parsed.lanes != 2 {
			return true, false, fmt.Errorf("arm64 %s accepts only B8/B16/H4/H8/S2/S4/D2 arrangements: %q", op, ins.Raw)
		}
		if i == 0 {
			arrangement = parsed
		} else if parsed != arrangement {
			return true, false, fmt.Errorf("arm64 %s arrangements must match: %q", op, ins.Raw)
		}
	}
	first, err := c.loadARM64VectorInteger(ins.Args[0].Reg, arrangement)
	if err != nil {
		return true, false, err
	}
	second, err := c.loadARM64VectorInteger(ins.Args[1].Reg, arrangement)
	if err != nil {
		return true, false, err
	}
	return true, false, c.lowerARM64VectorHalvingAddSubForm(spec, arrangement, first, second, ins.Args[2].Reg)
}

func (c *arm64Ctx) lowerARM64VectorHalvingAddSubForm(
	spec arm64HalvingAddSubSpec,
	arrangement arm64VectorArrangement,
	first string,
	second string,
	destination Reg,
) error {
	narrowType := fmt.Sprintf("<%d x i%d>", arrangement.lanes, arrangement.elementBits)
	wideArrangement := arm64VectorArrangement{elementBits: arrangement.elementBits * 2, lanes: arrangement.lanes}
	wideType := fmt.Sprintf("<%d x i%d>", wideArrangement.lanes, wideArrangement.elementBits)
	extension := "zext"
	shift := "lshr"
	if spec.signed {
		extension = "sext"
		shift = "ashr"
	}
	wideFirst := c.newTmp()
	wideSecond := c.newTmp()
	combined := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", wideFirst, extension, narrowType, first, wideType)
	fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", wideSecond, extension, narrowType, second, wideType)
	operation := "add"
	if spec.subtract {
		operation = "sub"
	}
	fmt.Fprintf(c.b, "  %%%s = %s %s %%%s, %%%s\n", combined, operation, wideType, wideFirst, wideSecond)
	shiftSource := "%" + combined
	if spec.rounding {
		rounded := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add %s %s, %s\n", rounded, wideType, shiftSource, arm64VectorIntegerSplat(wideArrangement, 1))
		shiftSource = "%" + rounded
	}
	halved := c.newTmp()
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s %s %s, %s\n", halved, shift, wideType, shiftSource, arm64VectorIntegerSplat(wideArrangement, 1))
	fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to %s\n", result, wideType, halved, narrowType)
	return c.storeARM64VectorInteger(destination, arrangement, "%"+result)
}
