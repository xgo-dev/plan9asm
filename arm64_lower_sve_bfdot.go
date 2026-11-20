package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVEBFDOTForm struct {
	first       int
	second      int
	destination int
	lane        int
	indexed     bool
}

func (c *arm64Ctx) lowerARM64SVEBFDOT(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZBFDOT" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 ZBFDOT expects one complete Go 1.27 form without a suffix: %q", ins.Raw)
	}
	form := arm64SVEBFDOTForm{}
	if first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[0]); firstOK {
		if firstBits != 16 {
			return true, false, fmt.Errorf("arm64 ZBFDOT vector source must use H elements: %q", ins.Raw)
		}
		form.first = first
	} else {
		first, firstBits, lane, firstOK := arm64ParseSVEZIndexedElementRegUnbounded(ins.Args[0])
		if !firstOK || firstBits != 16 || first > 7 || lane > 3 {
			return true, false, fmt.Errorf("arm64 ZBFDOT indexed source must use Z0..Z7.H[0..3]: %q", ins.Raw)
		}
		form.first = first
		form.lane = lane
		form.indexed = true
	}
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[1])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	if !secondOK || secondBits != 16 || !destinationOK || destinationBits != 32 {
		return true, false, fmt.Errorf("arm64 ZBFDOT operands must use H source elements and an S accumulator: %q", ins.Raw)
	}
	form.second = second
	form.destination = destination
	return true, false, c.lowerARM64SVEBFDOTForm(form)
}

func (c *arm64Ctx) lowerARM64SVEBFDOTForm(form arm64SVEBFDOTForm) error {
	accumulator, accumulatorType, err := c.loadRawSVEFloatVector(form.destination, 32)
	if err != nil {
		return err
	}
	loadBFloat := func(register int) (string, error) {
		integer, integerType, err := c.loadZRegElements(register, 16)
		if err != nil {
			return "", err
		}
		converted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <vscale x 8 x bfloat>\n", converted, integerType, integer)
		return "%" + converted, nil
	}
	second, err := loadBFloat(form.second)
	if err != nil {
		return err
	}
	first, err := loadBFloat(form.first)
	if err != nil {
		return err
	}
	result := c.newTmp()
	if form.indexed {
		fmt.Fprintf(c.b, "  %%%s = call <vscale x 4 x float> @llvm.aarch64.sve.bfdot.lane.v2(<vscale x 4 x float> %s, <vscale x 8 x bfloat> %s, <vscale x 8 x bfloat> %s, i32 %d)\n", result, accumulator, second, first, form.lane)
	} else {
		fmt.Fprintf(c.b, "  %%%s = call <vscale x 4 x float> @llvm.aarch64.sve.bfdot(<vscale x 4 x float> %s, <vscale x 8 x bfloat> %s, <vscale x 8 x bfloat> %s)\n", result, accumulator, second, first)
	}
	return c.storeRawSVEFloatVector(form.destination, 32, "%"+result, accumulatorType)
}
