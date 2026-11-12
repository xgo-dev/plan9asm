package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVEFDOTForm struct {
	first, second, destination  int
	sourceBits, destinationBits int
	lane                        int
	indexed                     bool
}

func (c *arm64Ctx) lowerARM64SVEFDOT(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZFDOT" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 ZFDOT expects one complete Go 1.27 vector or indexed form without a suffix: %q", ins.Raw)
	}
	form := arm64SVEFDOTForm{}
	if first, sourceBits, firstOK := arm64ParseSVEZElementReg(ins.Args[0]); firstOK {
		form.first, form.sourceBits = first, sourceBits
	} else {
		first, sourceBits, lane, firstOK := arm64ParseSVEZIndexedElementRegUnbounded(ins.Args[0])
		if !firstOK || first > 7 {
			return true, false, fmt.Errorf("arm64 ZFDOT indexed source must use Z0..Z7: %q", ins.Raw)
		}
		form.first, form.sourceBits, form.lane, form.indexed = first, sourceBits, lane, true
	}
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[1])
	destination, destinationBits, destinationOK := arm64SVEFloatElementReg(ins.Args[2])
	validWidths := (form.sourceBits == 8 && (destinationBits == 16 || destinationBits == 32)) || (form.sourceBits == 16 && destinationBits == 32)
	if !secondOK || !destinationOK || secondBits != form.sourceBits || !validWidths {
		return true, false, fmt.Errorf("arm64 ZFDOT requires B sources with an H/S accumulator or H sources with an S accumulator: %q", ins.Raw)
	}
	if form.indexed {
		maxLane := 3
		if form.sourceBits == 8 && destinationBits == 16 {
			maxLane = 7
		}
		if form.lane > maxLane {
			return true, false, fmt.Errorf("arm64 ZFDOT lane is outside the selected dot-product group range: %q", ins.Raw)
		}
	}
	form.second, form.destination, form.destinationBits = second, destination, destinationBits
	return true, false, c.lowerARM64SVEFDOTForm(form)
}

func (c *arm64Ctx) lowerARM64SVEFDOTForm(form arm64SVEFDOTForm) error {
	accumulator, accumulatorType, err := c.loadRawSVEFloatVector(form.destination, form.destinationBits)
	if err != nil {
		return err
	}
	result := c.newTmp()
	if form.sourceBits == 8 {
		first, err := c.loadZReg(form.first)
		if err != nil {
			return err
		}
		second, err := c.loadZReg(form.second)
		if err != nil {
			return err
		}
		lanes := 128 / form.destinationBits
		mangle := map[int]string{16: "f16", 32: "f32"}[form.destinationBits]
		if form.indexed {
			fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.fp8.fdot.lane.nxv%d%s(%s %s, <vscale x 16 x i8> %s, <vscale x 16 x i8> %s, i32 %d)\n", result, accumulatorType, lanes, mangle, accumulatorType, accumulator, second, first, form.lane)
		} else {
			fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.fp8.fdot.nxv%d%s(%s %s, <vscale x 16 x i8> %s, <vscale x 16 x i8> %s)\n", result, accumulatorType, lanes, mangle, accumulatorType, accumulator, second, first)
		}
	} else {
		first, _, err := c.loadRawSVEFloatVector(form.first, 16)
		if err != nil {
			return err
		}
		second, _, err := c.loadRawSVEFloatVector(form.second, 16)
		if err != nil {
			return err
		}
		if form.indexed {
			fmt.Fprintf(c.b, "  %%%s = call <vscale x 4 x float> @llvm.aarch64.sve.fdot.lane.x2.nxv4f32(<vscale x 4 x float> %s, <vscale x 8 x half> %s, <vscale x 8 x half> %s, i32 %d)\n", result, accumulator, second, first, form.lane)
		} else {
			fmt.Fprintf(c.b, "  %%%s = call <vscale x 4 x float> @llvm.aarch64.sve.fdot.x2.nxv4f32(<vscale x 4 x float> %s, <vscale x 8 x half> %s, <vscale x 8 x half> %s)\n", result, accumulator, second, first)
		}
	}
	return c.storeRawSVEFloatVector(form.destination, form.destinationBits, "%"+result, accumulatorType)
}

func arm64SVEFDOTFeatureClass(ins Instr) (sourceBits, destinationBits int, ok bool) {
	if len(ins.Args) != 3 {
		return 0, 0, false
	}
	_, sourceBits, sourceOK := arm64ParseSVEZElementReg(ins.Args[0])
	if !sourceOK {
		_, sourceBits, _, sourceOK = arm64ParseSVEZIndexedElementRegUnbounded(ins.Args[0])
	}
	_, destinationBits, destinationOK := arm64SVEFloatElementReg(ins.Args[2])
	return sourceBits, destinationBits, sourceOK && destinationOK
}
