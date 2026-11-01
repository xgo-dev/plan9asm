package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVEWideningFloatMLASpec struct {
	intrinsic string
	fp16      bool
	fp8ToHalf bool
	fp8ToWord bool
}

var arm64SVEWideningFloatMLASpecs = map[Op]arm64SVEWideningFloatMLASpec{
	"ZFMLALB":   {intrinsic: "fmlalb", fp16: true, fp8ToHalf: true},
	"ZFMLALT":   {intrinsic: "fmlalt", fp16: true, fp8ToHalf: true},
	"ZFMLSLB":   {intrinsic: "fmlslb", fp16: true},
	"ZFMLSLT":   {intrinsic: "fmlslt", fp16: true},
	"ZFMLALLBB": {intrinsic: "fmlallbb", fp8ToWord: true},
	"ZFMLALLBT": {intrinsic: "fmlallbt", fp8ToWord: true},
	"ZFMLALLTB": {intrinsic: "fmlalltb", fp8ToWord: true},
	"ZFMLALLTT": {intrinsic: "fmlalltt", fp8ToWord: true},
}

type arm64SVEWideningFloatMLAForm struct {
	intrinsic                   string
	first, second, destination  int
	sourceBits, destinationBits int
	lane                        int
	indexed                     bool
}

func (c *arm64Ctx) lowerARM64SVEWideningFloatMLA(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVEWideningFloatMLASpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects one complete Go 1.27 vector or indexed widening floating multiply-accumulate form without a suffix: %q", op, ins.Raw)
	}
	form := arm64SVEWideningFloatMLAForm{intrinsic: spec.intrinsic}
	if first, sourceBits, firstOK := arm64ParseSVEZElementReg(ins.Args[0]); firstOK {
		form.first, form.sourceBits = first, sourceBits
	} else {
		first, sourceBits, lane, firstOK := arm64ParseSVEZIndexedElementRegUnbounded(ins.Args[0])
		if !firstOK || first > 7 {
			return true, false, fmt.Errorf("arm64 %s indexed source must use Z0..Z7: %q", op, ins.Raw)
		}
		form.first, form.sourceBits, form.lane, form.indexed = first, sourceBits, lane, true
	}
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[1])
	destination, destinationBits, destinationOK := arm64SVEFloatElementReg(ins.Args[2])
	validWidth := form.sourceBits == 16 && destinationBits == 32 && spec.fp16 ||
		form.sourceBits == 8 && destinationBits == 16 && spec.fp8ToHalf ||
		form.sourceBits == 8 && destinationBits == 32 && spec.fp8ToWord
	if !secondOK || !destinationOK || secondBits != form.sourceBits || !validWidth {
		return true, false, fmt.Errorf("arm64 %s source/destination widths are outside its complete Go 1.27 forms: %q", op, ins.Raw)
	}
	if form.indexed {
		maxLane := map[int]int{8: 15, 16: 7}[form.sourceBits]
		if form.lane > maxLane {
			return true, false, fmt.Errorf("arm64 %s indexed lane exceeds the Go 1.27 range for its source width: %q", op, ins.Raw)
		}
	}
	form.second, form.destination, form.destinationBits = second, destination, destinationBits
	return true, false, c.lowerARM64SVEWideningFloatMLAForm(form)
}

func (c *arm64Ctx) lowerARM64SVEWideningFloatMLAForm(form arm64SVEWideningFloatMLAForm) error {
	accumulator, accumulatorType, err := c.loadRawSVEFloatVector(form.destination, form.destinationBits)
	if err != nil {
		return err
	}
	result := c.newTmp()
	lanes := 128 / form.destinationBits
	mangle := map[int]string{16: "f16", 32: "f32"}[form.destinationBits]
	if form.sourceBits == 8 {
		first, err := c.loadZReg(form.first)
		if err != nil {
			return err
		}
		second, err := c.loadZReg(form.second)
		if err != nil {
			return err
		}
		if form.indexed {
			fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.fp8.%s.lane.nxv%d%s(%s %s, <vscale x 16 x i8> %s, <vscale x 16 x i8> %s, i32 %d)\n", result, accumulatorType, form.intrinsic, lanes, mangle, accumulatorType, accumulator, second, first, form.lane)
		} else {
			fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.fp8.%s.nxv%d%s(%s %s, <vscale x 16 x i8> %s, <vscale x 16 x i8> %s)\n", result, accumulatorType, form.intrinsic, lanes, mangle, accumulatorType, accumulator, second, first)
		}
	} else {
		first, sourceType, err := c.loadRawSVEFloatVector(form.first, 16)
		if err != nil {
			return err
		}
		second, _, err := c.loadRawSVEFloatVector(form.second, 16)
		if err != nil {
			return err
		}
		if form.indexed {
			fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.lane.nxv4f32(%s %s, %s %s, %s %s, i32 %d)\n", result, accumulatorType, form.intrinsic, accumulatorType, accumulator, sourceType, second, sourceType, first, form.lane)
		} else {
			fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv4f32(%s %s, %s %s, %s %s)\n", result, accumulatorType, form.intrinsic, accumulatorType, accumulator, sourceType, second, sourceType, first)
		}
	}
	return c.storeRawSVEFloatVector(form.destination, form.destinationBits, "%"+result, accumulatorType)
}

func arm64SVEWideningFloatMLAFeatureClass(ins Instr) (sourceBits int, ok bool) {
	if len(ins.Args) != 3 {
		return 0, false
	}
	_, sourceBits, sourceOK := arm64ParseSVEZElementReg(ins.Args[0])
	if !sourceOK {
		_, sourceBits, _, sourceOK = arm64ParseSVEZIndexedElementRegUnbounded(ins.Args[0])
	}
	return sourceBits, sourceOK
}
