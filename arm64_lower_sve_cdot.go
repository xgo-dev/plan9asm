package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVECDOTForm struct {
	first, second, destination  int
	sourceBits, destinationBits int
	rotation                    int
	lane                        int
	indexed                     bool
}

func (c *arm64Ctx) lowerARM64SVECDOT(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZCDOT" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 4 || ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" || ins.Args[0].ImmIsFloat {
		return true, false, fmt.Errorf("arm64 ZCDOT expects $0|$90|$180|$270 and one complete Go 1.27 vector or indexed form: %q", ins.Raw)
	}
	rotation := int(ins.Args[0].Imm)
	if rotation != 0 && rotation != 90 && rotation != 180 && rotation != 270 {
		return true, false, fmt.Errorf("arm64 ZCDOT rotation must be $0, $90, $180, or $270: %q", ins.Raw)
	}
	form := arm64SVECDOTForm{rotation: rotation}
	if first, sourceBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1]); firstOK {
		form.first, form.sourceBits = first, sourceBits
	} else {
		first, sourceBits, lane, firstOK := arm64ParseSVEZIndexedElementRegUnbounded(ins.Args[1])
		if !firstOK {
			return true, false, fmt.Errorf("arm64 ZCDOT requires a B/H vector or indexed source: %q", ins.Raw)
		}
		form.first, form.sourceBits, form.lane, form.indexed = first, sourceBits, lane, true
	}
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[2])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[3])
	validWidths := (form.sourceBits == 8 && destinationBits == 32) || (form.sourceBits == 16 && destinationBits == 64)
	if !secondOK || !destinationOK || secondBits != form.sourceBits || !validWidths {
		return true, false, fmt.Errorf("arm64 ZCDOT requires B sources with an S accumulator or H sources with a D accumulator: %q", ins.Raw)
	}
	if form.indexed {
		maxRegister, maxLane := 7, 3
		if form.sourceBits == 16 {
			maxRegister, maxLane = 15, 1
		}
		if form.first > maxRegister || form.lane > maxLane {
			return true, false, fmt.Errorf("arm64 ZCDOT indexed source exceeds its register or lane range: %q", ins.Raw)
		}
	}
	form.second, form.destination, form.destinationBits = second, destination, destinationBits
	return true, false, c.lowerARM64SVECDOTForm(form)
}

func (c *arm64Ctx) lowerARM64SVECDOTForm(form arm64SVECDOTForm) error {
	accumulator, accumulatorType, err := c.loadZRegElements(form.destination, form.destinationBits)
	if err != nil {
		return err
	}
	first, sourceType, err := c.loadZRegElements(form.first, form.sourceBits)
	if err != nil {
		return err
	}
	second, _, err := c.loadZRegElements(form.second, form.sourceBits)
	if err != nil {
		return err
	}
	lanes := 128 / form.destinationBits
	result := c.newTmp()
	if form.indexed {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.cdot.lane.nxv%di%d(%s %s, %s %s, %s %s, i32 %d, i32 %d)\n", result, accumulatorType, lanes, form.destinationBits, accumulatorType, accumulator, sourceType, second, sourceType, first, form.lane, form.rotation)
	} else {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.cdot.nxv%di%d(%s %s, %s %s, %s %s, i32 %d)\n", result, accumulatorType, lanes, form.destinationBits, accumulatorType, accumulator, sourceType, second, sourceType, first, form.rotation)
	}
	return c.storeZRegElements(form.destination, form.destinationBits, "%"+result)
}
