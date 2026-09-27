package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVEIntegerDotSpec struct {
	intrinsic   string
	mixed       bool
	indexedOnly bool
	rawBases    [4][2]uint32 // B->H, H->S, B->S, H->D; vector and indexed.
}

var arm64SVEIntegerDotSpecs = map[Op]arm64SVEIntegerDotSpec{
	"ZSDOT": {intrinsic: "sdot", rawBases: [4][2]uint32{
		{0x44400000, 0x44200000}, {0x4400c800, 0x4480c800},
		{0x44800000, 0x44a00000}, {0x44c00000, 0x44e00000},
	}},
	"ZUDOT": {intrinsic: "udot", rawBases: [4][2]uint32{
		{0x44400400, 0x44200400}, {0x4400cc00, 0x4480cc00},
		{0x44800400, 0x44a00400}, {0x44c00400, 0x44e00400},
	}},
	"ZSUDOT": {intrinsic: "sudot", mixed: true, indexedOnly: true,
		rawBases: [4][2]uint32{2: {0, 0x44a01c00}}},
	"ZUSDOT": {intrinsic: "usdot", mixed: true,
		rawBases: [4][2]uint32{2: {0x44807800, 0x44a01800}}},
}

type arm64SVEIntegerDotWidths struct {
	source, destination        int
	maximumVector, maximumLane int
	feature                    string
}

var arm64SVEIntegerDotWidthForms = [...]arm64SVEIntegerDotWidths{
	{8, 16, 7, 7, "+sve2p3"},
	{16, 32, 7, 3, "+sve2p1"},
	{8, 32, 7, 3, ""},
	{16, 64, 15, 1, ""},
}

type arm64SVEIntegerDotForm struct {
	intrinsic       string
	sourceBits      int
	destinationBits int
	first           int
	second          int
	destination     int
	lane            int
	indexed         bool
}

func arm64SVEIntegerDotFeature(ins Instr) string {
	if len(ins.Args) != 3 {
		return ""
	}
	_, sourceBits, ok := arm64ParseSVEZElementReg(ins.Args[0])
	if !ok {
		_, sourceBits, _, ok = arm64ParseSVEZIndexedElementRegUnbounded(ins.Args[0])
	}
	_, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	if !ok || !destinationOK {
		return ""
	}
	for _, widths := range arm64SVEIntegerDotWidthForms {
		if widths.source == sourceBits && widths.destination == destinationBits {
			return widths.feature
		}
	}
	return ""
}

func (c *arm64Ctx) lowerARM64SVEIntegerDot(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVEIntegerDotSpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects one complete Go 1.27 integer-dot form without a suffix: %q", op, ins.Raw)
	}
	form := arm64SVEIntegerDotForm{intrinsic: spec.intrinsic}
	if first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[0]); firstOK {
		form.first = first
		form.sourceBits = firstBits
	} else {
		first, firstBits, lane, firstOK := arm64ParseSVEZIndexedElementRegUnbounded(ins.Args[0])
		if !firstOK {
			return true, false, fmt.Errorf("arm64 %s first source must be a B/H vector or indexed vector: %q", op, ins.Raw)
		}
		form.first = first
		form.sourceBits = firstBits
		form.lane = lane
		form.indexed = true
	}
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[1])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	if !secondOK || secondBits != form.sourceBits || !destinationOK || !arm64SVEIntegerDotWidthOK(spec, form.sourceBits, destinationBits) || spec.indexedOnly && !form.indexed {
		return true, false, fmt.Errorf("arm64 %s has an invalid source/destination width or indexing mode: %q", op, ins.Raw)
	}
	if form.indexed {
		maximumVector, maximumLane := arm64SVEIntegerDotIndexedLimits(form.sourceBits, destinationBits)
		if maximumVector < 0 || form.first > maximumVector || form.lane > maximumLane {
			return true, false, fmt.Errorf("arm64 %s indexed source is outside the Go 1.27 register/lane range: %q", op, ins.Raw)
		}
	}
	form.second = second
	form.destination = destination
	form.destinationBits = destinationBits
	return true, false, c.lowerARM64SVEIntegerDotForm(form)
}

func arm64SVEIntegerDotWidthOK(spec arm64SVEIntegerDotSpec, sourceBits, destinationBits int) bool {
	if spec.mixed {
		return sourceBits == 8 && destinationBits == 32
	}
	for _, widths := range arm64SVEIntegerDotWidthForms {
		if widths.source == sourceBits && widths.destination == destinationBits {
			return true
		}
	}
	return false
}

func arm64SVEIntegerDotIndexedLimits(sourceBits, destinationBits int) (maximumVector, maximumLane int) {
	for _, widths := range arm64SVEIntegerDotWidthForms {
		if widths.source == sourceBits && widths.destination == destinationBits {
			return widths.maximumVector, widths.maximumLane
		}
	}
	return -1, -1
}

func (c *arm64Ctx) lowerARM64SVEIntegerDotForm(form arm64SVEIntegerDotForm) error {
	accumulator, destinationType, err := c.loadZRegElements(form.destination, form.destinationBits)
	if err != nil {
		return err
	}
	second, sourceType, err := c.loadZRegElements(form.second, form.sourceBits)
	if err != nil {
		return err
	}
	first, _, err := c.loadZRegElements(form.first, form.sourceBits)
	if err != nil {
		return err
	}
	if form.destinationBits == 16 {
		result := c.newTmp()
		assembly := form.intrinsic + " $0.h, $2.b, $3.b"
		if form.indexed {
			assembly += fmt.Sprintf("[%d]", form.lane)
		}
		fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q(%s %s, %s %s, %s %s)\n", result, destinationType, assembly, "=&w,0,w,w", destinationType, accumulator, sourceType, second, sourceType, first)
		return c.storeZRegElements(form.destination, form.destinationBits, "%"+result)
	}
	lanes := 128 / form.destinationBits
	intrinsic := form.intrinsic
	if form.indexed {
		intrinsic += ".lane"
	}
	if form.destinationBits == form.sourceBits*2 {
		intrinsic += ".x2"
	}
	result := c.newTmp()
	if form.indexed {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s, %s %s, i32 %d)\n", result, destinationType, intrinsic, lanes, form.destinationBits, destinationType, accumulator, sourceType, second, sourceType, first, form.lane)
	} else {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s, %s %s)\n", result, destinationType, intrinsic, lanes, form.destinationBits, destinationType, accumulator, sourceType, second, sourceType, first)
	}
	return c.storeZRegElements(form.destination, form.destinationBits, "%"+result)
}
