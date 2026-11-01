package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVEWideningAddSubKind uint8

const (
	arm64SVEAddSubLong arm64SVEWideningAddSubKind = iota
	arm64SVEAddSubWide
	arm64SVEAddSubNarrowBottom
	arm64SVEAddSubNarrowTop
)

type arm64SVEWideningAddSubSpec struct {
	intrinsic string
	kind      arm64SVEWideningAddSubKind
	rawBase   uint32
}

var arm64SVEWideningAddSubSpecs = map[Op]arm64SVEWideningAddSubSpec{
	"ZADDHNB":  {intrinsic: "addhnb", kind: arm64SVEAddSubNarrowBottom},
	"ZADDHNT":  {intrinsic: "addhnt", kind: arm64SVEAddSubNarrowTop},
	"ZRADDHNB": {intrinsic: "raddhnb", kind: arm64SVEAddSubNarrowBottom},
	"ZRADDHNT": {intrinsic: "raddhnt", kind: arm64SVEAddSubNarrowTop},
	"ZSADDLB":  {intrinsic: "saddlb", kind: arm64SVEAddSubLong},
	"ZSADDLBT": {intrinsic: "saddlbt", kind: arm64SVEAddSubLong},
	"ZSADDLT":  {intrinsic: "saddlt", kind: arm64SVEAddSubLong},
	"ZSADDWB":  {intrinsic: "saddwb", kind: arm64SVEAddSubWide, rawBase: 0x45004000},
	"ZSADDWT":  {intrinsic: "saddwt", kind: arm64SVEAddSubWide, rawBase: 0x45004400},
	"ZSSUBLB":  {intrinsic: "ssublb", kind: arm64SVEAddSubLong},
	"ZSSUBLBT": {intrinsic: "ssublbt", kind: arm64SVEAddSubLong},
	"ZSSUBLT":  {intrinsic: "ssublt", kind: arm64SVEAddSubLong},
	"ZSSUBLTB": {intrinsic: "ssubltb", kind: arm64SVEAddSubLong},
	"ZSSUBWB":  {intrinsic: "ssubwb", kind: arm64SVEAddSubWide, rawBase: 0x45005000},
	"ZSSUBWT":  {intrinsic: "ssubwt", kind: arm64SVEAddSubWide, rawBase: 0x45005400},
	"ZSUBHNB":  {intrinsic: "subhnb", kind: arm64SVEAddSubNarrowBottom},
	"ZSUBHNT":  {intrinsic: "subhnt", kind: arm64SVEAddSubNarrowTop},
	"ZRSUBHNB": {intrinsic: "rsubhnb", kind: arm64SVEAddSubNarrowBottom},
	"ZRSUBHNT": {intrinsic: "rsubhnt", kind: arm64SVEAddSubNarrowTop},
	"ZUADDLB":  {intrinsic: "uaddlb", kind: arm64SVEAddSubLong},
	"ZUADDLT":  {intrinsic: "uaddlt", kind: arm64SVEAddSubLong},
	"ZUADDWB":  {intrinsic: "uaddwb", kind: arm64SVEAddSubWide, rawBase: 0x45004800},
	"ZUADDWT":  {intrinsic: "uaddwt", kind: arm64SVEAddSubWide, rawBase: 0x45004c00},
	"ZUSUBLB":  {intrinsic: "usublb", kind: arm64SVEAddSubLong},
	"ZUSUBLT":  {intrinsic: "usublt", kind: arm64SVEAddSubLong},
	"ZUSUBWB":  {intrinsic: "usubwb", kind: arm64SVEAddSubWide, rawBase: 0x45005800},
	"ZUSUBWT":  {intrinsic: "usubwt", kind: arm64SVEAddSubWide, rawBase: 0x45005c00},
}

var arm64SVEAddSubWideRawOps = func() map[uint32]Op {
	rows := make(map[uint32]Op)
	for op, spec := range arm64SVEWideningAddSubSpecs {
		if spec.kind == arm64SVEAddSubWide && spec.rawBase != 0 {
			rows[spec.rawBase] = op
		}
	}
	return rows
}()

func decodeARM64RawSVEAddSubWide(word uint32) (Instr, bool) {
	op, ok := arm64SVEAddSubWideRawOps[word&0xff20fc00]
	size := word >> 22 & 3
	if !ok || size == 0 {
		return Instr{}, false
	}
	return Instr{Op: op, Raw: fmt.Sprintf("WORD $%#08x", word), Args: []Operand{
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", word>>16&31, "BHSD"[size-1]))},
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", word>>5&31, "BHSD"[size]))},
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", word&31, "BHSD"[size]))},
	}}, true
}

type arm64SVEWideningAddSubForm struct {
	sourceBits      int
	destinationBits int
	first           int
	second          int
	destination     int
}

func (c *arm64Ctx) lowerARM64SVEWideningAddSub(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVEWideningAddSubSpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects its three-register Go 1.27 SVE2 form without suffix: %q", op, ins.Raw)
	}
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
	first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	if !secondOK || !firstOK || !destinationOK {
		return true, false, fmt.Errorf("arm64 %s requires three scalable vector element registers: %q", op, ins.Raw)
	}
	form := arm64SVEWideningAddSubForm{first: first, second: second, destination: destination, destinationBits: destinationBits}
	switch spec.kind {
	case arm64SVEAddSubLong:
		if secondBits != firstBits || firstBits == 64 || destinationBits != 2*firstBits {
			return true, false, fmt.Errorf("arm64 %s requires matching B/H/S sources widened to H/S/D: %q", op, ins.Raw)
		}
		form.sourceBits = firstBits
	case arm64SVEAddSubWide:
		if secondBits == 64 || firstBits != 2*secondBits || destinationBits != firstBits {
			return true, false, fmt.Errorf("arm64 %s requires a narrow B/H/S source plus matching H/S/D wide source and destination: %q", op, ins.Raw)
		}
		form.sourceBits = secondBits
	case arm64SVEAddSubNarrowBottom, arm64SVEAddSubNarrowTop:
		if secondBits != firstBits || firstBits == 8 || destinationBits*2 != firstBits {
			return true, false, fmt.Errorf("arm64 %s requires matching H/S/D sources narrowed to B/H/S: %q", op, ins.Raw)
		}
		form.sourceBits = firstBits
	default:
		return true, false, fmt.Errorf("arm64 %s has an unknown widening/narrowing form", op)
	}
	return true, false, c.lowerARM64SVEWideningAddSubForm(spec, form)
}

func (c *arm64Ctx) lowerARM64SVEWideningAddSubForm(spec arm64SVEWideningAddSubSpec, form arm64SVEWideningAddSubForm) error {
	first, firstType, err := c.loadZRegElements(form.first, map[arm64SVEWideningAddSubKind]int{arm64SVEAddSubLong: form.sourceBits, arm64SVEAddSubWide: form.destinationBits, arm64SVEAddSubNarrowBottom: form.sourceBits, arm64SVEAddSubNarrowTop: form.sourceBits}[spec.kind])
	if err != nil {
		return err
	}
	second, secondType, err := c.loadZRegElements(form.second, form.sourceBits)
	if err != nil {
		return err
	}
	destinationType, destinationLanes, err := arm64SVEVectorType(form.destinationBits)
	if err != nil {
		return err
	}
	result := c.newTmp()
	if spec.kind == arm64SVEAddSubNarrowTop {
		merged, _, err := c.loadZRegElements(form.destination, form.destinationBits)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s, %s %s)\n", result, destinationType, spec.intrinsic, 128/form.sourceBits, form.sourceBits, destinationType, merged, firstType, first, secondType, second)
	} else if spec.kind == arm64SVEAddSubNarrowBottom {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s)\n", result, destinationType, spec.intrinsic, 128/form.sourceBits, form.sourceBits, firstType, first, secondType, second)
	} else {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s)\n", result, destinationType, spec.intrinsic, destinationLanes, form.destinationBits, firstType, first, secondType, second)
	}
	return c.storeZRegElements(form.destination, form.destinationBits, "%"+result)
}
