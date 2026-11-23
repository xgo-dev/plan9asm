package plan9asm

import (
	"fmt"
	"math/bits"
	"strings"
)

type arm64ShiftInsertForm struct {
	arrangement         arm64VectorArrangement
	source, destination Reg
	shift               int64
	right               bool
}

func decodeARM64RawShiftInsert(word uint32) (arm64ShiftInsertForm, bool) {
	const (
		scalarBit = 1 << 28
		qBit      = 1 << 30
		leftBit   = 1 << 12
		fields    = scalarBit | qBit | leftBit | 0x7f<<16 | 31<<5 | 31
	)
	if word&^fields != 0x2f004400 {
		return arm64ShiftInsertForm{}, false
	}
	immediate := int64(word >> 16 & 127)
	if immediate < 8 { // immh=0 is outside the shift-immediate encoding.
		return arm64ShiftInsertForm{}, false
	}
	width := 1 << (bits.Len8(uint8(immediate)) - 1)
	arrangement := arm64VectorArrangement{elementBits: width, lanes: (64 << (word >> 30 & 1)) / width}
	if word&scalarBit != 0 {
		if word&qBit == 0 || width != 64 {
			return arm64ShiftInsertForm{}, false
		}
		arrangement.lanes = 1
	} else if !arm64IntegerShiftVectorArrangement(arrangement) {
		return arm64ShiftInsertForm{}, false
	}
	form := arm64ShiftInsertForm{
		arrangement: arrangement,
		source:      Reg(fmt.Sprintf("V%d", word>>5&31)), destination: Reg(fmt.Sprintf("V%d", word&31)),
		right: word&leftBit == 0,
	}
	form.shift = immediate - int64(width)
	if form.right {
		form.shift = int64(2*width) - immediate
	}
	return form, true
}

func (c *arm64Ctx) lowerARM64VectorShiftInsert(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "VSRI" && op != "VSLI" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 || ins.Args[0].Kind != OpImm || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
		return true, false, fmt.Errorf("arm64 %s expects $shift, Vsrc.<T>, Vdst.<T> and no suffix: %q", op, ins.Raw)
	}
	sourceArrangement, sourceOK := parseARM64VectorArrangement(ins.Args[1].Reg)
	destinationArrangement, destinationOK := parseARM64VectorArrangement(ins.Args[2].Reg)
	if !sourceOK || !destinationOK || sourceArrangement != destinationArrangement || !arm64IntegerShiftVectorArrangement(sourceArrangement) {
		return true, false, fmt.Errorf("arm64 %s requires matching B8/B16/H4/H8/S2/S4/D2 arrangements: %q", op, ins.Raw)
	}
	immediate := ins.Args[0]
	if immediate.ImmRaw != "" || immediate.ImmIsFloat {
		return true, false, fmt.Errorf("arm64 %s requires an integer shift amount: %q", op, ins.Raw)
	}
	shift := immediate.Imm
	if op == "VSRI" {
		if shift < 1 || shift > int64(sourceArrangement.elementBits) {
			return true, false, fmt.Errorf("arm64 VSRI shift must be in [1,%d]: %q", sourceArrangement.elementBits, ins.Raw)
		}
	} else if shift < 0 || shift >= int64(sourceArrangement.elementBits) {
		return true, false, fmt.Errorf("arm64 VSLI shift must be in [0,%d]: %q", sourceArrangement.elementBits-1, ins.Raw)
	}
	return true, false, c.lowerARM64ShiftInsertForm(arm64ShiftInsertForm{
		arrangement: sourceArrangement, source: ins.Args[1].Reg, destination: ins.Args[2].Reg,
		shift: shift, right: op == "VSRI",
	})
}

func (c *arm64Ctx) lowerARM64ShiftInsertForm(form arm64ShiftInsertForm) error {
	arrangement, shift := form.arrangement, form.shift
	source, err := c.loadARM64VectorInteger(form.source, arrangement)
	if err != nil {
		return err
	}
	destination, err := c.loadARM64VectorInteger(form.destination, arrangement)
	if err != nil {
		return err
	}
	if shift == 0 {
		return c.storeARM64VectorInteger(form.destination, arrangement, source)
	}
	if shift == int64(arrangement.elementBits) {
		return c.storeARM64VectorInteger(form.destination, arrangement, destination)
	}

	op := "shl"
	preserve := (int64(1) << uint(shift)) - 1
	if form.right {
		op = "lshr"
		preserve = -(int64(1) << uint(int64(arrangement.elementBits)-shift))
	}
	vectorType := fmt.Sprintf("<%d x i%d>", arrangement.lanes, arrangement.elementBits)
	preserved := c.newTmp()
	inserted := c.newTmp()
	combined := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and %s %s, %s\n", preserved, vectorType, destination, arm64VectorIntegerSplat(arrangement, preserve))
	fmt.Fprintf(c.b, "  %%%s = %s %s %s, %s\n", inserted, op, vectorType, source, arm64VectorIntegerSplat(arrangement, shift))
	fmt.Fprintf(c.b, "  %%%s = or %s %%%s, %%%s\n", combined, vectorType, preserved, inserted)
	return c.storeARM64VectorInteger(form.destination, arrangement, "%"+combined)
}
