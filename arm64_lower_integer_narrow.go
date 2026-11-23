package plan9asm

import (
	"fmt"
	"math/bits"
	"strings"
)

type arm64IntegerNarrowKind uint8

const (
	arm64NarrowTruncate arm64IntegerNarrowKind = iota
	arm64NarrowSigned
	arm64NarrowUnsigned
	arm64NarrowSignedToUnsigned
)

type arm64IntegerNarrowOp struct {
	name              Op
	encoding          uint32
	kind              arm64IntegerNarrowKind
	shifted, rounding bool
}

var arm64IntegerNarrowOps = [...]arm64IntegerNarrowOp{
	{name: "VXTN", encoding: 0x0e212800, kind: arm64NarrowTruncate},
	{name: "VSQXTN", encoding: 0x0e214800, kind: arm64NarrowSigned},
	{name: "VUQXTN", encoding: 0x2e214800, kind: arm64NarrowUnsigned},
	{name: "VSQXTUN", encoding: 0x2e212800, kind: arm64NarrowSignedToUnsigned},
	{name: "VSQSHRN", encoding: 0x0f009400, kind: arm64NarrowSigned, shifted: true},
	{name: "VSQRSHRN", encoding: 0x0f009c00, kind: arm64NarrowSigned, shifted: true, rounding: true},
	{name: "VUQSHRN", encoding: 0x2f009400, kind: arm64NarrowUnsigned, shifted: true},
	{name: "VUQRSHRN", encoding: 0x2f009c00, kind: arm64NarrowUnsigned, shifted: true, rounding: true},
	{name: "VSQSHRUN", encoding: 0x2f008400, kind: arm64NarrowSignedToUnsigned, shifted: true},
	{name: "VSQRSHRUN", encoding: 0x2f008c00, kind: arm64NarrowSignedToUnsigned, shifted: true, rounding: true},
}

type arm64IntegerNarrowForm struct {
	arm64NarrowOperands
	op    *arm64IntegerNarrowOp
	shift int
}

func decodeARM64RawIntegerNarrow(word uint32) (arm64IntegerNarrowForm, bool) {
	const scalarBit, qBit = 1 << 28, 1 << 30
	const commonFields = scalarBit | qBit | 31<<5 | 31
	scalar, q := word&scalarBit != 0, word&qBit != 0
	if scalar && !q {
		return arm64IntegerNarrowForm{}, false
	}
	form := arm64IntegerNarrowForm{
		arm64NarrowOperands: arm64NarrowOperands{
			source: int(word >> 5 & 31), destination: int(word & 31),
			scalar: scalar, highHalf: q && !scalar,
		},
	}
	base := word &^ commonFields
	for i := range arm64IntegerNarrowOps {
		op := &arm64IntegerNarrowOps[i]
		if op.shifted {
			if base&^(0x7f<<16) != op.encoding {
				continue
			}
			immediate := uint8(word >> 16 & 0x7f)
			if immediate < 8 || immediate >= 64 {
				return arm64IntegerNarrowForm{}, false
			}
			form.bits = 1 << (bits.Len8(immediate) - 1)
			form.shift = 2*form.bits - int(immediate)
		} else {
			if base&^(3<<22) != op.encoding {
				continue
			}
			size := word >> 22 & 3
			if size == 3 || scalar && op.kind == arm64NarrowTruncate {
				return arm64IntegerNarrowForm{}, false
			}
			form.bits = 8 << size
		}
		form.op = op
		return form, true
	}
	return arm64IntegerNarrowForm{}, false
}

func (c *arm64Ctx) lowerARM64VectorIntegerNarrow(op Op, ins Instr) (bool, bool, error) {
	base := Op(strings.TrimSuffix(string(op), "2"))
	form := arm64IntegerNarrowForm{arm64NarrowOperands: arm64NarrowOperands{highHalf: base != op}}
	for i := range arm64IntegerNarrowOps {
		if arm64IntegerNarrowOps[i].name == base {
			form.op = &arm64IntegerNarrowOps[i]
			break
		}
	}
	if form.op == nil {
		return false, false, nil
	}

	first := 0
	if form.op.shifted {
		first = 1
	}
	invalid := func() (bool, bool, error) {
		return true, false, fmt.Errorf("arm64 %s requires H8->B8/S4->H4/D2->S2 (or the doubled *2 destination): %q", op, ins.Raw)
	}
	if !strings.EqualFold(string(ins.Op), string(op)) || len(ins.Args) != first+2 ||
		ins.Args[first].Kind != OpReg || ins.Args[first+1].Kind != OpReg {
		return invalid()
	}
	sourceReg, destinationReg := ins.Args[first].Reg, ins.Args[first+1].Reg
	source, sourceOK := parseARM64VectorArrangement(sourceReg)
	destination, destinationOK := parseARM64VectorArrangement(destinationReg)
	if !sourceOK || !destinationOK || destination.elementBits == 64 {
		return invalid()
	}
	form.bits = destination.elementBits
	wantSource, wantDestination := form.arrangements()
	if source != wantSource || destination != wantDestination {
		return invalid()
	}
	if form.op.shifted {
		shift := ins.Args[0]
		if shift.Kind != OpImm || shift.ImmRaw != "" || shift.ImmIsFloat ||
			shift.Imm < 1 || shift.Imm > int64(form.bits) {
			return true, false, fmt.Errorf("arm64 %s shift must be in [1,%d]: %q", op, form.bits, ins.Raw)
		}
		form.shift = int(shift.Imm)
	}
	form.source, _ = arm64ParseVReg(sourceReg)
	form.destination, _ = arm64ParseVReg(destinationReg)
	return true, false, c.lowerARM64IntegerNarrow(form)
}

func (c *arm64Ctx) lowerARM64IntegerNarrow(form arm64IntegerNarrowForm) error {
	if form.op.kind == arm64NarrowTruncate || !arm64ScalarConversionNativeTarget(c.targetTriple) {
		sourceView, destinationView := form.arrangements()
		return c.lowerARM64PortableIntegerNarrow(form, sourceView, destinationView)
	}
	return c.lowerARM64NativeNarrow(form.arm64NarrowOperands, strings.ToLower(string(form.op.name[1:])), form.shift, false)
}

func (c *arm64Ctx) lowerARM64PortableIntegerNarrow(form arm64IntegerNarrowForm, sourceView, destinationView arm64VectorArrangement) error {
	value, err := c.loadRawARM64VectorOperand(form.source, sourceView, 0, form.scalar)
	if err != nil {
		return err
	}
	sourceType := fmt.Sprintf("<%d x i%d>", sourceView.lanes, sourceView.elementBits)
	if form.op.shifted {
		operation := "ashr"
		if form.op.kind == arm64NarrowUnsigned {
			operation = "lshr"
		}
		shifted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s %s %s, %s\n", shifted, operation, sourceType, value,
			arm64VectorIntegerSplat(sourceView, int64(form.shift)))
		if form.op.rounding {
			roundingShift, roundingBit, rounded := c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %s\n", roundingShift, sourceType, value,
				arm64VectorIntegerSplat(sourceView, int64(form.shift-1)))
			fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %s\n", roundingBit, sourceType, roundingShift,
				arm64VectorIntegerSplat(sourceView, 1))
			fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %%%s\n", rounded, sourceType, shifted, roundingBit)
			shifted = rounded
		}
		value = "%" + shifted
	}

	switch form.op.kind {
	case arm64NarrowSigned:
		limit := int64(1) << (form.bits - 1)
		value = c.clampARM64VectorInteger(sourceType, sourceView, value, "slt", -limit, "sgt", limit-1)
	case arm64NarrowSignedToUnsigned:
		maximum := (int64(1) << form.bits) - 1
		value = c.clampARM64VectorInteger(sourceType, sourceView, value, "slt", 0, "sgt", maximum)
	case arm64NarrowUnsigned:
		maximum := arm64VectorIntegerSplat(sourceView, (int64(1)<<form.bits)-1)
		above, selected := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp ugt %s %s, %s\n", above, sourceType, value, maximum)
		fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %s, %s %s\n",
			selected, sourceView.lanes, above, sourceType, maximum, sourceType, value)
		value = "%" + selected
	}

	lowView := arm64VectorArrangement{form.bits, sourceView.lanes}
	narrowType := fmt.Sprintf("<%d x i%d>", lowView.lanes, lowView.elementBits)
	narrowed := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc %s %s to %s\n", narrowed, sourceType, value, narrowType)
	result := "%" + narrowed
	if form.highHalf {
		old, err := c.loadRawARM64VectorOperand(form.destination, lowView, 0, false)
		if err != nil {
			return err
		}
		indices := make([]int, destinationView.lanes)
		for i := range indices {
			indices[i] = i
		}
		result = c.arm64StructureShuffle(narrowType, old, result, indices)
	}
	return c.storeRawARM64VectorResult(form.destination, destinationView, result, form.scalar)
}

func (c *arm64Ctx) clampARM64VectorInteger(vectorType string, arrangement arm64VectorArrangement, source, lowerPredicate string, lower int64, upperPredicate string, upper int64) string {
	lowerValue := arm64VectorIntegerSplat(arrangement, lower)
	below := c.newTmp()
	lowerClamped := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp %s %s %s, %s\n", below, lowerPredicate, vectorType, source, lowerValue)
	fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %s, %s %s\n",
		lowerClamped, arrangement.lanes, below, vectorType, lowerValue, vectorType, source)
	upperValue := arm64VectorIntegerSplat(arrangement, upper)
	above := c.newTmp()
	upperClamped := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp %s %s %%%s, %s\n", above, upperPredicate, vectorType, lowerClamped, upperValue)
	fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %s, %s %%%s\n",
		upperClamped, arrangement.lanes, above, vectorType, upperValue, vectorType, lowerClamped)
	return "%" + upperClamped
}
