package plan9asm

import (
	"fmt"
	"strings"
)

type amd64PackedScalarExtractSpec struct {
	bits         int
	vector       bool
	maxImmediate int64
	allowMMX     bool
}

var amd64PackedScalarExtractSpecs = map[Op]amd64PackedScalarExtractSpec{
	"EXTRACTPS":  {bits: 32, maxImmediate: 3},
	"VEXTRACTPS": {bits: 32, vector: true, maxImmediate: 255},
	"PEXTRB":     {bits: 8, maxImmediate: 255, allowMMX: true},
	"PEXTRW":     {bits: 16, maxImmediate: 255},
	"PEXTRD":     {bits: 32, maxImmediate: 255, allowMMX: true},
	"PEXTRQ":     {bits: 64, maxImmediate: 255, allowMMX: true},
	"VPEXTRB":    {bits: 8, vector: true, maxImmediate: 255},
	"VPEXTRW":    {bits: 16, vector: true, maxImmediate: 255},
	"VPEXTRD":    {bits: 32, vector: true, maxImmediate: 255},
	"VPEXTRQ":    {bits: 64, vector: true, maxImmediate: 255},
}

func (c *amd64Ctx) lowerPackedScalarExtract(op Op, ins Instr) (ok bool, terminated bool, err error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	if _, known := amd64PackedScalarExtractSpecs[Op(base)]; !known {
		return false, false, nil
	}
	var f x86ScalarLaneForm
	if base == "EXTRACTPS" || base == "VEXTRACTPS" {
		var ps x86InsertExtractForm
		ins, ps, _, err = c.bindInsertExtractForm(op, ins)
		f = x86ScalarLaneForm{bits: 32, gpBits: 32, source: ps.source, destination: ps.destination, offset: ps.offset, memory: ps.memory}
		if len(ins.Args) == 3 && ins.Args[2].Kind == OpReg {
			f.transferReg = ins.Args[2].Reg
		}
	} else {
		ins, f, _, err = c.bindScalarLaneForm(op, ins)
	}
	if err != nil {
		return true, false, err
	}
	destination := ins.Args[f.destination]
	if (base == "EXTRACTPS" || base == "VEXTRACTPS") && destination.Kind == OpFP {
		// Complete destination fields never initialize unknown source lanes.
		// Check before emitting any IR, including the source-register load.
		if _, err := c.scalarFPSpan(destination.FPOffset, 32); err != nil {
			return true, false, err
		}
		if err := c.scalarFPResultInitialized(); err != nil {
			return true, false, err
		}
	}

	source, err := c.loadX(ins.Args[f.source].Reg)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / f.bits
	laneVector, extracted := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <%d x i%d>\n", laneVector, source, lanes, f.bits)
	fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %%%s, i32 %d\n", extracted, lanes, f.bits, laneVector, f.offset/(f.bits/8))
	value := "%" + extracted
	if destination.Kind == OpReg {
		destination.Reg = f.transferReg
		if f.gpBits > f.bits {
			widened := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i%d %s to i%d\n", widened, f.bits, value, f.gpBits)
			value = "%" + widened
		} else if f.gpBits < f.bits {
			truncated := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i%d %s to i%d\n", truncated, f.bits, value, f.gpBits)
			value = "%" + truncated
		}
		return true, false, c.storeRegSized(destination.Reg, amd64IntegerTypeForBits(f.gpBits), value)
	}
	if (base == "EXTRACTPS" || base == "VEXTRACTPS") && destination.Kind == OpFP {
		// Parameter copies and result fields share the existing logical byte
		// writer. Neither source syntax nor a complete destination makes an
		// unknown selected X lane initialized, or a pointer/padding numeric.
		bytes := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast i32 %s to <4 x i8>\n", bytes, value)
		return true, false, c.storeFPVectorBytes(destination.FPOffset, 4, "%"+bytes, "")
	}
	return true, false, c.storePackedScalarExtractMemory(destination, amd64IntegerTypeForBits(f.bits), value)
}

func amd64MMXEncodingGP(index int) Reg {
	return [...]Reg{AX, CX, DX, BX, SP, BP, SI, DI}[index]
}

func (c *amd64Ctx) storePackedScalarExtractMemory(destination Operand, typ LLVMType, value string) error {
	bits := map[LLVMType]int{I8: 8, I16: 16, I32: 32, I64: 64}[typ]
	if destination.Kind == OpFP {
		return c.storeScalarLaneFPBits(destination.FPOffset, bits, value)
	}
	return c.storeVMOVIntegerScalar(destination, bits, value)
}
