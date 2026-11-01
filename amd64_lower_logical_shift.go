package plan9asm

import (
	"fmt"
)

type amd64PackedLogicalShiftSpec struct {
	laneBits int
	left     bool
	vector   bool
}

// amd64PackedLogicalShiftSpecs covers all Go 1.27 uniform packed logical
// shifts. Legacy operations use yps (MMX/XMM, immediate or packed count), and
// V-prefixed operations use _yvpslld (X/Y/Z data and an immediate or X/m128
// count, with the table's EVEX mask and D/Q broadcast forms).
var amd64PackedLogicalShiftSpecs = map[Op]amd64PackedLogicalShiftSpec{
	"PSLLW":  {laneBits: 16, left: true},
	"PSLLL":  {laneBits: 32, left: true},
	"PSLLQ":  {laneBits: 64, left: true},
	"PSRLW":  {laneBits: 16},
	"PSRLL":  {laneBits: 32},
	"PSRLQ":  {laneBits: 64},
	"VPSLLW": {laneBits: 16, left: true, vector: true},
	"VPSLLD": {laneBits: 32, left: true, vector: true},
	"VPSLLQ": {laneBits: 64, left: true, vector: true},
	"VPSRLW": {laneBits: 16, vector: true},
	"VPSRLD": {laneBits: 32, vector: true},
	"VPSRLQ": {laneBits: 64, vector: true},
}

func (c *amd64Ctx) lowerPackedLogicalShift(op Op, ins Instr) (ok bool, terminated bool, err error) {
	return c.lowerX86PackedShift(op, ins)
}

func (c *amd64Ctx) loadPackedUniformLogicalShiftCount(count Operand, mmx bool) (string, error) {
	if count.Kind == OpImm {
		return fmt.Sprintf("%d", uint8(count.Imm)), nil
	}
	if mmx {
		if count.Kind == OpMem || count.Kind == OpSym {
			bytes, err := c.loadX86PackedShiftBytes(count, 8, true)
			if err != nil {
				return "", err
			}
			value := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <8 x i8> %s to i64\n", value, bytes)
			return "%" + value, nil
		}
		return c.loadLegacyMMXPackedSource(count)
	}
	// The ignored upper count qword still belongs to the complete native
	// m128 read, even when a zero mask or saturated result is optimized.
	countBytes, err := c.loadX86PackedShiftBytes(count, 16, true)
	if err != nil {
		return "", err
	}
	countWords := c.newTmp()
	low := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", countWords, countBytes)
	fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %%%s, i32 0\n", low, countWords)
	return "%" + low, nil
}

func (c *amd64Ctx) emitPackedLogicalShift(spec amd64PackedLogicalShiftSpec, lanes int, data, count64 string) string {
	inRange := c.newTmp()
	safe64 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ult i64 %s, %d\n", inRange, count64, spec.laneBits)
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 %s, i64 0\n", safe64, inRange, count64)
	count := "%" + safe64
	if spec.laneBits < 64 {
		narrow := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i%d\n", narrow, count, spec.laneBits)
		count = "%" + narrow
	}
	counts := amd64SplatInteger(c, lanes, spec.laneBits, count)
	shifted := c.newTmp()
	operation := "lshr"
	if spec.left {
		operation = "shl"
	}
	typeName := fmt.Sprintf("<%d x i%d>", lanes, spec.laneBits)
	fmt.Fprintf(c.b, "  %%%s = %s %s %s, %s\n", shifted, operation, typeName, data, counts)
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s %%%s, %s zeroinitializer\n", result, inRange, typeName, shifted, typeName)
	return "%" + result
}
