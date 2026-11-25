package arm64

import (
	"fmt"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
	// lowerRawWord models flag-writing and decoded AArch64 instructions emitted as
	// raw WORD encodings by generated Go assembly.
)

func (c *arm64Ctx) lowerRawWord(ins asm.Instr) error {
	if len(ins.Args) != 1 || ins.Args[0].Kind != asm.OpImm || ins.Args[0].ImmRaw != "" {
		return nil
	}

	word := uint32(ins.Args[0].Imm)
	switch {
	case word == 0xea00001f: // TST X0, X0 (ANDS XZR, X0, X0)
		value, err := c.loadReg("R0")
		if err != nil {
			return err
		}
		c.setFlagsLogic(value)
		return nil

	case word&0xff800000 == 0xf1000000: // SUBS Xd, Xn, #imm{, LSL #12}
		rn := (word >> 5) & 31
		rd := word & 31
		imm := int64((word >> 10) & 0xfff)
		if word&(1<<22) != 0 {
			imm <<= 12
		}

		srcReg := asm.Reg(fmt.Sprintf("R%d", rn))
		if rn == 31 {
			srcReg = asm.SP
		}
		src, err := c.loadReg(srcReg)
		if err != nil {
			return err
		}

		resTmp := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub i64 %s, %d\n", resTmp, src, imm)
		res := "%" + resTmp
		if rd != 31 {
			if err := c.storeReg(asm.Reg(fmt.Sprintf("R%d", rd)), res); err != nil {
				return err
			}
		}
		c.setFlagsSub(src, fmt.Sprintf("%d", imm), res)
		return nil
	}

	// Fallback: decode arbitrary AArch64 WORD encodings via arm64asm and lower
	// supported arithmetic/SIMD/crypto instructions through the normal pipeline.
	if decoded, ok := DecodeRawWord(word); ok {
		op := asm.Op(strings.ToUpper(string(decoded.Op)))
		if op == "NOP" || op == "HINT" || op == "YIELD" || op == "DMB" || op == "DSB" || op == "ISB" {
			return nil
		}
		if handled, _, err := c.lowerArith(op, decoded); handled {
			return err
		}
		if handled, _, err := c.lowerVec(op, false, decoded); handled {
			return err
		}
	}

	return nil
}
