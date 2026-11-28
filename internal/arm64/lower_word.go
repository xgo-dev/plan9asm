package arm64

import (
	"fmt"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

// lowerRawWord models flag-writing and decoded AArch64 instructions emitted as
// raw WORD encodings by generated Go assembly.
func (c *arm64Ctx) lowerRawWord(ins asm.Instr) error {
	if len(ins.Args) != 1 || ins.Args[0].Kind != asm.OpImm || ins.Args[0].ImmRaw != "" {
		return fmt.Errorf("arm64: unsupported executable %s", ins.Raw)
	}

	word := uint32(ins.Args[0].Imm)
	switch {
	case word&0xfffff01f == 0xd503201f:
		// HINT has aliases with observable register or control-flow effects.
		// Decode this space before x/arch can erase the immediate in an alias.
		switch (word >> 5) & 127 {
		case 0:
			return nil // NOP
		case 1, 20: // YIELD and CSDB can be retained at their instruction site.
			if !c.nativeAArch64 {
				return fmt.Errorf("%w: raw HINT requires an AArch64 target", asm.ErrProbeNeedsContext)
			}
			fmt.Fprintf(c.b, "  call void asm sideeffect \".inst 0x%08x\", \"~{memory}\"()\n", word)
			return nil
		default:
			return fmt.Errorf("arm64: unsupported executable HINT %#x", word)
		}
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

	// Use named lowering after decoding. Preserve .P/.W addressing: the
	// immediate in a post-indexed word updates the base after the access.
	if decoded, ok := DecodeRawWord(word); ok {
		rawOp := strings.ToUpper(string(decoded.Op))
		name, suffix, _ := strings.Cut(rawOp, ".")
		op := asm.Op(name)
		post := suffix == "P"
		switch op {
		case "MRS", "MSR":
			if !c.nativeAArch64 {
				return fmt.Errorf("%w: raw %s needs an AArch64 target", asm.ErrProbeNeedsContext, op)
			}
		case "SB", "DMB", "DSB", "ISB", "DC", "BRK":
			// Use the original immediates and the translated value of Rt.
			if op == "DC" {
				r := asm.Reg(fmt.Sprintf("R%d", word&31))
				if word&31 == 31 {
					r = asm.ZR
				}
				return c.emitCacheMaintenance(int(word>>16&7), int(word>>8&15), int(word>>5&7), r)
			}
			if op == "DMB" || op == "DSB" || op == "ISB" {
				decoded.Args = []asm.Operand{{Kind: asm.OpImm, Imm: int64(word >> 8 & 15)}}
			}
			_, err := c.lowerSystemEffect(op, decoded)
			return err
		case "HINT":
			return fmt.Errorf("arm64: unsupported executable HINT %#x", word)
		case "NOP", "YIELD", "PRFM":
			return nil
		}
		if spec, ok := arm64SVETable.Lookup(op); ok && strings.HasPrefix(spec.LLVMOp, "sve_") {
			if !c.nativeAArch64 {
				return fmt.Errorf("%w: raw %s needs an AArch64 target", asm.ErrProbeNeedsContext, op)
			}
			_, _, err := c.lowerSVEOrSys(op, decoded)
			return err
		}
		savedPre := c.curPreInc
		c.curPreInc = suffix == "W"
		defer func() { c.curPreInc = savedPre }()
		savedB := c.b
		savedTmp := c.tmp
		var scratch strings.Builder
		c.b = &scratch
		handled, _, err := c.lowerArith(op, decoded)
		if !handled {
			handled, _, err = c.lowerVec(op, post, decoded)
		}
		if !handled {
			handled, _, err = c.lowerVecDeclarative(op, post, decoded)
		}
		if !handled {
			handled, _, err = c.lowerData(op, post, decoded)
		}
		if !handled {
			handled, _, err = c.lowerScalarDeclarative(op, post, decoded)
		}
		if !handled {
			handled, _, err = c.lowerFP(op, decoded)
		}
		if !handled {
			handled, _, err = c.lowerFPDeclarative(op, post, decoded)
		}
		c.b = savedB
		if handled && err == nil {
			c.b.WriteString(scratch.String())
			return nil
		}
		c.tmp = savedTmp
		if err != nil {
			return fmt.Errorf("arm64 raw instruction %s decoded as %s: %w", ins.Raw, decoded.Raw, err)
		}
	}

	return fmt.Errorf("arm64: unsupported executable %s", ins.Raw)
}
