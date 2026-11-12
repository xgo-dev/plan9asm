package plan9asm

import (
	"fmt"
	"math/bits"
	"strings"
)

// Go asm5 types 35/36/37 select CPSR fields fs (mask 0xc), not fsxc.
// The Go frontend excludes SPSR and checkSuffix rejects .S/.P/.W/.U/.F.
// Raw A32 encodings may additionally select just f; control/extension fields
// and SPSR require a privileged machine-entry contract which we do not invent.
type armStatusMove struct {
	condition string
	write     bool
	fields    string
	source    Operand
	dest      Reg
}

func armStatusOperand(operand Operand) bool {
	return operand.Kind == OpIdent && (strings.EqualFold(operand.Ident, "CPSR") || strings.EqualFold(operand.Ident, "SPSR"))
}

func parseARMStatusMove(ins Instr) (armStatusMove, bool, error) {
	if ins.Op == "WORD" && len(ins.Args) == 1 && ins.Args[0].Kind == OpImm && ins.Args[0].ImmRaw == "" {
		if ins.Args[0].ImmIsFloat {
			return armStatusMove{}, true, fmt.Errorf("ARM WORD requires an integer encoding, not a floating operand: %s", ins.Raw)
		}
		return decodeARMRawStatusMove(uint32(ins.Args[0].Imm), ins.Raw)
	}
	matched := false
	for _, operand := range ins.Args {
		matched = matched || armStatusOperand(operand)
	}
	if !matched {
		return armStatusMove{}, false, nil
	}
	op, condition, _, _ := armDecodeOp(string(ins.Op))
	if op != "MOVW" || len(ins.Args) != 2 {
		return armStatusMove{}, true, fmt.Errorf("ARM status transfer requires Go MOVW CPSR,Rn or Rn/rotated-immediate,CPSR: %s", ins.Raw)
	}
	if err := armRequireConditionOnlySuffix(ins); err != nil {
		return armStatusMove{}, true, err
	}
	for _, operand := range armRawOperands(ins) {
		if strings.TrimSpace(operand) == "R10" {
			return armStatusMove{}, true, fmt.Errorf("ARM Go register table reserves R10; source must use the actual g spelling: %s", ins.Raw)
		}
	}
	for _, operand := range ins.Args {
		if operand.Kind == OpIdent && strings.EqualFold(operand.Ident, "SPSR") {
			return armStatusMove{}, true, fmt.Errorf("ARM SPSR spelling is not accepted by the Go assembler register table: %s", ins.Raw)
		}
	}
	form := armStatusMove{condition: condition, fields: "fs"}
	if armStatusOperand(ins.Args[0]) {
		form.dest = ins.Args[1].Reg
		if ins.Args[1].Kind != OpReg || !isARMGeneralReg(form.dest) {
			return form, true, fmt.Errorf("ARM CPSR read requires a physical GP destination: %s", ins.Raw)
		}
		return form, true, armStatusGPContext(form.dest, ins.Raw)
	}
	if !armStatusOperand(ins.Args[1]) {
		return form, true, fmt.Errorf("ARM CPSR write requires the status destination: %s", ins.Raw)
	}
	form.write, form.source = true, ins.Args[0]
	switch form.source.Kind {
	case OpReg:
		if !isARMGeneralReg(form.source.Reg) {
			return form, true, fmt.Errorf("ARM CPSR write requires a physical GP input: %s", ins.Raw)
		}
		return form, true, armStatusGPContext(form.source.Reg, ins.Raw)
	case OpImm:
		// A numerically integral float remains Go C_FCON, not C_RCON.
		if form.source.ImmIsFloat {
			return form, true, fmt.Errorf("ARM CPSR immediate requires the Go integer operand class: %s", ins.Raw)
		}
		if form.source.ImmRaw == "" {
			value := uint32(form.source.Imm)
			for rotation := 0; rotation < 32; rotation += 2 {
				if bits.RotateLeft32(value, rotation) <= 255 {
					return form, true, nil
				}
			}
		}
	}
	return form, true, fmt.Errorf("ARM CPSR write requires Go C_REG/C_RCON, not an arbitrary value or memory operand: %s", ins.Raw)
}

func armStatusGPContext(reg Reg, raw string) error {
	if reg == "R15" || reg == PC || reg == SP {
		return fmt.Errorf("%w: ARM status transfer using PC/pseudo-SP requires a physical source layout/stack contract: %s", ErrProbeNeedsContext, raw)
	}
	return nil
}

func decodeARMRawStatusMove(word uint32, raw string) (armStatusMove, bool, error) {
	read := word&0x0fbf0fff == 0x010f0000
	register := word&0x0fb0fff0 == 0x0120f000
	immediate := word&0x0fb0f000 == 0x0320f000
	if !read && !register && !immediate {
		return armStatusMove{}, false, nil
	}
	// The zero-mask CPSR immediate space is architectural HINT, not MSR.
	// Preserve the existing independent hint decoder (including old-CPU
	// YIELD-as-NOP behavior); unknown hints still fail in normal lowering.
	if immediate && word&(1<<22) == 0 && word>>16&15 == 0 {
		return armStatusMove{}, false, nil
	}
	condition, ok := armRawCondition(word >> 28)
	if !ok {
		return armStatusMove{}, true, fmt.Errorf("ARM PSR encoding has no A32 condition: %s", raw)
	}
	form := armStatusMove{condition: condition, write: !read}
	if word&(1<<22) != 0 {
		return form, true, fmt.Errorf("%w: ARM SPSR transfer requires a privileged exception-state entry contract: %s", ErrProbeNeedsContext, raw)
	}
	if read {
		form.dest = Reg(fmt.Sprintf("R%d", word>>12&15))
		return form, true, armStatusGPContext(form.dest, raw)
	}
	switch word >> 16 & 15 {
	case 8:
		form.fields = "f"
	case 12:
		form.fields = "fs"
	default:
		return form, true, fmt.Errorf("%w: ARM CPSR fields %#x require a separate status/control/extension effect contract: %s", ErrProbeNeedsContext, word>>16&15, raw)
	}
	if register {
		form.source = Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("R%d", word&15))}
		return form, true, armStatusGPContext(form.source.Reg, raw)
	}
	form.source = Operand{Kind: OpImm, Imm: int64(bits.RotateLeft32(word&255, -int(word>>8&15)*2))}
	return form, true, nil
}

func (c *armCtx) lowerStatusMove(form armStatusMove) error {
	return c.emitConditionalEffect(form.condition, func() error {
		if !form.write {
			value, err := c.eval32(Operand{Kind: OpIdent, Ident: "CPSR"}, false)
			if err != nil {
				return err
			}
			return c.storeReg(form.dest, value)
		}
		value, err := c.eval32(form.source, false)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(i32 %s)\n", "msr cpsr_"+form.fields+", $0", "r,~{cc},~{memory}", value)
		c.storeFlagsFromStatus(value)
		return nil
	})
}
