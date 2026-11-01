package plan9asm

import (
	"fmt"
	"strings"
)

// Go's C_RACON/C_LACON rows are address calculations, not SB symbol loads.
// The small row uses ADD or SUB; the large row materializes the signed offset
// in R11, then always uses ADD. Both allow conditions and the flag-setting bit.
type armRegisterAddressForm struct {
	base, destination Reg
	offset            int64
	large, setFlags   bool
}

func parseARMRegisterAddressForm(op string, ins Instr, memory MemRef) (armRegisterAddressForm, error) {
	f := armRegisterAddressForm{base: memory.Base, offset: memory.Off}
	if op != "MOVW" || len(ins.Args) != 2 || ins.Args[1].Kind != OpReg || !isARMGeneralReg(ins.Args[1].Reg) {
		return f, fmt.Errorf("arm register address requires MOVW $offset(register),register: %q", ins.Raw)
	}
	f.destination = ins.Args[1].Reg
	if f.destination == PC || f.destination == SP || f.base == PC {
		return f, fmt.Errorf("arm register address cannot use PC/SP as a general-register operand: %q", ins.Raw)
	}
	if !isARMGeneralReg(f.base) || memory.Index != "" || memory.OffRaw != "" {
		return f, fmt.Errorf("arm register address requires a concrete immediate offset and one base register: %q", ins.Raw)
	}
	for _, suffix := range armInstructionSuffixes(ins) {
		if suffix == "S" {
			f.setFlags = true
		} else if suffix != "" && !armCondCodes[suffix] {
			return f, fmt.Errorf("arm MOVW register-address suffix %q is absent from the Go optab: %q", suffix, ins.Raw)
		}
	}
	f.large = !armRotatedImmediateEncodable(uint32(f.offset)) && !armRotatedImmediateEncodable(uint32(-f.offset))
	return f, nil
}

func (c *armCtx) lowerRegisterAddressMove(op, cond string, ins Instr) (bool, bool, error) {
	if _, ok := armIntegerMemorySpecs[op]; !ok || len(ins.Args) == 0 || ins.Args[0].Kind != OpSym {
		return false, false, nil
	}
	address := strings.TrimSpace(ins.Args[0].Sym)
	if !strings.HasPrefix(address, "$") {
		return false, false, nil
	}
	memory, ok := parseMem(strings.TrimSpace(strings.TrimPrefix(address, "$")))
	if !ok || memory.Base == SP {
		// Named pseudo-SP/FP addresses retain their separate frame contract.
		return false, false, nil
	}
	f, err := parseARMRegisterAddressForm(op, ins, memory)
	if err != nil {
		return true, false, err
	}
	err = c.emitConditionalEffect(cond, func() error {
		if f.large {
			// This happens before reading the base. An explicit R11 base must
			// therefore see the newly materialized offset, just like Go.
			if err := c.storeReg("R11", c.imm32(f.offset)); err != nil {
				return err
			}
		}
		left, err := c.loadReg(f.base)
		if err != nil {
			return err
		}
		operation, offset := "add", f.offset
		if !f.large && offset < 0 {
			operation, offset = "sub", -offset
		}
		right := c.imm32(offset)
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s i32 %s, %s\n", result, operation, left, right)
		if err := c.storeReg(f.destination, "%"+result); err != nil {
			return err
		}
		if !f.setFlags {
			return nil
		}
		// The condition is evaluated once before the effect. Testing it again
		// after updating one flag would change later flag writes' predicate.
		if operation == "sub" {
			return c.setFlagsSub("", left, right, "%"+result)
		}
		return c.setFlagsAdd("", left, right, "%"+result)
	})
	return true, false, err
}
