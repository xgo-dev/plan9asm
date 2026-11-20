package plan9asm

import (
	"fmt"
	"strings"
)

func (c *amd64Ctx) namedLockPrefixBinding(block, instruction int, prefix Instr) error {
	context := func(reason string) error {
		return fmt.Errorf("%w: %s named LOCK needs a complete source-adjacent atomic operation: %s", ErrProbeNeedsContext, c.goarch, reason)
	}
	if prefix.Op != "LOCK" || len(prefix.Args) != 0 {
		return context("the prefix is not its exact zero-operand form")
	}
	if block < 0 || block >= len(c.blocks) || instruction < 0 || instruction+1 >= len(c.blocks[block].instrs) {
		return context("the body is missing or separated by a source/CFG boundary")
	}
	body := c.blocks[block].instrs[instruction+1]
	op := Op(strings.ToUpper(string(body.Op)))
	if form, recognized, err := x86LockScalarRMWProperties(op, body, c.goarch); recognized {
		if err != nil {
			return err
		}
		return x86LockScalarNativeMemoryBound(form, body, c.goarch)
	}
	if form, recognized, err := x86CompareExchangeProperties(op, body, c.goarch); recognized {
		if err != nil {
			return err
		}
		if form.destination.Kind != OpMem && form.destination.Kind != OpSym || body.x86UnboundAddressOverride {
			return context("the native CMPXCHG memory operand is not bound")
		}
		return nil
	}
	spec, known := amd64ExchangeSpecs[op]
	if !known {
		// A different RMW opcode may not inherit another family's witness.
		return context("the whole opcode effect is not independently closed")
	}
	form, err := parseAMD64ExchangeForm(c.goarch, op, spec, body)
	if err != nil {
		return context("the complete exchange operand grammar is not bound")
	}
	if form.other.Kind != OpMem && form.other.Kind != OpSym || body.x86UnboundAddressOverride {
		return context("the native memory operand is not bound")
	}
	if c.goarch == "386" && spec.bits == 8 {
		// Go synthesizes unavailable byte-register views through another GP
		// register. LOCK must not bind the first instruction of that expansion
		// as though it were the final byte memory RMW.
		switch form.register.Reg {
		case AX, BX, CX, DX, AL, AH, BL, BH, CL, CH, DL, DH:
		default:
			return context("the source byte-register view needs a Go encoder expansion")
		}
	}
	// These existing memory lowerers emit a complete native XADD with LOCK or
	// an implicitly locked XCHG, with read/write memory constraints, no guessed
	// alignment and their unchanged byte/flags effects. Address, initialization,
	// frame and caller permissions still come from the ordinary consumers.
	return nil
}

func (c *amd64Ctx) verifyNamedLockPrefixes() error {
	for block, body := range c.blocks {
		for instruction, prefix := range body.instrs {
			if !strings.EqualFold(string(prefix.Op), "LOCK") {
				continue
			}
			if err := c.namedLockPrefixBinding(block, instruction, prefix); err != nil {
				return err
			}
		}
	}
	return c.verifyNamedLockCarry()
}
