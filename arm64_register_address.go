package plan9asm

import (
	"fmt"
	"strings"
)

type arm64RegisterAddressForm struct {
	base, destination Reg
	offset            int64
	usesScratch       bool
	constantBase      bool
}

// Go's C_AACON/C_AACON2 rows use ADD/SUB immediates. C_LACON first
// materializes the literal into R27 and then reads the base for ADD.
func arm64AddressUsesScratch(offset int64) bool {
	addImmediate := func(value int64) bool {
		return value >= 0 && (value <= 0xfff || value&0xfff == 0 && value>>12 <= 0xfff)
	}
	return !addImmediate(offset) && !addImmediate(-offset) && (offset < 0 || offset > 0xffffff)
}

func parseARM64RegisterAddressForm(op Op, ins Instr) (arm64RegisterAddressForm, bool, error) {
	var f arm64RegisterAddressForm
	if len(ins.Args) == 0 || ins.Args[0].Kind != OpSym {
		return f, false, nil
	}
	address := strings.TrimSpace(ins.Args[0].Sym)
	if !strings.HasPrefix(address, "$") || strings.HasSuffix(address, "(SB)") {
		return f, false, nil
	}
	memory, ok := parseMem(strings.TrimSpace(strings.TrimPrefix(address, "$")))
	if !ok {
		return f, false, nil // Named constants retain their separate resolution.
	}
	constantBase := memory.Base == ZR
	if op != "MOVD" || string(ins.Op) != "MOVD" || len(ins.Args) != 2 ||
		ins.Args[1].Kind != OpReg ||
		(!arm64AddressReg(ins.Args[1].Reg) && !(constantBase && ins.Args[1].Reg == ZR)) ||
		(!arm64AddressReg(memory.Base) && !constantBase) || memory.Index != "" || memory.OffRaw != "" {
		return f, true, fmt.Errorf("arm64 register address requires MOVD $offset(GP/RSP),GP/RSP with no suffix: %q", ins.Raw)
	}
	f.base, f.destination, f.offset = memory.Base, ins.Args[1].Reg, memory.Off
	if constantBase && arm64StackReg(f.destination) {
		return f, true, fmt.Errorf("arm64 zero-base literal is not a GP/RSP address row: %q", ins.Raw)
	}
	f.constantBase = constantBase
	f.usesScratch = !constantBase && arm64AddressUsesScratch(memory.Off)
	return f, true, nil
}

func arm64AddressReg(reg Reg) bool {
	return arm64StackReg(reg) || isARM64GeneralOrZeroReg(reg) && reg != ZR
}

func (c *arm64Ctx) lowerARM64RegisterAddress(op Op, ins Instr) (bool, bool, error) {
	f, handled, err := parseARM64RegisterAddressForm(op, ins)
	if !handled || err != nil {
		return handled, false, err
	}
	if f.constantBase {
		return true, false, c.storeReg(f.destination, c.imm64(f.offset))
	}
	if f.usesScratch {
		if err := c.storeReg("R27", c.imm64(f.offset)); err != nil {
			return true, false, err
		}
	}
	base, err := c.loadReg(f.base)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add i64 %s, %s\n", result, base, c.imm64(f.offset))
	return true, false, c.storeReg(f.destination, "%"+result)
}
