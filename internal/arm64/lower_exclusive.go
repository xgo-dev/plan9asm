package arm64

import (
	"fmt"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

// Preserve the architectural monitor between load- and store-exclusive. A CAS
// on the original value cannot detect an intervening write of that value.
func (c *arm64Ctx) lowerExclusive(op asm.Op, ins asm.Instr) error {
	if !c.nativeAArch64 {
		return fmt.Errorf("%w: %s needs an AArch64 exclusive monitor", asm.ErrProbeNeedsContext, op)
	}
	load := strings.HasPrefix(string(op), "LD")
	mnemonic := strings.ToLower(strings.TrimSuffix(string(op), "W"))
	pair := strings.HasSuffix(mnemonic, "p")
	regFmt := "$%d"
	if strings.HasSuffix(string(op), "W") || strings.HasSuffix(mnemonic, "b") || strings.HasSuffix(mnemonic, "h") {
		regFmt = "${%d:w}"
	}
	memIdx, regIdx, count := 0, 1, 2
	if !load {
		memIdx, regIdx, count = 1, 0, 3
	}
	if len(ins.Args) != count || ins.Args[memIdx].Kind != asm.OpMem || (!load && ins.Args[2].Kind != asm.OpReg) {
		return fmt.Errorf("invalid arm64 exclusive operands: %s", ins.Raw)
	}
	data := ins.Args[regIdx]
	var regs []asm.Reg
	switch {
	case pair && data.Kind == asm.OpRegList && len(data.RegList) == 2:
		regs = data.RegList
	case !pair && data.Kind == asm.OpReg:
		regs = []asm.Reg{data.Reg}
	default:
		return fmt.Errorf("invalid arm64 exclusive register operand: %s", ins.Raw)
	}
	if load && pair && regs[0] == regs[1] {
		return fmt.Errorf("arm64 %s requires distinct load destinations", op)
	}
	if !load {
		status := ins.Args[2].Reg
		if status == ins.Args[memIdx].Mem.Base {
			return fmt.Errorf("arm64 %s status overlaps address", op)
		}
		for _, data := range regs {
			if status == data {
				return fmt.Errorf("arm64 %s status overlaps data", op)
			}
		}
	}
	addr, err := c.atomicMemPtr(ins.Args[memIdx].Mem)
	if err != nil {
		return err
	}

	result := c.newTmp()
	if load {
		if !pair {
			fmt.Fprintf(c.b, "  %%%s = call i64 asm sideeffect %q, \"=r,r,~{memory}\"(ptr %s)\n", result, mnemonic+" "+fmt.Sprintf(regFmt, 0)+", [$1]", addr)
			return c.storeReg(regs[0], "%"+result)
		}
		code := fmt.Sprintf("%s "+regFmt+", "+regFmt+", [$2]", mnemonic, 0, 1)
		fmt.Fprintf(c.b, "  %%%s = call {i64,i64} asm sideeffect %q, \"=&r,=&r,r,~{memory}\"(ptr %s)\n", result, code, addr)
		for i, r := range regs {
			value := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractvalue {i64,i64} %%%s, %d\n", value, result, i)
			if err := c.storeReg(r, "%"+value); err != nil {
				return err
			}
		}
		return nil
	}

	// The status output must not overlap either a data input or the base.
	code, constraints := mnemonic+" ${0:w}", "=&r"
	var args []string
	for i, r := range regs {
		value, err := c.loadReg(r)
		if err != nil {
			return err
		}
		args = append(args, "i64 "+value)
		code += ", " + fmt.Sprintf(regFmt, i+1)
		constraints += ",r"
	}
	code += fmt.Sprintf(", [$%d]", len(regs)+1)
	args = append(args, "ptr "+addr)
	fmt.Fprintf(c.b, "  %%%s = call i64 asm sideeffect %q, %q(%s)\n", result, code, constraints+",r,~{memory}", strings.Join(args, ", "))
	return c.storeReg(ins.Args[2].Reg, "%"+result)
}
