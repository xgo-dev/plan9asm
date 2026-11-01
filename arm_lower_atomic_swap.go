package plan9asm

import "fmt"

func (c *armCtx) lowerARMAtomicSwap(op, cond string, ins Instr) error {
	if err := armRequireConditionOnlySuffix(ins); err != nil {
		return err
	}
	if len(ins.Args) != 3 ||
		ins.Args[0].Kind != OpReg || !isARMGeneralReg(ins.Args[0].Reg) ||
		ins.Args[1].Kind != OpMem || ins.Args[1].Mem.Base == "" || ins.Args[1].Mem.Off != 0 ||
		ins.Args[1].Mem.OffRaw != "" || ins.Args[1].Mem.Index != "" || ins.Args[1].Mem.Sym != "" ||
		ins.Args[2].Kind != OpReg || !isARMGeneralReg(ins.Args[2].Reg) {
		return fmt.Errorf("arm %s expects source register, (base register), destination register: %q", op, ins.Raw)
	}
	if cond != "" {
		return c.emitConditionalEffect(cond, func() error {
			return c.lowerARMAtomicSwap(op, "", ins)
		})
	}
	source, err := c.loadReg(ins.Args[0].Reg)
	if err != nil {
		return err
	}
	address, _, _, err := c.addrI32(ins.Args[1].Mem, false)
	if err != nil {
		return err
	}
	pointer := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i32 %s to ptr\n", pointer, address)
	if op == "SWPW" {
		old := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = atomicrmw xchg ptr %%%s, i32 %s seq_cst\n", old, pointer, source)
		return c.storeReg(ins.Args[2].Reg, "%"+old)
	}
	narrowed := c.newTmp()
	old := c.newTmp()
	extended := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i32 %s to i8\n", narrowed, source)
	fmt.Fprintf(c.b, "  %%%s = atomicrmw xchg ptr %%%s, i8 %%%s seq_cst\n", old, pointer, narrowed)
	fmt.Fprintf(c.b, "  %%%s = zext i8 %%%s to i32\n", extended, old)
	return c.storeReg(ins.Args[2].Reg, "%"+extended)
}
