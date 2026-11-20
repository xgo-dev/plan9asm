package plan9asm

import "fmt"

func (c *arm64Ctx) lowerARM64ScalarMemory(op Op, ins Instr) (bool, bool, error) {
	f, handled, err := parseARM64ScalarMemoryForm(op, ins)
	if !handled || err != nil {
		return handled, false, err
	}
	// Capture the complete effective address before R27 is overwritten. In
	// Go's expanded transfer both the original base and the transfer data can
	// spell R27, but their reads occur on opposite sides of materialization.
	ptr, base, increment := "", Reg(""), int64(0)
	scratch := "undef"
	if f.memory.Kind == OpMem {
		mem := f.memory.Mem
		if f.pre {
			if err := c.updatePostInc(mem.Base, mem.Off); err != nil {
				return true, false, err
			}
			mem.Off = 0
		}
		if f.scratch && f.scratchKnown && f.scratchAddress {
			value, err := c.loadReg(f.scratchBase)
			if err != nil {
				return true, false, err
			}
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add i64 %s, %d\n", t, value, f.scratchOffset)
			scratch = "%" + t
		}
		address, addressBase, inc, err := c.addrI64(mem, f.post)
		if err != nil {
			return true, false, err
		}
		base, increment = addressBase, inc
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", t, address)
		ptr = "%" + t
	} else if f.memory.Kind == OpSym {
		ptr, err = c.ptrFromSB(f.memory.Sym)
		if err != nil {
			return true, false, err
		}
	}
	if f.scratch {
		if f.scratchKnown && !f.scratchAddress {
			scratch = c.imm64(f.scratchOffset)
		}
		if err := c.storeReg("R27", scratch); err != nil {
			return true, false, err
		}
		if !f.scratchKnown {
			c.recordMachineUnavailable("R27")
		}
	}
	if f.store {
		value, err := c.loadRegisterWidth(f.data, f.bits)
		if err != nil {
			return true, false, err
		}
		if f.memory.Kind == OpFP {
			err = c.storeFPFrameBits(f.memory.FPOffset, int64(f.bits/8), value)
		} else {
			if f.bits != 64 {
				t := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i%d\n", t, value, f.bits)
				value = "%" + t
			}
			fmt.Fprintf(c.b, "  store i%d %s, ptr %s, align 1\n", f.bits, value, ptr)
		}
		if err != nil {
			return true, false, err
		}
	} else {
		var value string
		if f.memory.Kind == OpFP {
			value, err = c.loadFPFrameBits(f.memory.FPOffset, int64(f.bits/8))
		} else {
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load i%d, ptr %s, align 1\n", t, f.bits, ptr)
			value = "%" + t
			if f.bits != 64 {
				t := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = zext i%d %s to i64\n", t, f.bits, value)
				value = "%" + t
			}
		}
		if err != nil {
			return true, false, err
		}
		if f.bits != 64 {
			value = c.arm64ExtendNarrow(value, f.bits, f.signed)
		}
		if err := c.storeReg(f.data, value); err != nil {
			return true, false, err
		}
	}
	return true, false, c.updatePostInc(base, increment)
}
