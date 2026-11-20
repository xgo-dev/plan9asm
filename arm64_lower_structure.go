package plan9asm

import (
	"fmt"
)

var arm64StructureLoadStoreCounts = map[Op]int{
	"VLD1":  1,
	"VLD2":  2,
	"VLD3":  3,
	"VLD4":  4,
	"VLD1R": 1,
	"VLD2R": 2,
	"VLD3R": 3,
	"VLD4R": 4,
	"VST1":  1,
	"VST2":  2,
	"VST3":  3,
	"VST4":  4,
}

func (c *arm64Ctx) lowerARM64StructureLoadStore(op Op, postInc bool, ins Instr) (ok bool, terminated bool, err error) {
	_, dispatched := arm64StructureLoadStoreCounts[op]
	_, sourceFamily := arm64StructureLoadStoreCounts[arm64ControlOp(ins)]
	if !dispatched {
		if sourceFamily {
			return true, false, fmt.Errorf("arm64 structure opcode dispatch %s disagrees with source %s: %q", op, ins.Op, ins.Raw)
		}
		return false, false, nil
	}

	expected := op
	if postInc {
		expected += ".P"
	}
	if ins.Op == "" {
		// Legacy helpers supply the opcode separately. Normalize a local
		// value copy; the original instruction and operands remain intact.
		ins.Op = expected
	} else if ins.Op != expected {
		return true, false, fmt.Errorf("arm64 structure dispatch %s disagrees with source %s: %q", expected, ins.Op, ins.Raw)
	}

	form, handled, err := parseARM64StructureMemory(ins)
	if !handled {
		return false, false, nil
	}
	if err != nil {
		return true, false, err
	}
	if postInc != form.post {
		return true, false, fmt.Errorf("arm64 %s inconsistent post-index dispatch: %q", op, ins.Raw)
	}
	if form.lane >= 0 {
		return true, false, c.lowerStructureLane(form)
	}
	registers, arrangement := form.registers, form.arrangement
	registerCount := len(registers)
	addr, increment, err := c.structureAddress(form)
	if err != nil {
		return true, false, err
	}
	if form.replicate {
		for registerIndex, reg := range registers {
			elementOffset := int64(registerIndex * arrangement.elementBits / 8)
			element, err := c.arm64LoadStructureElement(addr, elementOffset, arrangement.elementBits)
			if err != nil {
				return true, false, err
			}
			value := c.arm64VDUPSplat(arrangement, element)
			if err := c.storeARM64VectorInteger(reg, arrangement, value); err != nil {
				return true, false, err
			}
		}
	} else if op == "VLD1" || op == "VST1" {
		if err := c.lowerContiguousStructureTransfer(form, addr); err != nil {
			return true, false, err
		}
	} else if form.load {
		for registerIndex, reg := range registers {
			value := "poison"
			for lane := 0; lane < arrangement.lanes; lane++ {
				elementOffset := arm64StructureElementOffset(form.op, arrangement, registerCount, registerIndex, lane)
				element, err := c.arm64LoadStructureElement(addr, elementOffset, arrangement.elementBits)
				if err != nil {
					return true, false, err
				}
				inserted := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> %s, i%d %s, i32 %d\n",
					inserted, arrangement.lanes, arrangement.elementBits, value, arrangement.elementBits, element, lane)
				value = "%" + inserted
			}
			if err := c.storeARM64VectorInteger(reg, arrangement, value); err != nil {
				return true, false, err
			}
		}
	} else {
		values := make([]string, registerCount)
		for i, reg := range registers {
			values[i], err = c.loadARM64VectorInteger(reg, arrangement)
			if err != nil {
				return true, false, err
			}
		}
		for lane := 0; lane < arrangement.lanes; lane++ {
			for registerIndex := range registers {
				element := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %s, i32 %d\n", element, arrangement.lanes, arrangement.elementBits, values[registerIndex], lane)
				elementOffset := arm64StructureElementOffset(form.op, arrangement, registerCount, registerIndex, lane)
				if err := c.arm64StoreStructureElement(addr, elementOffset, arrangement.elementBits, "%"+element); err != nil {
					return true, false, err
				}
			}
		}
	}
	if postInc {
		if err := c.arm64UpdatePostIncrement(form.memory.Mem.Base, increment); err != nil {
			return true, false, err
		}
	}
	return true, false, nil
}

// LD/ST1 concatenate whole registers, unlike LD/ST2-4's interleaved lanes.
// Keep each register's exact 8/16-byte access and unaligned address contract.
func (c *arm64Ctx) lowerContiguousStructureTransfer(form arm64StructureMemoryForm, addr string) error {
	arrangement := form.arrangement
	values := make([]string, len(form.registers))
	if !form.load {
		for i, reg := range form.registers {
			value, err := c.loadARM64VectorInteger(reg, arrangement)
			if err != nil {
				return err
			}
			values[i] = value
		}
	}
	for i, reg := range form.registers {
		address := addr
		if i != 0 {
			added := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add i64 %s, %d\n", added, addr, i*arrangement.lanes*arrangement.elementBits/8)
			address = "%" + added
		}
		pointer := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pointer, address)
		if form.load {
			value := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load <%d x i%d>, ptr %%%s, align 1\n", value, arrangement.lanes, arrangement.elementBits, pointer)
			if err := c.storeARM64VectorInteger(reg, arrangement, "%"+value); err != nil {
				return err
			}
		} else {
			fmt.Fprintf(c.b, "  store <%d x i%d> %s, ptr %%%s, align 1\n", arrangement.lanes, arrangement.elementBits, values[i], pointer)
		}
	}
	return nil
}

func arm64StructureElementOffset(op Op, arrangement arm64VectorArrangement, registerCount, registerIndex, lane int) int64 {
	elementBytes := arrangement.elementBits / 8
	if op == "VLD1" || op == "VST1" {
		return int64(registerIndex*arrangement.lanes*elementBytes + lane*elementBytes)
	}
	return int64((lane*registerCount + registerIndex) * elementBytes)
}

func arm64VectorArrangementName(arrangement arm64VectorArrangement) string {
	kind := "B"
	switch arrangement.elementBits {
	case 16:
		kind = "H"
	case 32:
		kind = "S"
	case 64:
		kind = "D"
	}
	return fmt.Sprintf("%s%d", kind, arrangement.lanes)
}

func (c *arm64Ctx) arm64UpdatePostIncrement(base Reg, increment string) error {
	if increment == "" {
		return nil
	}
	baseValue, err := c.loadReg(base)
	if err != nil {
		return err
	}
	updated := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add i64 %s, %s\n", updated, baseValue, increment)
	return c.storeReg(base, "%"+updated)
}

func (c *arm64Ctx) arm64LoadStructureElement(addr string, offset int64, bits int) (string, error) {
	elementAddr := addr
	if offset != 0 {
		added := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i64 %s, %d\n", added, addr, offset)
		elementAddr = "%" + added
	}
	pointer := c.newTmp()
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pointer, elementAddr)
	fmt.Fprintf(c.b, "  %%%s = load i%d, ptr %%%s, align 1\n", value, bits, pointer)
	return "%" + value, nil
}

func (c *arm64Ctx) arm64StoreStructureElement(addr string, offset int64, bits int, value string) error {
	elementAddr := addr
	if offset != 0 {
		added := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i64 %s, %d\n", added, addr, offset)
		elementAddr = "%" + added
	}
	pointer := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pointer, elementAddr)
	fmt.Fprintf(c.b, "  store i%d %s, ptr %%%s, align 1\n", bits, value, pointer)
	return nil
}
