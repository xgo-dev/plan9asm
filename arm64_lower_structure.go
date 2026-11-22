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
	return true, false, c.lowerStructureMemory(form)
}

func (c *arm64Ctx) lowerStructureMemory(form arm64StructureMemoryForm) error {
	if form.lane >= 0 {
		return c.lowerStructureLane(form)
	}
	registers, arrangement := form.registers, form.arrangement
	addr, increment, err := c.structureAddress(form)
	if err != nil {
		return err
	}
	if form.replicate {
		for registerIndex, reg := range registers {
			elementOffset := int64(registerIndex * arrangement.elementBits / 8)
			element, err := c.arm64LoadStructureElement(addr, elementOffset, arrangement.elementBits)
			if err != nil {
				return err
			}
			value := c.arm64VDUPSplat(arrangement, element)
			if err := c.storeARM64VectorInteger(reg, arrangement, value); err != nil {
				return err
			}
		}
	} else if !form.interleaved {
		if err := c.lowerContiguousStructureTransfer(form, addr); err != nil {
			return err
		}
	} else {
		if err := c.lowerInterleavedStructureTransfer(form, addr); err != nil {
			return err
		}
	}
	if form.post {
		return c.arm64UpdatePostIncrement(form.memory.Mem.Base, increment)
	}
	return nil
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

// LD/ST2-4 transfer exactly one interleaved memory span. Regular strided
// shuffles let LLVM select the native structure operations where available.
func (c *arm64Ctx) lowerInterleavedStructureTransfer(form arm64StructureMemoryForm, addr string) error {
	arrangement := form.arrangement
	count, lanes := len(form.registers), arrangement.lanes
	wideType := fmt.Sprintf("<%d x i%d>", count*lanes, arrangement.elementBits)
	pointer := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pointer, addr)
	if form.load {
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load %s, ptr %%%s, align 1\n", wide, wideType, pointer)
		indices := make([]int, lanes)
		for i, reg := range form.registers {
			for lane := range indices {
				indices[lane] = lane*count + i
			}
			value := c.arm64StructureShuffle(wideType, "%"+wide, "poison", indices)
			if err := c.storeARM64VectorInteger(reg, arrangement, value); err != nil {
				return err
			}
		}
		return nil
	}

	var values [4]string
	for i, reg := range form.registers {
		value, err := c.loadARM64VectorInteger(reg, arrangement)
		if err != nil {
			return err
		}
		values[i] = value
	}
	vectorType := fmt.Sprintf("<%d x i%d>", lanes, arrangement.elementBits)
	left, right := values[0], values[1]
	if count > 2 {
		concat := make([]int, 2*lanes)
		for i := range concat {
			concat[i] = i
		}
		if count == 3 {
			values[3] = "poison" // No lane of the absent register is selected.
		}
		left = c.arm64StructureShuffle(vectorType, left, right, concat)
		right = c.arm64StructureShuffle(vectorType, values[2], values[3], concat)
		vectorType = fmt.Sprintf("<%d x i%d>", 2*lanes, arrangement.elementBits)
	}
	indices := make([]int, count*lanes)
	for i := range indices {
		indices[i] = (i%count)*lanes + i/count
	}
	value := c.arm64StructureShuffle(vectorType, left, right, indices)
	fmt.Fprintf(c.b, "  store %s %s, ptr %%%s, align 1\n", wideType, value, pointer)
	return nil
}

func (c *arm64Ctx) arm64StructureShuffle(vectorType, left, right string, indices []int) string {
	name := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector %s %s, %s %s, %s\n",
		name, vectorType, left, vectorType, right, arm64LLVMShuffleMask(indices))
	return "%" + name
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
