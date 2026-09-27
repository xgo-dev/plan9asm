package plan9asm

import (
	"fmt"
	"strings"
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
	registerCount, handled := arm64StructureLoadStoreCounts[op]
	if !handled {
		return false, false, nil
	}
	// VLD1 also has single-lane forms (for example VLD1.P (R0), V1.S[2]).
	// Keep those in the lane-specific lowerer below this mechanism.
	if op == "VLD1" && len(ins.Args) == 2 && ins.Args[1].Kind == OpReg {
		return false, false, nil
	}
	if op == "VST1" && len(ins.Args) == 2 && ins.Args[0].Kind == OpReg && ins.Args[1].Kind == OpMem {
		return false, false, nil
	}
	rawOp := strings.ToUpper(string(ins.Op))
	load := strings.HasPrefix(string(op), "VLD")
	replicate := strings.HasSuffix(string(op), "R")
	if rawOp != string(op) && rawOp != string(op)+".P" {
		return true, false, fmt.Errorf("arm64 %s accepts only the optional .P suffix: %q", op, ins.Raw)
	}
	if postInc != strings.HasSuffix(rawOp, ".P") || len(ins.Args) != 2 {
		return true, false, fmt.Errorf("arm64 %s expects one memory operand and one vector register list: %q", op, ins.Raw)
	}
	var memory Operand
	var listed []Reg
	if load {
		if ins.Args[0].Kind != OpMem || ins.Args[1].Kind != OpRegList {
			return true, false, fmt.Errorf("arm64 %s expects memory, [V...]: %q", op, ins.Raw)
		}
		memory, listed = ins.Args[0], ins.Args[1].RegList
	} else {
		if ins.Args[0].Kind != OpRegList || ins.Args[1].Kind != OpMem {
			return true, false, fmt.Errorf("arm64 %s expects [V...], memory: %q", op, ins.Raw)
		}
		listed, memory = ins.Args[0].RegList, ins.Args[1]
	}
	if len(listed) < 1 || len(listed) > 4 {
		return true, false, fmt.Errorf("arm64 %s expects a Go C_LIST containing one through four registers: %q", op, ins.Raw)
	}
	if replicate && postInc && memory.Mem.Off != 0 && len(listed) != registerCount {
		return true, false, fmt.Errorf("arm64 %s explicit-immediate post-indexed form expects exactly %d vector registers: %q", op, registerCount, ins.Raw)
	}
	arrangement, valid := parseARM64VectorArrangement(listed[0])
	firstIndex, firstValid := arm64ParseVReg(listed[0])
	if !valid || !firstValid {
		return true, false, fmt.Errorf("arm64 %s requires an arranged vector list: %q", op, ins.Raw)
	}
	for i, reg := range listed {
		parsed, ok := parseARM64VectorArrangement(reg)
		index, indexOK := arm64ParseVReg(reg)
		if !ok || parsed != arrangement || !indexOK || index != (firstIndex+i)%32 {
			return true, false, fmt.Errorf("arm64 %s requires consecutive same-arrangement vector registers: %q", op, ins.Raw)
		}
	}
	if op == "VLD1" || op == "VST1" {
		registerCount = len(listed)
	}
	registers := make([]Reg, registerCount)
	arrangementName := arm64VectorArrangementName(arrangement)
	for i := range registers {
		registers[i] = Reg(fmt.Sprintf("V%d.%s", (firstIndex+i)%32, arrangementName))
	}
	activeBytes := arrangement.lanes * arrangement.elementBits / 8
	incrementBytes := registerCount * activeBytes
	immediateBytes := len(listed) * activeBytes
	if replicate {
		incrementBytes = registerCount * arrangement.elementBits / 8
		immediateBytes = len(listed) * arrangement.elementBits / 8
	}
	addr, base, increment, err := c.arm64StructureAddress(memory.Mem, postInc, int64(incrementBytes), int64(immediateBytes))
	if err != nil {
		return true, false, fmt.Errorf("arm64 %s: %w", op, err)
	}
	if replicate {
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
	} else if load {
		for registerIndex, reg := range registers {
			value := "poison"
			for lane := 0; lane < arrangement.lanes; lane++ {
				elementOffset := arm64StructureElementOffset(op, arrangement, registerCount, registerIndex, lane)
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
				elementOffset := arm64StructureElementOffset(op, arrangement, registerCount, registerIndex, lane)
				if err := c.arm64StoreStructureElement(addr, elementOffset, arrangement.elementBits, "%"+element); err != nil {
					return true, false, err
				}
			}
		}
	}
	if postInc {
		if err := c.arm64UpdatePostIncrement(base, increment); err != nil {
			return true, false, err
		}
	}
	return true, false, nil
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

func (c *arm64Ctx) arm64StructureAddress(mem MemRef, postInc bool, incrementBytes, immediateBytes int64) (addr string, base Reg, increment string, err error) {
	base = mem.Base
	if base == ZR || base == Reg("RSP") {
		base = SP
	}
	addr, err = c.loadReg(base)
	if err != nil {
		return "", "", "", err
	}
	if !postInc {
		if mem.Off != 0 || mem.Index != "" {
			return "", "", "", fmt.Errorf("non-post-indexed structure memory must use (Rbase)")
		}
		return addr, base, "", nil
	}
	if mem.Index != "" {
		if mem.Off != 0 || mem.IndexExt != "" || (mem.Scale != 0 && mem.Scale != 1) {
			return "", "", "", fmt.Errorf("register post-increment requires plain (Rbase)(Rindex)")
		}
		increment, err = c.loadReg(mem.Index)
		return addr, base, increment, err
	}
	// `(Rbase)` is Go's implicit post-increment spelling. The encoded
	// instruction advances by the structure width even though its parsed
	// displacement is zero.
	if mem.Off == 0 {
		return addr, base, c.imm64(incrementBytes), nil
	}
	if mem.Off != immediateBytes {
		return "", "", "", fmt.Errorf("immediate post-increment is %d bytes, want %d for the written register list", mem.Off, immediateBytes)
	}
	return addr, base, c.imm64(incrementBytes), nil
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
