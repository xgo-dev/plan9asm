package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) lowerPCRelativeAddress(bi int, op Op, ins Instr) (ok bool, terminated bool, err error) {
	switch op {
	case "ADR", "ADRP":
	default:
		return false, false, nil
	}
	if strings.Contains(strings.ToUpper(string(ins.Op)), ".") {
		return true, false, fmt.Errorf("arm64 %s does not accept a suffix: %q", op, ins.Raw)
	}
	if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg || !isARM64GeneralOrZeroReg(ins.Args[1].Reg) {
		return true, false, fmt.Errorf("arm64 %s expects label|n(PC), general register: %q", op, ins.Raw)
	}

	target, targetOK := c.resolveBranchTarget(bi, ins.Args[0])
	if !targetOK || (ins.Args[0].Kind != OpIdent && ins.Args[0].Kind != OpSym &&
		(ins.Args[0].Kind != OpMem || ins.Args[0].Mem.Base != PC)) {
		return true, false, fmt.Errorf("arm64 %s expects label|n(PC), general register: %q", op, ins.Raw)
	}
	if ins.Args[0].Kind == OpSym && strings.HasSuffix(ins.Args[0].Sym, "(SB)") {
		return true, false, fmt.Errorf("arm64 %s expects a local label or n(PC): %q", op, ins.Raw)
	}

	value, err := c.arm64LocalPCAddress(target, op, ins.Raw)
	if err != nil {
		return true, false, err
	}
	if op == "ADRP" {
		page := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %s, -4096\n", page, value)
		value = "%" + page
	}
	return true, false, c.storeReg(ins.Args[1].Reg, value)
}

func (c *arm64Ctx) arm64LocalPCAddress(target string, op Op, source string) (string, error) {
	knownTarget := false
	for _, block := range c.blocks {
		if block.name == target {
			knownTarget = true
			break
		}
	}
	if !knownTarget {
		return "", fmt.Errorf("arm64 %s undefined local target %q: %q", op, target, source)
	}

	address := c.newTmp()
	if pointer, ok := c.arm64RawDataPointer(target); ok {
		fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i64\n", address, pointer)
	} else {
		fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr blockaddress(%s, %%%s) to i64\n", address, llvmGlobal(c.sig.Name), arm64LLVMBlockName(target))
	}
	return "%" + address, nil
}

func (c *arm64Ctx) arm64RawDataPointer(target string) (string, bool) {
	global, ok := c.rawDataGlobals[target]
	if !ok {
		return "", false
	}
	pointer := llvmGlobal(global)
	if offset := c.rawDataOffsets[target]; offset != 0 {
		pointer = fmt.Sprintf("getelementptr (i8, ptr %s, i64 %d)", pointer, offset)
	}
	return pointer, true
}
