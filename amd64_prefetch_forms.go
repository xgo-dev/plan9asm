package plan9asm

import (
	"fmt"
	"strings"
)

// Go's yprefetch row has one Ym operand. The extended opcode names are
// supplied by the raw decoder and share the same memory shape.
func x86PrefetchProperties(op Op, ins Instr, arch string) (bool, error) {
	if !strings.HasPrefix(string(op), "PREFETCH") {
		return false, nil
	}
	name, _, dotted := strings.Cut(string(op), ".")
	switch name {
	case "PREFETCHNTA", "PREFETCHT0", "PREFETCHT1", "PREFETCHT2",
		"PREFETCHRST2", "PREFETCHIT0", "PREFETCHIT1":
	default:
		return false, nil
	}
	if dotted || arch != "amd64" && arch != "386" || len(ins.Args) != 1 ||
		ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) ||
		!isAMD64MemoryOperand(ins.Args[0]) || !x86PackedShiftMemoryValid(ins.Args[0], arch) ||
		x86NamedMultiplyMemoryError(ins.Args[0], arch) != nil {
		return true, fmt.Errorf("%s %s expects one encodable memory operand: %q", arch, op, ins.Raw)
	}
	return true, nil
}
