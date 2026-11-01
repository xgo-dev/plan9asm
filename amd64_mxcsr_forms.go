package plan9asm

import (
	"fmt"
	"strings"
)

// Go's ysvrs_mo, ysvrs_om and _yvldmxcsr rows have one m32 operand.
// This descriptor gives no source, memory, frame or MXCSR control authority.
func x86MXCSRProperties(ins Instr, arch string) (write, known bool, err error) {
	base, _, dotted := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	switch base {
	case "LDMXCSR", "VLDMXCSR":
	case "STMXCSR", "VSTMXCSR":
		write = true
	default:
		return false, false, nil
	}
	if arch != "amd64" && arch != "386" || dotted || len(ins.Args) != 1 ||
		!isAMD64MemoryOperand(ins.Args[0]) || !x86PackedShiftMemoryValid(ins.Args[0], arch) {
		return write, true, fmt.Errorf("%s %s expects one Go m32 operand without suffixes: %q", arch, ins.Op, ins.Raw)
	}
	return write, true, nil
}

func x86TypedMXCSRByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	if ins.Op != "" && !strings.EqualFold(string(op), string(ins.Op)) {
		if _, known, _ := x86MXCSRProperties(Instr{Op: op}, arch); known {
			return x86TypedByteEffect{}, true, fmt.Errorf("MXCSR effect/source identity differs: %s/%s", op, ins.Op)
		}
		return x86TypedByteEffect{}, false, nil
	}
	ins.Op = op
	write, known, err := x86MXCSRProperties(ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	return x86TypedByteEffect{operands: []x86TypedByteOperand{
		{index: 0, operand: ins.Args[0], width: 4, read: !write, write: write},
	}}, true, nil // All six integer status bits and DF are unaffected.
}
