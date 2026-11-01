package plan9asm

import (
	"fmt"
	"strings"
)

// Go's asm7 types 22/23 accept pre/post-indexed scalar loads and stores
// with a signed nine-bit immediate. Unsigned narrow moves share the same
// table through oprangeset. Keep their typed load/store semantics in lowerData.
func (c *arm64Ctx) lowerARM64ScalarMemoryWriteback(op Op, ins Instr) (bool, bool, error) {
	switch op {
	case "MOVD", "MOVW", "MOVWU", "MOVH", "MOVHU", "MOVB", "MOVBU":
	default:
		return false, false, nil
	}
	rawOp := strings.ToUpper(string(ins.Op))
	if rawOp == string(op) {
		return false, false, nil
	}
	post := rawOp == string(op)+".P"
	pre := rawOp == string(op)+".W"
	if (!post && !pre) || len(ins.Args) != 2 {
		return true, false, fmt.Errorf("arm64 %s requires a single .P or .W memory writeback suffix: %q", op, ins.Raw)
	}

	memoryIndex, dataIndex := 0, 1
	if ins.Args[1].Kind == OpMem {
		memoryIndex, dataIndex = 1, 0
	}
	memory, data := ins.Args[memoryIndex], ins.Args[dataIndex]
	// Go's arm64 progedit rewrites literal $0 to REGZERO for these seven
	// move opcodes before matching asm7 types 22/23. Keep that exact source
	// alias; unresolved expressions and nonzero immediates are not registers.
	zeroStore := memoryIndex == 1 && data.Kind == OpImm && data.Imm == 0 && data.ImmRaw == ""
	if zeroStore {
		data = Operand{Kind: OpReg, Reg: ZR}
	}
	if memory.Kind != OpMem || data.Kind != OpReg || !isARM64GeneralOrZeroReg(data.Reg) {
		return true, false, fmt.Errorf("arm64 %s writeback requires memory and a general or zero register: %q", op, ins.Raw)
	}
	mem := memory.Mem
	if mem.OffRaw != "" || mem.Index != "" || mem.Off < -256 || mem.Off > 255 {
		return true, false, fmt.Errorf("arm64 %s writeback requires a signed nine-bit immediate memory offset: %q", op, ins.Raw)
	}
	if mem.Base != SP && mem.Base != Reg("RSP") && mem.Base == data.Reg {
		return true, false, fmt.Errorf("arm64 %s writeback has constrained unpredictable base/data register overlap: %q", op, ins.Raw)
	}

	normalized := ins
	normalized.Op = op
	if zeroStore || pre {
		normalized.Args = append([]Operand(nil), ins.Args...)
	}
	if zeroStore {
		normalized.Args[dataIndex] = data
	}
	if pre {
		base := mem.Base
		if base == ZR || base == Reg("RSP") {
			base = SP
		}
		if err := c.updatePostInc(base, mem.Off); err != nil {
			return true, false, err
		}
		memory.Mem.Off = 0
		normalized.Args[memoryIndex] = memory
	}
	return c.lowerData(op, post, normalized)
}
