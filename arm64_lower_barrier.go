package plan9asm

import (
	"fmt"
	"strings"
)

// lowerARM64Barrier implements Go's ADMB optab row, the ADSB/AISB aliases
// installed from it, and the operand-free ASB row.
func (c *arm64Ctx) lowerARM64Barrier(op Op, ins Instr) (ok bool, terminated bool, err error) {
	switch op {
	case "SB":
		if strings.ToUpper(string(ins.Op)) != "SB" || len(ins.Args) != 0 {
			return true, false, fmt.Errorf("arm64 SB accepts no operands or suffix: %q", ins.Raw)
		}
		// SB is encoded as HINT #7. Spelling the backward-compatible encoding
		// directly lets LLVM 22 compile the same object for every ARM64 baseline;
		// the memory clobber preserves the compiler-barrier semantics.
		fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q()\n", "hint #7", "~{memory}")
		return true, false, nil
	case "DMB", "DSB", "ISB":
	default:
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 1 || ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" {
		return true, false, fmt.Errorf("arm64 %s expects exactly one constant operand with no suffix: %q", op, ins.Raw)
	}
	encoded := uint64(ins.Args[0].Imm) & 0xf
	// Preserve the architectural operation instead of substituting a weaker
	// generic LLVM fence. The memory clobber also prevents compiler reordering
	// across DMB/DSB and is conservative for ISB.
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q()\n", strings.ToLower(string(op))+fmt.Sprintf(" #%d", encoded), "~{memory}")
	return true, false, nil
}
