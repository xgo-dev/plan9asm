package arm

import (
	"fmt"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

// ARM runtime stubs use WORD for instructions that the Plan 9 assembler cannot
// name at every GOARM level. Raw instructions must explicitly bind their Go
// register effects, since LLVM allocates the physical registers independently.
func (c *armCtx) lowerRawWord(ins asm.Instr) (bool, error) {
	if len(ins.Args) != 1 || ins.Args[0].Kind != asm.OpImm || ins.Args[0].ImmRaw != "" {
		return false, fmt.Errorf("arm WORD needs a 32-bit immediate: %q", ins.Raw)
	}
	if !c.nativeA32 {
		return false, fmt.Errorf("%w: executable ARM WORD needs an A32 target", asm.ErrProbeNeedsContext)
	}
	word := uint32(ins.Args[0].Imm)
	switch word {
	case 0xe7f001f0: // runtime.breakpoint
		fmt.Fprintf(c.b, "  call void asm sideeffect \".inst 0x%08x\", \"~{memory}\"()\n", word)
		return false, nil
	case 0xe320f001, 0xf57ff01f: // YIELD, CLREX
		fmt.Fprintf(c.b, "  call void asm sideeffect \".inst 0x%08x\", \"~{memory}\"()\n", word)
		return false, nil
	case 0xec510f0e, 0xec510f1e: // MRRC of the physical or virtual counter into R0:R1
		pair := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call {i32,i32} asm sideeffect \".inst 0x%08x\", \"={r0},={r1},~{memory}\"()\n", pair, word)
		for i := 0; i < 2; i++ {
			v := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractvalue {i32,i32} %%%s, %d\n", v, pair, i)
			if err := c.storeReg(asm.Reg(fmt.Sprintf("R%d", i)), "%"+v); err != nil {
				return false, err
			}
		}
		return false, nil
	}
	// Assign the encoded transfer register to r0 in the physical instruction,
	// then connect the LLVM input or output to the source program's register.
	reg := int(word >> 12 & 15)
	op := word &^ 0xf000
	if reg < 15 {
		r := asm.Reg(fmt.Sprintf("R%d", reg))
		switch op {
		case 0xeef10a10, 0xee1d0f70: // VMRS FPSCR or MRC of the TLS register
			v := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call i32 asm sideeffect \".inst 0x%08x\", \"={r0},~{memory}\"()\n", v, op)
			return false, c.storeReg(r, "%"+v)
		case 0xeee10a10: // VMSR FPSCR
			v, err := c.loadReg(r)
			if err != nil {
				return false, err
			}
			fmt.Fprintf(c.b, "  call void asm sideeffect \".inst 0x%08x\", \"{r0},~{memory}\"(i32 %s)\n", op, v)
			return false, nil
		}
	}
	return false, fmt.Errorf("arm: unsupported executable WORD %#08x", word)
}
