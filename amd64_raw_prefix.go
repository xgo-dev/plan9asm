package plan9asm

import (
	"fmt"

	"golang.org/x/arch/x86/x86asm"
)

// Intel specifies that the r/m field is ignored for each unprefixed register
// fence encoding. The pinned decoder recognizes only the canonical r/m=0,
// and the cache-line recognizer otherwise mistakes SFENCE /7 for CLFLUSH.
// Do not strip or reinterpret any prefix here: those remain independently
// decoded and validated, including LOCK and the distinct 66 memory forms.
func decodedX86OrderingFenceInstruction(code []byte, mode int) (Instr, int, bool) {
	if mode != 32 && mode != 64 || len(code) < 3 || code[0] != 0x0f || code[1] != 0xae || code[2]>>6 != 3 {
		return Instr{}, 0, false
	}
	op := Op("")
	switch code[2] >> 3 & 7 {
	case 5:
		op = "LFENCE"
	case 6:
		op = "MFENCE"
	case 7:
		op = "SFENCE"
	default:
		return Instr{}, 0, false
	}
	return Instr{Op: op}, 3, true
}

// x/arch keeps invalidity in metadata that GoSyntax can erase or print as a
// standalone prefix with the real instruction in its operands. Reject before
// any width/alias rewrite. PrefixIgnored alone is not machine invalidity.
func decodedX86PrefixError(inst x86asm.Inst) error {
	for _, prefix := range inst.Prefix {
		if prefix&x86asm.PrefixInvalid != 0 {
			return fmt.Errorf("raw %s has a machine-invalid prefix 0x%02x", inst.Op, byte(prefix))
		}
	}
	for _, prefix := range inst.Prefix {
		if prefix&0xff == x86asm.PrefixLOCK && prefix&x86asm.PrefixIgnored == 0 {
			// This is valid native syntax, not invalid source. The existing
			// standalone LOCK lowerer cannot bind a printed whole RMW or its
			// atomic effect. Do not silently discard the following opcode.
			return fmt.Errorf("%w: raw LOCK %s requires its complete atomic prefix/operand effect", ErrProbeNeedsContext, inst.Op)
		}
		if prefix&(x86asm.PrefixIgnored|x86asm.PrefixImplicit) != 0 {
			continue
		}
		switch prefix {
		case x86asm.PrefixXACQUIRE, x86asm.PrefixXRELEASE, x86asm.PrefixBND:
			// GoSyntax uses only the low prefix byte for REP/REPNE. That
			// textual repeater is not the original transactional or bounds
			// effect and can leak onto a later string operation.
			return fmt.Errorf("%w: raw %s %s requires its complete native prefix effect", ErrProbeNeedsContext, prefix, inst.Op)
		}
	}
	return nil
}
