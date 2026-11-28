package arm

import (
	"fmt"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

// A normal LLVM function may acquire flag-setting instructions before even its
// first sideeffect asm. Read CPSR at the actual A32 entry point and pass the
// snapshot to the lowered body as an ordinary AAPCS argument.
func (c *armCtx) emitEntryCPSRWrapper(publicHeader string) error {
	if !c.nativeA32 {
		return fmt.Errorf("%w: reading incoming CPSR requires an A32 target", asm.ErrProbeNeedsContext)
	}
	switch c.sig.Ret {
	case asm.Void, asm.I1, asm.I8, asm.I16, asm.I32, asm.I64, asm.Ptr:
	default:
		return fmt.Errorf("%w: incoming CPSR with return ABI %s", asm.ErrProbeNeedsContext, c.sig.Ret)
	}
	params := make([]string, 0, len(c.sig.Args)+2)
	for i, typ := range c.sig.Args {
		switch typ {
		case asm.I1, asm.I8, asm.I16, asm.I32, asm.Ptr:
		default:
			return fmt.Errorf("%w: incoming CPSR with argument ABI %s", asm.ErrProbeNeedsContext, typ)
		}
		params = append(params, fmt.Sprintf("%s %%arg%d", typ, i))
	}

	// If r0-r3 are occupied, prepend an aligned pair of stack words to the
	// existing stack arguments. Return registers go straight back to the caller.
	transfer := ""
	if len(params) < 4 {
		transfer = fmt.Sprintf("mrs r%d, cpsr\\0A\\09b BODY", len(params))
		params = append(params, "i32 %entry_cpsr")
	} else {
		// Keep the return address outside the body's incoming argument area.
		// A tail call or a spill may overwrite any word of that area.
		stackArgs := len(params) - 4
		var code []string
		code = append(code, "push {r4, lr}", "add r4, sp, #8", "mov r12, r4")
		for n := 4 * stackArgs; n > 0; {
			step := n
			if step > 252 {
				step = 252
			}
			code = append(code, fmt.Sprintf("add r12, r12, #%d", step))
			n -= step
		}
		if stackArgs%2 == 0 {
			code = append(code, "sub sp, sp, #4")
		}
		for i := 0; i < stackArgs; i++ {
			code = append(code, "ldr lr, [r12, #-4]!", "push {lr}")
		}
		// None of the instructions above sets NZCV.
		code = append(code, "mrs r12, cpsr", "push {r12}", "bl BODY", "sub sp, r4, #8", "pop {r4, pc}")
		transfer = strings.Join(code, "\\0A\\09")
		params = append(params, "")
		copy(params[5:], params[4:len(params)-1])
		params[4] = "i32 %entry_cpsr"
	}
	name := c.sig.Name + ".with_entry_cpsr"
	for {
		if _, ok := c.sigs[name]; !ok {
			break
		}
		name += "."
	}
	body := asm.LLVMGlobal(name)
	c.emitNakedTransfer(publicHeader, transfer, body)
	fmt.Fprintf(c.b, "define private %s %s(%s) noinline \"disable-tail-calls\"=\"true\" %s {\n", c.sig.Ret, body, strings.Join(params, ", "), c.sig.Attrs)
	return nil
}

// Naked assembly performs the actual transfer and return. Also express the
// return to LLVM so callers can be optimized without inventing a noreturn or
// constant-result contract.
func (c *armCtx) emitNakedTransfer(header, transfer, body string) {
	result, constraints, ret := "", "", "ret void"
	targetIndex := 0
	if c.sig.Ret != asm.Void {
		result = "%result = "
		constraints = "=r,"
		ret = fmt.Sprintf("ret %s %%result", c.sig.Ret)
		targetIndex = 1
	}
	input := ""
	if body != "" {
		transfer = strings.ReplaceAll(transfer, "BODY", fmt.Sprintf("${%d:c}", targetIndex))
		input = "ptr " + body
		constraints += "i,"
	}
	fmt.Fprintf(c.b, "define %s naked noinline %s {\n", header, c.sig.Attrs)
	fmt.Fprintf(c.b, "  %scall %s asm sideeffect \"%s\", \"%s~{memory}\"(%s)\n  %s\n}\n", result, c.sig.Ret, transfer, constraints, input, ret)
}
