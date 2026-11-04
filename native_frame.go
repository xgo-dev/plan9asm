package plan9asm

import (
	"fmt"
	"strings"
)

type nativeFramePlan struct {
	local  int64
	saveBP bool
}

// Match current Go obj6's fixed-frame entry/return contract. Older host
// compilers can build this backend; their historical frame sequences and
// incoming FLAGS are not selected by the host SDK. Physical SP is independent
// of logical Go parameter, result and caller permissions.
func nativeTextFrame(fn Func, target NativeOptions) (nativeFramePlan, error) {
	var plan nativeFramePlan
	parts := strings.Split(fn.Instrs[0].Raw, ",")
	if len(parts) != 3 || !strings.HasPrefix(strings.TrimSpace(parts[2]), "$") {
		return plan, fmt.Errorf("native TEXT requires a complete fixed frame: %s", fn.Sym)
	}
	spec, err := parseTEXTFrameSpec(parts)
	if target.GOARCH == "arm64" && (err != nil || spec.argSize != 0 || spec.frameSize != 0) {
		return plan, fmt.Errorf("native ARM64 TEXT requires zero Go frame: %s", fn.Sym)
	}
	if err != nil || spec.argSize != 0 || spec.frameSize < 0 || spec.frameSize > 2147483639 || spec.frameSize%8 != 0 {
		return plan, fmt.Errorf("native TEXT requires aligned fixed locals and zero Go arguments: %s", fn.Sym)
	}
	flags, err := nativeFlags(parts[1], "NOSPLIT", "NOFRAME")
	if err != nil || !flags["NOSPLIT"] {
		return plan, fmt.Errorf("native TEXT requires exact NOSPLIT/frame flags: %s", fn.Sym)
	}
	if target.GOARCH != "amd64" {
		for _, ins := range fn.Instrs {
			if (ins.Op == "CALL" || ins.Op == "BL") && !flags["NOFRAME"] {
				return plan, fmt.Errorf("native ARM64 non-leaf TEXT requires NOFRAME: %s", fn.Sym)
			}
		}
		return plan, nil
	}
	plan.local = spec.frameSize
	hasCall := false
	var stackDelta int64
	for _, ins := range fn.Instrs {
		hasCall = hasCall || ins.Op == "CALL"
		if stack, known, err := x86StackWidthProperties(ins, "amd64"); known {
			if err != nil {
				return plan, err
			}
			if stack.mode == amd64StackPushValue || stack.mode == amd64StackPushFlags {
				stackDelta += int64(stack.bits / 8)
			} else {
				stackDelta -= int64(stack.bits / 8)
			}
		} else if ins.Op == "ADJSP" && len(ins.Args) != 0 && ins.Args[0].Kind == OpImm {
			stackDelta += ins.Args[0].Imm
		}
		if ins.Op == OpRET && stackDelta != 0 {
			return plan, fmt.Errorf("native TEXT has unbalanced PUSH/POP: %s", fn.Sym)
		}
	}
	plan.saveBP = !flags["NOFRAME"] && (plan.local != 0 || hasCall)
	return plan, nil
}

func (p nativeFramePlan) prologue(out *strings.Builder) {
	if p.saveBP {
		out.WriteString("\tpushq %rbp\n\tmovq %rsp, %rbp\n")
	}
	if p.local != 0 {
		fmt.Fprintf(out, "\tsubq $%d, %%rsp\n", p.local)
	}
}

func (p nativeFramePlan) epilogue(out *strings.Builder) {
	if p.local != 0 {
		fmt.Fprintf(out, "\taddq $%d, %%rsp\n", p.local)
	}
	if p.saveBP {
		out.WriteString("\tpopq %rbp\n")
	}
}
