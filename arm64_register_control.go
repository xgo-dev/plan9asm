package plan9asm

import (
	"fmt"
	"strings"
)

// Go's AB accepts C_ZOREG; ABL accepts C_ZREG and C_ZOREG. Encoding
// register 31 in BR/BLR reads XZR, even when the frontend spells it RSP.
func (c *arm64Ctx) registerBranchAddress(op Op, ins Instr) (string, error) {
	if len(ins.Args) != 1 || strings.Contains(string(ins.Op), ".") {
		return "", fmt.Errorf("arm64 %s expects one unsuffixed register target: %q", op, ins.Raw)
	}
	target := ins.Args[0]
	if op == OpRET {
		// obj7's RET auto-epilogue keeps only To.Reg (or the default LR),
		// then emits zero-displacement ARET. Its source displacement/index
		// and a sole immediate operand are deliberately not branch offsets.
		if normalized, ok := arm64RegisterReturnTarget(ins, false); ok {
			target = normalized
		}
	}
	if target.Kind == OpReg {
		if (op != "BL" && op != "BLR" && op != "CALL" && op != OpRET) || !isARM64GeneralOrZeroReg(target.Reg) {
			return "", fmt.Errorf("arm64 %s does not accept this bare register: %q", op, ins.Raw)
		}
		return c.loadReg(target.Reg)
	}
	if target.Kind != OpMem || target.Mem.Off != 0 || target.Mem.OffRaw != "" || target.Mem.Index != "" {
		return "", fmt.Errorf("arm64 %s expects (general register) with zero displacement: %q", op, ins.Raw)
	}
	reg := target.Mem.Base
	if reg == SP || reg == Reg("RSP") || reg == ZR {
		return "0", nil
	}
	if !isARM64GeneralOrZeroReg(reg) {
		return "", fmt.Errorf("arm64 %s expects (general register): %q", op, ins.Raw)
	}
	return c.loadReg(reg)
}

func (c *arm64Ctx) storeLocalLink(continuation string) error {
	link := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr blockaddress(%s, %%%s) to i64\n", link, llvmGlobal(c.sig.Name), arm64LLVMBlockName(continuation))
	return c.storeReg(Reg("R30"), "%"+link)
}

func (c *arm64Ctx) storeCallerLink() error {
	pointer, address := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call ptr @llvm.returnaddress(i32 0)\n  %%%s = ptrtoint ptr %%%s to i64\n", pointer, address, pointer)
	return c.storeReg(Reg("R30"), "%"+address)
}

func (c *arm64Ctx) lowerRegisterControl(bi int, op Op, ins Instr) (bool, error) {
	// BLR R30 must read its destination before replacing the link register.
	addr, err := c.registerBranchAddress(op, ins)
	if err != nil {
		return false, err
	}
	if c.lowerProvenUnreachableControl(bi) {
		return true, nil
	}
	targets, err := c.localControlTargets(bi)
	if err != nil {
		return false, err
	}
	call := op == "BL" || op == "BLR" || op == "CALL"
	if call {
		if bi+1 >= len(c.blocks) {
			return false, fmt.Errorf("arm64 %s has no continuation block: %q", op, ins.Raw)
		}
		if err := c.storeLocalLink(c.blocks[bi+1].name); err != nil {
			return false, err
		}
	}
	if len(targets) != 0 {
		// The caller's native link is not an in-function blockaddress. A
		// reaching-definition proof of that one target lowers to an ordinary
		// LLVM return block; no native pointer goes through indirectbr.
		if len(targets) == 1 && targets[0] == c.localControl.outer {
			if call {
				return false, fmt.Errorf("%w: ARM64 call through native caller link has no callee ABI contract: %q", ErrProbeNeedsContext, ins.Raw)
			}
			if op != OpRET && c.localControl.autoFrame {
				return false, fmt.Errorf("%w: ARM64 branch through caller link has no Go frame epilogue proof: %q", ErrProbeNeedsContext, ins.Raw)
			}
			if err := c.requireCallerSPRestored(bi, ins); err != nil {
				return false, err
			}
			fmt.Fprintf(c.b, "  br label %%%s\n", arm64LLVMBlockName(targets[0]))
			c.recordARM64FlagFlowEdges(targets[0])
			return true, nil
		}
		if op == OpRET && c.localControl.autoFrame {
			for _, target := range targets {
				if target != c.localControl.outer {
					return false, fmt.Errorf("%w: ARM64 framed RET to a local code address requires the caller-frame epilogue, not a local helper return: %q", ErrProbeNeedsContext, ins.Raw)
				}
			}
		}
		pointer := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n  indirectbr ptr %%%s, [", pointer, addr, pointer)
		for index, target := range targets {
			if index != 0 {
				c.b.WriteString(", ")
			}
			fmt.Fprintf(c.b, "label %%%s", arm64LLVMBlockName(target))
		}
		c.b.WriteString("]\n")
		c.recordARM64FlagFlowEdges(targets...)
		return true, nil
	}
	if call {
		if addr == "0" {
			// Physical BLR XZR always faults; it cannot return to observe an
			// ABI result. Keep the real zero branch, not a guessed void call.
			fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(i64 0)\n  unreachable\n", "blr $0", "r,~{memory}")
			return true, nil
		}
		return false, fmt.Errorf("%w: ARM64 native register call needs a callee ABI and virtual register/result contract: %q", ErrProbeNeedsContext, ins.Raw)
	}
	if addr == "0" {
		// As with BLR XZR, a physical zero branch cannot return. In
		// particular it must not fabricate a successful LLVM return.
		fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(i64 0)\n  unreachable\n", "br $0", "r,~{memory}")
		return true, nil
	}
	return false, fmt.Errorf("%w: ARM64 native register branch needs a tail ABI, native frame/link and virtual register/result contract: %q", ErrProbeNeedsContext, ins.Raw)
}
