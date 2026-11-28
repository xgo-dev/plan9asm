package arm

import (
	"fmt"
	"github.com/xgo-dev/plan9asm/internal/asm"
	"strings"
)

type armFlagMask uint8

const (
	armFlagN   armFlagMask = 1 << 0
	armFlagZ   armFlagMask = 1 << 1
	armFlagC   armFlagMask = 1 << 2
	armFlagV   armFlagMask = 1 << 3
	armFlagAll armFlagMask = armFlagN | armFlagZ | armFlagC | armFlagV
)

func armCondRequiredFlags(cond string) (armFlagMask, bool) {
	switch strings.ToUpper(cond) {
	case "EQ", "NE":
		return armFlagZ, true
	case "CS", "HS", "CC", "LO":
		return armFlagC, true
	case "MI", "PL":
		return armFlagN, true
	case "VS", "VC":
		return armFlagV, true
	case "HI", "LS":
		return armFlagC | armFlagZ, true
	case "GE", "LT":
		return armFlagN | armFlagV, true
	case "GT", "LE":
		return armFlagZ | armFlagN | armFlagV, true
	case "AL", "":
		return 0, true
	default:
		return 0, false
	}
}

func (c *armCtx) requireFlags(req armFlagMask, context string) error {
	if c.flagsDef&req != req {
		return fmt.Errorf("%w: arm %s requires undefined flags (defined=%04b need=%04b)", asm.ErrProbeNeedsContext, context, c.flagsDef, req)
	}
	return nil
}

func (c *armCtx) storeFlag(slot string, v string) {
	fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", v, slot)
}

// captureHardwareFlags records the APSR condition flags immediately after an
// out-of-line call. ARM assembly is allowed to branch on flags produced by the
// callee (the Linux kuser CAS helper does this), while an LLVM call has no flag
// result in its type. Reading APSR keeps that machine-level contract explicit.
func (c *armCtx) captureHardwareFlags() {
	status := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call i32 asm sideeffect %q, %q()\n", status, "mrs $0, apsr", "=r,~{memory}")
	c.storeFlagsFromStatus("%" + status)
}

func (c *armCtx) storeFlagsFromStatus(status string) {
	for _, item := range []struct {
		shift int
		slot  string
	}{
		{31, c.flagsNSlot},
		{30, c.flagsZSlot},
		{29, c.flagsCSlot},
		{28, c.flagsVSlot},
	} {
		shifted := c.newTmp()
		flag := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr i32 %s, %d\n", shifted, status, item.shift)
		fmt.Fprintf(c.b, "  %%%s = trunc i32 %%%s to i1\n", flag, shifted)
		c.storeFlag(item.slot, "%"+flag)
	}
	c.flagsDef = armFlagAll
}

func (c *armCtx) storeFlagPred(pred, slot, v string) {
	if pred == "" {
		c.storeFlag(slot, v)
		return
	}
	oldV := c.newTmp()
	sel := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i1, ptr %s\n", oldV, slot)
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, i1 %s, i1 %%%s\n", sel, pred, v, oldV)
	c.storeFlag(slot, "%"+sel)
}

func (c *armCtx) evalFlagPred(cond string) (string, error) {
	if cond == "" || strings.EqualFold(cond, "AL") {
		return "", nil
	}
	return c.condValue(cond)
}

func (c *armCtx) storeFlagCond(cond, slot, v string) error {
	pred, err := c.evalFlagPred(cond)
	if err != nil {
		return err
	}
	c.storeFlagPred(pred, slot, v)
	return nil
}

func (c *armCtx) setFlagsSub(cond, dst, src, res string) error {
	return c.setFlagsSubWithCarry(cond, dst, src, res, "")
}

func (c *armCtx) setFlagsSubWithCarry(cond, dst, src, res, carryOverride string) error {
	pred, err := c.evalFlagPred(cond)
	if err != nil {
		return err
	}
	if pred == "" {
		c.flagsDef |= armFlagAll
	}
	z := c.newTmp()
	n := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq i32 %s, 0\n", z, res)
	fmt.Fprintf(c.b, "  %%%s = icmp slt i32 %s, 0\n", n, res)
	carryVal := carryOverride
	if carryVal == "" {
		carry := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp uge i32 %s, %s\n", carry, dst, src)
		carryVal = "%" + carry
	}
	x1 := c.newTmp()
	x2 := c.newTmp()
	x3 := c.newTmp()
	ov := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor i32 %s, %s\n", x1, dst, src)
	fmt.Fprintf(c.b, "  %%%s = xor i32 %s, %s\n", x2, dst, res)
	fmt.Fprintf(c.b, "  %%%s = and i32 %%%s, %%%s\n", x3, x1, x2)
	fmt.Fprintf(c.b, "  %%%s = icmp slt i32 %%%s, 0\n", ov, x3)
	c.storeFlagPred(pred, c.flagsZSlot, "%"+z)
	c.storeFlagPred(pred, c.flagsNSlot, "%"+n)
	c.storeFlagPred(pred, c.flagsCSlot, carryVal)
	c.storeFlagPred(pred, c.flagsVSlot, "%"+ov)
	return nil
}

func (c *armCtx) setFlagsAdd(cond, dst, src, res string) error {
	return c.setFlagsAddWithCarry(cond, dst, src, res, "")
}

func (c *armCtx) setFlagsAddWithCarry(cond, dst, src, res, carryOverride string) error {
	pred, err := c.evalFlagPred(cond)
	if err != nil {
		return err
	}
	if pred == "" {
		c.flagsDef |= armFlagAll
	}
	z := c.newTmp()
	n := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq i32 %s, 0\n", z, res)
	fmt.Fprintf(c.b, "  %%%s = icmp slt i32 %s, 0\n", n, res)
	carryVal := carryOverride
	if carryVal == "" {
		carry := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp ult i32 %s, %s\n", carry, res, dst)
		carryVal = "%" + carry
	}
	x1 := c.newTmp()
	nx1 := c.newTmp()
	x2 := c.newTmp()
	x3 := c.newTmp()
	ov := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor i32 %s, %s\n", x1, dst, src)
	fmt.Fprintf(c.b, "  %%%s = xor i32 %%%s, -1\n", nx1, x1)
	fmt.Fprintf(c.b, "  %%%s = xor i32 %s, %s\n", x2, dst, res)
	fmt.Fprintf(c.b, "  %%%s = and i32 %%%s, %%%s\n", x3, nx1, x2)
	fmt.Fprintf(c.b, "  %%%s = icmp slt i32 %%%s, 0\n", ov, x3)
	c.storeFlagPred(pred, c.flagsZSlot, "%"+z)
	c.storeFlagPred(pred, c.flagsNSlot, "%"+n)
	c.storeFlagPred(pred, c.flagsCSlot, carryVal)
	c.storeFlagPred(pred, c.flagsVSlot, "%"+ov)
	return nil
}

func (c *armCtx) setFlagsNZCV(cond, n, z, carry, v string) error {
	pred, err := c.evalFlagPred(cond)
	if err != nil {
		return err
	}
	if pred == "" {
		c.flagsDef |= armFlagAll
	}
	c.storeFlagPred(pred, c.flagsNSlot, n)
	c.storeFlagPred(pred, c.flagsZSlot, z)
	c.storeFlagPred(pred, c.flagsCSlot, carry)
	c.storeFlagPred(pred, c.flagsVSlot, v)
	return nil
}

func (c *armCtx) setFlagsLogic(cond, res string) error {
	return c.setFlagsLogicCarry(cond, res, "", false)
}

func (c *armCtx) setFlagsLogicCarry(cond, res, carryOut string, carryDefined bool) error {
	pred, err := c.evalFlagPred(cond)
	if err != nil {
		return err
	}
	if pred == "" {
		c.flagsDef |= armFlagN | armFlagZ
		if carryDefined {
			c.flagsDef |= armFlagC
		}
	}
	z := c.newTmp()
	n := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq i32 %s, 0\n", z, res)
	fmt.Fprintf(c.b, "  %%%s = icmp slt i32 %s, 0\n", n, res)
	c.storeFlagPred(pred, c.flagsZSlot, "%"+z)
	c.storeFlagPred(pred, c.flagsNSlot, "%"+n)
	if carryOut != "" {
		c.storeFlagPred(pred, c.flagsCSlot, carryOut)
	}
	return nil
}

func (c *armCtx) condValue(cond string) (string, error) {
	req, ok := armCondRequiredFlags(cond)
	if !ok {
		return "", fmt.Errorf("arm: unsupported condition %q", cond)
	}
	if err := c.requireFlags(req, "condition "+cond); err != nil {
		return "", err
	}
	ldN := c.newTmp()
	ldZ := c.newTmp()
	ldC := c.newTmp()
	ldV := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i1, ptr %s\n", ldN, c.flagsNSlot)
	fmt.Fprintf(c.b, "  %%%s = load i1, ptr %s\n", ldZ, c.flagsZSlot)
	fmt.Fprintf(c.b, "  %%%s = load i1, ptr %s\n", ldC, c.flagsCSlot)
	fmt.Fprintf(c.b, "  %%%s = load i1, ptr %s\n", ldV, c.flagsVSlot)
	n := "%" + ldN
	z := "%" + ldZ
	carry := "%" + ldC
	v := "%" + ldV
	not := func(x string) string {
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i1 %s, true\n", t, x)
		return "%" + t
	}
	and := func(a, b string) string {
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i1 %s, %s\n", t, a, b)
		return "%" + t
	}
	or := func(a, b string) string {
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i1 %s, %s\n", t, a, b)
		return "%" + t
	}
	xor := func(a, b string) string {
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i1 %s, %s\n", t, a, b)
		return "%" + t
	}
	eq := func(a, b string) string {
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq i1 %s, %s\n", t, a, b)
		return "%" + t
	}
	switch strings.ToUpper(cond) {
	case "EQ":
		return z, nil
	case "NE":
		return not(z), nil
	case "CS", "HS":
		return carry, nil
	case "CC", "LO":
		return not(carry), nil
	case "HI":
		return and(carry, not(z)), nil
	case "LS":
		return or(not(carry), z), nil
	case "LT":
		return xor(n, v), nil
	case "GE":
		return eq(n, v), nil
	case "GT":
		return and(not(z), eq(n, v)), nil
	case "LE":
		return or(z, xor(n, v)), nil
	case "MI":
		return n, nil
	case "PL":
		return not(n), nil
	case "VS":
		return v, nil
	case "VC":
		return not(v), nil
	case "AL":
		return "true", nil
	default:
		return "", fmt.Errorf("arm: unsupported condition %q", cond)
	}
}

func armRegShiftDefinesCarry(arg asm.Operand) bool {
	return arg.Kind == asm.OpRegShift && arg.ShiftReg == "" && arg.ShiftAmount != 0
}

func armImmShiftEffAmount(op string, raw int64) int64 {
	imm5 := raw & 31
	switch {
	case raw == 0:
		return 0
	case imm5 == 0:
		if op == "SLL" {
			return 0
		}
		return 32
	default:
		return imm5
	}
}

func (c *armCtx) armInstrMustDefineFlags(baseOp, cond string, setFlags bool, ins asm.Instr) armFlagMask {
	if cond != "" && !strings.EqualFold(cond, "AL") {
		return 0
	}
	switch baseOp {
	case "CMP", "CMN", "CMPF", "CMPD":
		return armFlagAll
	case "ADD", "SUB", "RSB", "ADC", "SBC", "RSC":
		if setFlags {
			return armFlagAll
		}
	case "TST", "TEQ":
		m := armFlagN | armFlagZ
		if len(ins.Args) >= 1 {
			switch ins.Args[0].Kind {
			case asm.OpRegShift:
				if armRegShiftDefinesCarry(ins.Args[0]) {
					m |= armFlagC
				}
			case asm.OpImm:
				if ins.Args[0].ImmRaw == "" {
					if _, ok := armImmLogicalCarry(baseOp, ins.Args[0].Imm); ok {
						m |= armFlagC
					}
				}
			}
		}
		return m
	case "AND", "ORR", "EOR", "BIC":
		if !setFlags {
			return 0
		}
		m := armFlagN | armFlagZ
		if len(ins.Args) >= 1 {
			switch ins.Args[0].Kind {
			case asm.OpRegShift:
				if armRegShiftDefinesCarry(ins.Args[0]) {
					m |= armFlagC
				}
			case asm.OpImm:
				if ins.Args[0].ImmRaw == "" {
					if _, ok := armImmLogicalCarry(baseOp, ins.Args[0].Imm); ok {
						m |= armFlagC
					}
				}
			}
		}
		return m
	case "MVN":
		if !setFlags {
			return 0
		}
		m := armFlagN | armFlagZ
		if len(ins.Args) == 2 && armRegShiftDefinesCarry(ins.Args[0]) {
			m |= armFlagC
		} else if len(ins.Args) == 3 && armRegShiftDefinesCarry(ins.Args[1]) {
			m |= armFlagC
		}
		return m
	case "MOVW":
		if len(ins.Args) == 2 && ins.Args[1].Kind == asm.OpIdent && strings.EqualFold(ins.Args[1].Ident, "CPSR") {
			return armFlagAll
		}
		if setFlags && len(ins.Args) == 2 && ins.Args[1].Kind == asm.OpReg {
			m := armFlagN | armFlagZ
			if armRegShiftDefinesCarry(ins.Args[0]) {
				m |= armFlagC
			}
			return m
		}
	case "SLL", "SRL", "SRA":
		if !setFlags {
			return 0
		}
		m := armFlagN | armFlagZ
		if len(ins.Args) >= 1 && ins.Args[0].Kind == asm.OpImm && ins.Args[0].ImmRaw == "" {
			if armImmShiftEffAmount(baseOp, ins.Args[0].Imm) != 0 {
				m |= armFlagC
			}
		}
		return m
	case "BL", "CALL":
		if len(ins.Args) >= 1 {
			tgt := ins.Args[len(ins.Args)-1]
			if tgt.Kind == asm.OpSym {
				s := strings.TrimSpace(tgt.Sym)
				if strings.HasSuffix(s, "(SB)") {
					callee := c.resolve(strings.TrimSuffix(s, "(SB)"))
					if callee == "runtime.entersyscall" || callee == "runtime.exitsyscall" {
						return 0
					}
				}
			}
			return armFlagAll
		}
	}
	return 0
}

// computeBlockFlagsDefIn computes the per-block must-defined NZCV flag mask at
// entry to each basic block via a forward CFG worklist (intersection across all
// reachable predecessors, starting from 0 at function entry).
func (c *armCtx) computeBlockFlagsDefIn() []armFlagMask {
	n := len(c.blocks)
	in := make([]armFlagMask, n)
	if n == 0 {
		return in
	}
	blockIdx := make(map[string]int, n)
	for i, blk := range c.blocks {
		blockIdx[blk.name] = i
	}
	reachable := make([]bool, n)
	reachable[0] = true
	queue := []int{0}
	inQueue := make([]bool, n)
	inQueue[0] = true

	enqueue := func(s int, out armFlagMask) {
		if s < 0 || s >= n {
			return
		}
		if !reachable[s] {
			reachable[s] = true
			in[s] = out
			if !inQueue[s] {
				queue = append(queue, s)
				inQueue[s] = true
			}
			return
		}
		merged := in[s] & out
		if merged != in[s] {
			in[s] = merged
			if !inQueue[s] {
				queue = append(queue, s)
				inQueue[s] = true
			}
		}
	}

	for len(queue) > 0 {
		bi := queue[0]
		queue = queue[1:]
		inQueue[bi] = false
		cur := in[bi]
		terminated := false
		for _, ins := range c.blocks[bi].instrs {
			rawOp := strings.ToUpper(string(ins.Op))
			baseOp, cond, _, setFlags := armDecodeOp(rawOp)
			cur |= c.armInstrMustDefineFlags(baseOp, cond, setFlags, ins)
			op := baseOp
			if op == "JMP" {
				op = "B"
			}
			switch op {
			case string(asm.OpRET), "UNDEF", "RFE":
				terminated = true
			case "BX", "BXRET":
				if cond == "" {
					terminated = true
				}
			case "B":
				if len(ins.Args) == 1 {
					if cond != "" {
						if tgt, ok := c.resolveBranchTarget(bi, ins.Args[0]); ok {
							if ti, ok := blockIdx[tgt]; ok {
								enqueue(ti, cur)
							}
						}
						if bi+1 < n {
							enqueue(bi+1, cur)
						}
						terminated = true
					} else {
						if !(ins.Args[0].Kind == asm.OpSym && strings.HasSuffix(ins.Args[0].Sym, "(SB)")) &&
							!(ins.Args[0].Kind == asm.OpMem && ins.Args[0].Mem.Base != asm.PC) {
							if tgt, ok := c.resolveBranchTarget(bi, ins.Args[0]); ok {
								if ti, ok := blockIdx[tgt]; ok {
									enqueue(ti, cur)
								}
							}
						}
						terminated = true
					}
				}
			case "BEQ", "BNE", "BLT", "BGE", "BGT", "BLE", "BHS", "BHI", "BLS", "BLO", "BCC", "BCS", "BMI", "BPL", "BVS", "BVC":
				if len(ins.Args) == 1 {
					if tgt, ok := c.resolveBranchTarget(bi, ins.Args[0]); ok {
						if ti, ok := blockIdx[tgt]; ok {
							enqueue(ti, cur)
						}
					}
					if bi+1 < n {
						enqueue(bi+1, cur)
					}
					terminated = true
				}
			}
			if terminated {
				break
			}
		}
		if !terminated && bi+1 < n {
			enqueue(bi+1, cur)
		}
	}
	return in
}
