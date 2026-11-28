package arm

import (
	"fmt"
	"github.com/xgo-dev/plan9asm/internal/asm"
	"github.com/xgo-dev/plan9asm/internal/exclusive"
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
	c.flagsTouched |= armFlagAll
}

// readCPSR lowers MOVW CPSR, Rd. When all four NZCV flags are defined in the
// translator's LLVM flag slots, it reads the hardware CPSR for bits [27:0] and
// overlays bits [31:28] from the live tracked NZCV slots so preceding CMP/TST/
// ALU.S updates are observed accurately. Before any source flag mutation, use the entry
// snapshot even if lowering an earlier instruction changed the hardware flags.
// Otherwise (partial or call-clobbered flags where LLVM codegen may have
// clobbered hardware NZCV), it returns ErrProbeNeedsContext.
func (c *armCtx) readCPSR() (string, error) {
	if c.flagsDef == armFlagAll {
		raw := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i32 asm sideeffect %q, %q()\n", raw, "mrs $0, cpsr", "=r,~{memory}")
		masked := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i32 %%%s, 268435455\n", masked, raw)
		cur := "%" + masked
		for _, item := range []struct {
			shift int
			slot  string
		}{
			{31, c.flagsNSlot},
			{30, c.flagsZSlot},
			{29, c.flagsCSlot},
			{28, c.flagsVSlot},
		} {
			ld := c.newTmp()
			ext := c.newTmp()
			sh := c.newTmp()
			or := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load i1, ptr %s\n", ld, item.slot)
			fmt.Fprintf(c.b, "  %%%s = zext i1 %%%s to i32\n", ext, ld)
			fmt.Fprintf(c.b, "  %%%s = shl i32 %%%s, %d\n", sh, ext, item.shift)
			fmt.Fprintf(c.b, "  %%%s = or i32 %s, %%%s\n", or, cur, sh)
			cur = "%" + or
		}
		return cur, nil
	}
	if c.flagsTouched == 0 && c.needsEntryCPSR {
		return "%entry_cpsr", nil
	}
	return "", fmt.Errorf("%w: arm CPSR read requires all NZCV flags defined (defined=%04b)", asm.ErrProbeNeedsContext, c.flagsDef)
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
	c.flagsTouched |= armFlagAll
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
	c.flagsTouched |= armFlagAll
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
	c.flagsTouched |= armFlagAll
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
	c.flagsTouched |= armFlagN | armFlagZ
	if carryOut != "" {
		c.flagsTouched |= armFlagC
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

func (c *armCtx) setFlagsLogic64(cond, res64 string) error {
	pred, err := c.evalFlagPred(cond)
	if err != nil {
		return err
	}
	c.flagsTouched |= armFlagN | armFlagZ
	if pred == "" {
		c.flagsDef |= armFlagN | armFlagZ
	}
	z := c.newTmp()
	n := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq i64 %s, 0\n", z, res64)
	fmt.Fprintf(c.b, "  %%%s = icmp slt i64 %s, 0\n", n, res64)
	c.storeFlagPred(pred, c.flagsZSlot, "%"+z)
	c.storeFlagPred(pred, c.flagsNSlot, "%"+n)
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

func (c *armCtx) armInstrUpdateFlags(cur, touched armFlagMask, baseOp, cond string, setFlags bool, ins asm.Instr) (armFlagMask, armFlagMask) {
	if ins.Op == exclusive.Opcode && c.exclusive[ins.Args[0].Imm].Flags {
		return armFlagAll, touched | armFlagAll
	}
	uncond := cond == "" || strings.EqualFold(cond, "AL")
	switch baseOp {
	case "BL", "CALL":
		if len(ins.Args) >= 1 {
			tgt := ins.Args[len(ins.Args)-1]
			if tgt.Kind == asm.OpSym {
				s := strings.TrimSpace(tgt.Sym)
				if strings.HasSuffix(s, "(SB)") {
					callee := c.resolve(strings.TrimSuffix(s, "(SB)"))
					if callee == "runtime.entersyscall" || callee == "runtime.exitsyscall" {
						return cur, touched
					}
					if c.kuserCAS[callee] {
						touched |= armFlagAll
						if uncond {
							return armFlagC, touched
						}
						return cur & armFlagC, touched
					}
				}
			}
		}
		// General calls (both direct LLVM calls and indirect blx) clobber
		// hardware CPSR and do not return translated LLVM flag slots.
		return 0, touched | armFlagAll
	case "CMP", "CMN", "CMPF", "CMPD":
		touched |= armFlagAll
		if uncond {
			cur |= armFlagAll
		}
	case "ADD", "SUB", "RSB", "ADC", "SBC", "RSC":
		if setFlags {
			touched |= armFlagAll
			if uncond {
				cur |= armFlagAll
			}
		}
	case "MUL", "MULU", "MULA", "MULL", "MULLU", "MULAL", "MULALU":
		if setFlags {
			touched |= armFlagN | armFlagZ
			if uncond {
				cur |= armFlagN | armFlagZ
			}
		}
	case "DIV", "DIVU", "MOD", "MODU":
		// Software division/zero-guard codegen on ARMv7 may clobber hardware CPSR.
		touched |= armFlagAll
	case "TST", "TEQ":
		m := armFlagN | armFlagZ
		t := armFlagN | armFlagZ
		if len(ins.Args) >= 1 {
			switch ins.Args[0].Kind {
			case asm.OpRegShift:
				t |= armFlagC
				if armRegShiftDefinesCarry(ins.Args[0]) {
					m |= armFlagC
				}
			case asm.OpImm:
				if ins.Args[0].ImmRaw == "" {
					if _, ok := armImmLogicalCarry(baseOp, ins.Args[0].Imm); ok {
						m |= armFlagC
						t |= armFlagC
					}
				}
			}
		}
		touched |= t
		if uncond {
			cur |= m
		}
	case "AND", "ORR", "EOR", "BIC":
		if !setFlags {
			return cur, touched
		}
		m := armFlagN | armFlagZ
		t := armFlagN | armFlagZ
		if len(ins.Args) >= 1 {
			switch ins.Args[0].Kind {
			case asm.OpRegShift:
				t |= armFlagC
				if armRegShiftDefinesCarry(ins.Args[0]) {
					m |= armFlagC
				}
			case asm.OpImm:
				if ins.Args[0].ImmRaw == "" {
					if _, ok := armImmLogicalCarry(baseOp, ins.Args[0].Imm); ok {
						m |= armFlagC
						t |= armFlagC
					}
				}
			}
		}
		touched |= t
		if uncond {
			cur |= m
		}
	case "MVN":
		if !setFlags {
			return cur, touched
		}
		m := armFlagN | armFlagZ
		t := armFlagN | armFlagZ
		if len(ins.Args) == 2 && ins.Args[0].Kind == asm.OpRegShift {
			t |= armFlagC
			if armRegShiftDefinesCarry(ins.Args[0]) {
				m |= armFlagC
			}
		} else if len(ins.Args) == 3 && ins.Args[1].Kind == asm.OpRegShift {
			t |= armFlagC
			if armRegShiftDefinesCarry(ins.Args[1]) {
				m |= armFlagC
			}
		}
		touched |= t
		if uncond {
			cur |= m
		}
	case "MOVW":
		if len(ins.Args) == 2 && ins.Args[1].Kind == asm.OpIdent && strings.EqualFold(ins.Args[1].Ident, "CPSR") {
			touched |= armFlagAll
			if uncond {
				cur |= armFlagAll
			}
			return cur, touched
		}
		if setFlags && len(ins.Args) == 2 && ins.Args[1].Kind == asm.OpReg {
			m := armFlagN | armFlagZ
			t := armFlagN | armFlagZ
			if ins.Args[0].Kind == asm.OpRegShift {
				t |= armFlagC
				if armRegShiftDefinesCarry(ins.Args[0]) {
					m |= armFlagC
				}
			}
			touched |= t
			if uncond {
				cur |= m
			}
		}
	case "SLL", "SRL", "SRA":
		if !setFlags {
			return cur, touched
		}
		m := armFlagN | armFlagZ
		touched |= armFlagN | armFlagZ | armFlagC
		if len(ins.Args) >= 1 && ins.Args[0].Kind == asm.OpImm && ins.Args[0].ImmRaw == "" {
			if armImmShiftEffAmount(baseOp, ins.Args[0].Imm) != 0 {
				m |= armFlagC
			}
		}
		if uncond {
			cur |= m
		}
	}
	return cur, touched
}

// computeBlockFlagsDefIn computes, per basic block:
//   - in: must-defined NZCV flag mask (intersection across reachable predecessors, 0 at entry),
//   - touched: may-touched NZCV flag mask (union across reachable predecessors, 0 at entry),
//   - reachable: whether the block is reachable from entry.
func (c *armCtx) computeBlockFlagsDefIn() ([]armFlagMask, []armFlagMask, []bool) {
	n := len(c.blocks)
	in := make([]armFlagMask, n)
	touched := make([]armFlagMask, n)
	reachable := make([]bool, n)
	if n == 0 {
		return in, touched, reachable
	}
	blockIdx := make(map[string]int, n)
	for i, blk := range c.blocks {
		blockIdx[blk.name] = i
	}
	reachable[0] = true
	queue := []int{0}
	inQueue := make([]bool, n)
	inQueue[0] = true

	enqueue := func(s int, outDef, outTouched armFlagMask) {
		if s < 0 || s >= n {
			return
		}
		if !reachable[s] {
			reachable[s] = true
			in[s] = outDef
			touched[s] = outTouched
			if !inQueue[s] {
				queue = append(queue, s)
				inQueue[s] = true
			}
			return
		}
		mergedDef := in[s] & outDef
		mergedTouched := touched[s] | outTouched
		if mergedDef != in[s] || mergedTouched != touched[s] {
			in[s] = mergedDef
			touched[s] = mergedTouched
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
		curTouched := touched[bi]
		terminated := false
		for _, ins := range c.blocks[bi].instrs {
			rawOp := strings.ToUpper(string(ins.Op))
			baseOp, cond, _, setFlags := armDecodeOp(rawOp)
			if curTouched == 0 && baseOp == "MOVW" && len(ins.Args) == 2 && ins.Args[0].Kind == asm.OpIdent && strings.EqualFold(ins.Args[0].Ident, "CPSR") {
				c.needsEntryCPSR = true
			}
			cur, curTouched = c.armInstrUpdateFlags(cur, curTouched, baseOp, cond, setFlags, ins)
			op := baseOp
			if op == "JMP" {
				op = "B"
			}
			switch op {
			case string(asm.OpRET):
				terminated = cond == "" || cond == "AL"
			case "UNDEF", "RFE":
				terminated = true
			case "BX", "BXRET":
				if cond == "" {
					terminated = true
				}
			case "B":
				if len(ins.Args) == 1 {
					if cond != "" && cond != "AL" {
						if tgt, ok := c.resolveBranchTarget(bi, ins.Args[0]); ok {
							if ti, ok := blockIdx[tgt]; ok {
								enqueue(ti, cur, curTouched)
							}
						}
						if bi+1 < n {
							enqueue(bi+1, cur, curTouched)
						}
						terminated = true
					} else {
						if !(ins.Args[0].Kind == asm.OpSym && strings.HasSuffix(ins.Args[0].Sym, "(SB)")) &&
							!(ins.Args[0].Kind == asm.OpMem && ins.Args[0].Mem.Base != asm.PC) {
							if tgt, ok := c.resolveBranchTarget(bi, ins.Args[0]); ok {
								if ti, ok := blockIdx[tgt]; ok {
									enqueue(ti, cur, curTouched)
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
							enqueue(ti, cur, curTouched)
						}
					}
					if bi+1 < n {
						enqueue(bi+1, cur, curTouched)
					}
					terminated = true
				}
			}
			if terminated {
				break
			}
		}
		if !terminated && bi+1 < n {
			enqueue(bi+1, cur, curTouched)
		}
	}
	return in, touched, reachable
}
