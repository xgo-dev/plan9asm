package arm64

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

// arm64ParseZReg parses an SVE scalable vector register such as Z7, Z7.D,
// Z5.B[3], Z25[2], Z4.S.UXTW, or Z6.S.SXTW<<1, returning register index 0..31,
// lane width in bits (8/16/32/64/128, or 0 if unspecified), and optional lane
// index (-1 if none).
func arm64ParseZReg(s string) (idx int, laneBits int, elemIdx int, ok bool) {
	s = strings.ToUpper(strings.TrimSpace(s))
	if len(s) < 2 || s[0] != 'Z' || s[1] < '0' || s[1] > '9' {
		return 0, 0, -1, false
	}
	elemIdx = -1
	if sh := strings.Index(s, "<<"); sh >= 0 {
		s = s[:sh]
	}
	if br := strings.IndexByte(s, '['); br >= 0 {
		if end := strings.IndexByte(s[br:], ']'); end > 1 {
			if n, err := strconv.Atoi(s[br+1 : br+end]); err == nil {
				elemIdx = n
			}
		}
		s = s[:br]
	}
	parts := strings.Split(s, ".")
	n, err := strconv.Atoi(parts[0][1:])
	if err != nil || n < 0 || n > 31 {
		return 0, 0, -1, false
	}
	if len(parts) >= 2 {
		laneBits = sveLaneBitsFromSuffix(parts[1])
	}
	return n, laneBits, elemIdx, true
}

// arm64ParsePReg parses an SVE predicate or predicate-as-counter register such
// as P4, P4.B, P4.M, P1.Z, PN10.Z, PN12.H, or PN11[1].
func arm64ParsePReg(s string) (idx int, laneBits int, mode byte, ok bool) {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "/", ".")
	if br := strings.IndexByte(s, '['); br >= 0 {
		s = s[:br]
	}
	rest := ""
	switch {
	case strings.HasPrefix(s, "PN") && len(s) >= 3 && s[2] >= '0' && s[2] <= '9':
		rest = s[2:]
	case strings.HasPrefix(s, "P") && len(s) >= 2 && s[1] >= '0' && s[1] <= '9':
		rest = s[1:]
	default:
		return 0, 0, 0, false
	}
	parts := strings.Split(rest, ".")
	n, err := strconv.Atoi(parts[0])
	if err != nil || n < 0 || n > 15 {
		return 0, 0, 0, false
	}
	for _, p := range parts[1:] {
		switch p {
		case "M":
			mode = 'M'
		case "Z":
			mode = 'Z'
		default:
			if b := sveLaneBitsFromSuffix(p); b != 0 {
				laneBits = b
			}
		}
	}
	return n, laneBits, mode, true
}

func sveLaneBitsFromSuffix(s string) int {
	switch strings.ToUpper(s) {
	case "B", "B8", "B16":
		return 8
	case "H", "H4", "H8":
		return 16
	case "S", "S2", "S4":
		return 32
	case "D", "D1", "D2":
		return 64
	case "Q", "Q1":
		return 128
	default:
		return 0
	}
}

func arm64OpText(op asm.Operand) string {
	switch op.Kind {
	case asm.OpReg:
		return string(op.Reg)
	case asm.OpSym:
		return op.Sym
	case asm.OpIdent:
		return op.Ident
	default:
		return ""
	}
}

func (c *arm64Ctx) loadZIdx(idx int) (string, error) {
	slot, ok := c.vRegSlot[idx]
	if !ok {
		return "zeroinitializer", nil
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load <16 x i8>, ptr %s\n", t, slot)
	return "%" + t, nil
}

func (c *arm64Ctx) storeZIdx(idx int, v string) error {
	slot, ok := c.vRegSlot[idx]
	if !ok {
		return nil
	}
	fmt.Fprintf(c.b, "  store <16 x i8> %s, ptr %s\n", v, slot)
	return nil
}

func (c *arm64Ctx) loadPIdx(idx int) string {
	slot, ok := c.pRegSlot[idx]
	if !ok {
		return "0"
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i16, ptr %s\n", t, slot)
	return "%" + t
}

func (c *arm64Ctx) storePIdx(idx int, v16 string) {
	slot, ok := c.pRegSlot[idx]
	if !ok {
		return
	}
	fmt.Fprintf(c.b, "  store i16 %s, ptr %s\n", v16, slot)
}

func (c *arm64Ctx) sveSetPredFlags(v16 string) {
	// SVE predicate flag semantics (VL=128):
	// N = first element active (bit 0), Z = no active element (v == 0),
	// C = last element NOT active (bit 15 == 0), V = 0.
	b0, n, z, sh, b15, cf := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and i16 %s, 1\n", b0, v16)
	fmt.Fprintf(c.b, "  %%%s = icmp ne i16 %%%s, 0\n", n, b0)
	fmt.Fprintf(c.b, "  %%%s = icmp eq i16 %s, 0\n", z, v16)
	fmt.Fprintf(c.b, "  %%%s = lshr i16 %s, 15\n", sh, v16)
	fmt.Fprintf(c.b, "  %%%s = and i16 %%%s, 1\n", b15, sh)
	fmt.Fprintf(c.b, "  %%%s = icmp eq i16 %%%s, 0\n", cf, b15)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", n, c.flagsNSlot)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", z, c.flagsZSlot)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCSlot)
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsVSlot)
	c.flagsWritten = true
}

func (c *arm64Ctx) svePredToI1Vec(pIdx, lanes int) string {
	pv := c.loadPIdx(pIdx)
	bc := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast i16 %s to <16 x i1>\n", bc, pv)
	if lanes == 16 {
		return "%" + bc
	}
	stride := 16 / lanes
	me := make([]string, lanes)
	for i := 0; i < lanes; i++ {
		me[i] = fmt.Sprintf("i32 %d", i*stride)
	}
	sh := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector <16 x i1> %%%s, <16 x i1> poison, <%d x i32> <%s>\n",
		sh, bc, lanes, strings.Join(me, ", "))
	return "%" + sh
}

func (c *arm64Ctx) sveI1VecToPred(vec string, lanes int) string {
	src := vec
	if lanes < 16 {
		stride := 16 / lanes
		me := make([]string, 16)
		for i := 0; i < 16; i++ {
			if i%stride == 0 {
				me[i] = fmt.Sprintf("i32 %d", i/stride)
			} else {
				me[i] = fmt.Sprintf("i32 %d", lanes)
			}
		}
		sh := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i1> %s, <%d x i1> zeroinitializer, <16 x i32> <%s>\n",
			sh, lanes, vec, lanes, strings.Join(me, ", "))
		src = "%" + sh
	}
	bc := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i1> %s to i16\n", bc, src)
	return "%" + bc
}

func (c *arm64Ctx) lowerSVEOrSys(op asm.Op, ins asm.Instr) (ok bool, terminated bool, err error) {
	spec, found := arm64SVETable.Lookup(op)
	if !found {
		return false, false, nil
	}
	switch spec.LLVMOp {
	case "sys":
		return true, false, c.lowerARM64SysExt(op, ins)
	case "sve_scalar":
		return true, false, c.lowerARM64SVEScalar(op, ins)
	case "sve_pred":
		return true, false, c.lowerARM64SVEPred(op, ins)
	case "sve_mem":
		return true, false, c.lowerARM64SVEMem(op, ins)
	case "sve_cmp":
		return true, false, c.lowerARM64SVECmp(op, ins)
	case "sve_fp":
		return true, false, c.lowerARM64SVEFP(op, ins)
	case "sve_alu":
		return true, false, c.lowerARM64SVEALU(op, ins)
	}
	return false, false, nil
}

// 1. Non-SVE privileged & system instructions (12 ops / 15 forms).
func (c *arm64Ctx) lowerARM64SysExt(op asm.Op, ins asm.Instr) error {
	switch op {
	case "ADR":
		if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
			return fmt.Errorf("arm64 ADR expects label/sym, dstReg: %q", ins.Raw)
		}
		if ins.Args[0].Kind == asm.OpSym && strings.HasSuffix(ins.Args[0].Sym, "(SB)") {
			p, err := c.ptrFromSB(ins.Args[0].Sym)
			if err != nil {
				return err
			}
			pi := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i64\n", pi, p)
			return c.storeReg(ins.Args[1].Reg, "%"+pi)
		}
		return c.storeReg(ins.Args[1].Reg, "0")
	case "SYSL":
		if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
			return fmt.Errorf("arm64 SYSL expects $imm, dstReg: %q", ins.Raw)
		}
		return c.storeReg(ins.Args[1].Reg, "0")
	case "DRPS", "ERET":
		if len(ins.Args) != 0 {
			return fmt.Errorf("arm64 %s takes no operands: %q", op, ins.Raw)
		}
		return nil
	case "DCPS1", "DCPS2", "DCPS3", "HLT", "HVC", "SMC":
		if len(ins.Args) > 1 {
			return fmt.Errorf("arm64 %s expects at most 1 immediate: %q", op, ins.Raw)
		}
		return nil
	case "SYS", "TLBI":
		if len(ins.Args) < 1 || len(ins.Args) > 2 {
			return fmt.Errorf("arm64 %s expects 1 or 2 operands: %q", op, ins.Raw)
		}
		return nil
	}
	return nil
}

// 2. SVE scalar VL/PL arithmetic & loop termination (7 ops).
func (c *arm64Ctx) lowerARM64SVEScalar(op asm.Op, ins asm.Instr) error {
	switch op {
	case "RDVL":
		if len(ins.Args) != 2 || ins.Args[0].Kind != asm.OpImm || ins.Args[1].Kind != asm.OpReg {
			return fmt.Errorf("arm64 RDVL expects $imm, Rd: %q", ins.Raw)
		}
		return c.storeReg(ins.Args[1].Reg, fmt.Sprintf("%d", ins.Args[0].Imm*16))
	case "ADDVL", "ADDPL":
		if len(ins.Args) != 3 || ins.Args[0].Kind != asm.OpImm || ins.Args[1].Kind != asm.OpReg || ins.Args[2].Kind != asm.OpReg {
			return fmt.Errorf("arm64 %s expects $imm, Rn, Rd: %q", op, ins.Raw)
		}
		rn, err := c.loadReg(ins.Args[1].Reg)
		if err != nil {
			return err
		}
		scale := int64(16)
		if op == "ADDPL" {
			scale = 2
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i64 %s, %d\n", t, rn, ins.Args[0].Imm*scale)
		return c.storeReg(ins.Args[2].Reg, "%"+t)
	default: // CTERMEQ, CTERMEQW, CTERMNE, CTERMNEW
		if len(ins.Args) != 2 || ins.Args[0].Kind != asm.OpReg || ins.Args[1].Kind != asm.OpReg {
			return fmt.Errorf("arm64 %s expects Rm, Rn: %q", op, ins.Raw)
		}
		rm, err := c.loadReg(ins.Args[0].Reg)
		if err != nil {
			return err
		}
		rn, err := c.loadReg(ins.Args[1].Reg)
		if err != nil {
			return err
		}
		ty := "i64"
		if strings.HasSuffix(string(op), "W") {
			ty = "i32"
			tm, tn := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", tm, rm)
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", tn, rn)
			rm, rn = "%"+tm, "%"+tn
		}
		pred := "eq"
		if strings.HasPrefix(string(op), "CTERMNE") {
			pred = "ne"
		}
		eq := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp %s %s %s, %s\n", eq, pred, ty, rn, rm)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", eq, c.flagsNSlot)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", eq, c.flagsZSlot)
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsCSlot)
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsVSlot)
		c.flagsWritten = true
		return nil
	}
}

func (c *arm64Ctx) sveEvalRegName(name string) (string, error) {
	name = strings.ToUpper(strings.TrimSpace(name))
	shift := int64(0)
	if idx := strings.Index(name, "<<"); idx >= 0 {
		if n, err := strconv.ParseInt(name[idx+2:], 10, 64); err == nil {
			shift = n
		}
		name = name[:idx]
	}
	if dot := strings.IndexByte(name, '.'); dot >= 0 {
		name = name[:dot]
	}
	v, err := c.loadReg(asm.Reg(name))
	if err != nil {
		return "0", nil
	}
	if shift > 0 {
		sh := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shl i64 %s, %d\n", sh, v, shift)
		return "%" + sh, nil
	}
	return v, nil
}

// sveEvalMemPtr evaluates a scalar or VL-scaled SVE memory operand into an
// LLVM `ptr`. Handles `(-VL*k)(Rn)`, `(VL*k)(RSP)`, `(R6<<1)(R14)`, `8(R14)`,
// etc., returning hasZ=true if the operand uses a Z vector base/index.
func (c *arm64Ctx) sveEvalMemPtr(op asm.Operand, vlBytes int64) (ptr string, hasZ bool, zIdx int, zLaneBits int, baseAddr string, err error) {
	switch op.Kind {
	case asm.OpSym:
		// Parse (-VL*6)(R3) or (VL*1)(RSP) or sym(SB)
		s := strings.TrimSpace(op.Sym)
		if strings.HasSuffix(s, "(SB)") {
			p, e := c.ptrFromSB(s)
			return p, false, 0, 0, "", e
		}
		off := int64(0)
		regName := ""
		if lp := strings.LastIndexByte(s, '('); lp >= 0 && strings.HasSuffix(s, ")") {
			regName = s[lp+1 : len(s)-1]
			prefix := strings.Trim(s[:lp], " ()")
			up := strings.ToUpper(prefix)
			if strings.Contains(up, "VL") {
				mult := int64(1)
				if strings.HasPrefix(up, "-") {
					mult = -1
					up = strings.TrimPrefix(up, "-")
				}
				if star := strings.IndexByte(up, '*'); star >= 0 {
					if k, e := strconv.ParseInt(strings.TrimSpace(up[star+1:]), 10, 64); e == nil {
						mult *= k
					}
				}
				off = mult * vlBytes
			} else if k, e := strconv.ParseInt(prefix, 10, 64); e == nil {
				off = k
			}
		}
		base, _ := c.sveEvalRegName(regName)
		addr := base
		if off != 0 {
			ad := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add i64 %s, %d\n", ad, base, off)
			addr = "%" + ad
		}
		p := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", p, addr)
		return "%" + p, false, 0, 0, addr, nil

	case asm.OpMem:
		mem := op.Mem
		// Check whether Base or Index is a Z vector register (gather/scatter!).
		if zi, zlb, _, ok := arm64ParseZReg(string(mem.Base)); ok {
			bVal := "0"
			if mem.Index != "" {
				bVal, _ = c.sveEvalRegName(string(mem.Index))
			}
			if mem.Off != 0 {
				ad := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = add i64 %s, %d\n", ad, bVal, mem.Off)
				bVal = "%" + ad
			}
			return "", true, zi, zlb, bVal, nil
		}
		if zi, zlb, _, ok := arm64ParseZReg(string(mem.Index)); ok {
			bVal := "0"
			if mem.Base != "" {
				bVal, _ = c.sveEvalRegName(string(mem.Base))
			}
			if mem.Off != 0 {
				ad := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = add i64 %s, %d\n", ad, bVal, mem.Off)
				bVal = "%" + ad
			}
			return "", true, zi, zlb, bVal, nil
		}
		// Pure scalar memory (handles (R6<<1)(R14), (VL*1)(RSP), 6(R14), etc.)
		baseStr := string(mem.Base)
		idxStr := string(mem.Index)
		addr := "0"
		if strings.Contains(strings.ToUpper(baseStr), "VL") {
			mult := int64(1)
			up := strings.ToUpper(strings.Trim(baseStr, " ()"))
			if strings.HasPrefix(up, "-") {
				mult = -1
				up = strings.TrimPrefix(up, "-")
			}
			if star := strings.IndexByte(up, '*'); star >= 0 {
				if k, e := strconv.ParseInt(strings.TrimSpace(up[star+1:]), 10, 64); e == nil {
					mult *= k
				}
			}
			baseVal := "0"
			if idxStr != "" {
				baseVal, _ = c.sveEvalRegName(idxStr)
			}
			ad := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add i64 %s, %d\n", ad, baseVal, mult*vlBytes+mem.Off)
			addr = "%" + ad
		} else {
			if baseStr != "" {
				addr, _ = c.sveEvalRegName(baseStr)
			}
			if idxStr != "" {
				iv, _ := c.sveEvalRegName(idxStr)
				ad := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = add i64 %s, %s\n", ad, addr, iv)
				addr = "%" + ad
			}
			if mem.Off != 0 {
				ad := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = add i64 %s, %d\n", ad, addr, mem.Off)
				addr = "%" + ad
			}
		}
		p := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", p, addr)
		return "%" + p, false, 0, 0, addr, nil

	default:
		return "", false, 0, 0, "", fmt.Errorf("arm64 SVE unsupported memory operand %s", op.String())
	}
}

// 3. SVE Predicate Engine (80 P* ops / 100 forms).
func (c *arm64Ctx) lowerARM64SVEPred(op asm.Op, ins asm.Instr) error {
	name := string(op)
	switch {
	case strings.HasPrefix(name, "PPRF"):
		return nil

	case name == "PLDR":
		if len(ins.Args) != 2 && len(ins.Args) != 3 {
			return fmt.Errorf("arm64 PLDR expects mem, Pt: %q", ins.Raw)
		}
		dstArg := ins.Args[len(ins.Args)-1]
		pi, _, _, ok := arm64ParsePReg(arm64OpText(dstArg))
		if !ok {
			return fmt.Errorf("arm64 PLDR expects P dst: %q", ins.Raw)
		}
		memArg := ins.Args[0]
		if len(ins.Args) == 3 && ins.Args[0].Kind == asm.OpReg && ins.Args[1].Kind == asm.OpImm {
			memArg = asm.Operand{Kind: asm.OpMem, Mem: asm.MemRef{Base: ins.Args[0].Reg, Off: ins.Args[1].Imm * 2}}
		}
		ptr, _, _, _, _, err := c.sveEvalMemPtr(memArg, 2)
		if err != nil {
			return err
		}
		ld := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load i16, ptr %s, align 1\n", ld, ptr)
		c.storePIdx(pi, "%"+ld)
		return nil

	case name == "PSTR":
		if len(ins.Args) != 2 && len(ins.Args) != 3 {
			return fmt.Errorf("arm64 PSTR expects Pt, mem: %q", ins.Raw)
		}
		pi, _, _, ok := arm64ParsePReg(arm64OpText(ins.Args[0]))
		if !ok {
			return fmt.Errorf("arm64 PSTR expects P src: %q", ins.Raw)
		}
		memArg := ins.Args[1]
		if len(ins.Args) == 3 && ins.Args[1].Kind == asm.OpReg && ins.Args[2].Kind == asm.OpImm {
			memArg = asm.Operand{Kind: asm.OpMem, Mem: asm.MemRef{Base: ins.Args[1].Reg, Off: ins.Args[2].Imm * 2}}
		}
		ptr, _, _, _, _, err := c.sveEvalMemPtr(memArg, 2)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store i16 %s, ptr %s, align 1\n", c.loadPIdx(pi), ptr)
		return nil

	case name == "PPFALSE":
		if len(ins.Args) != 1 {
			return fmt.Errorf("arm64 PPFALSE expects Pd: %q", ins.Raw)
		}
		if pi, _, _, ok := arm64ParsePReg(arm64OpText(ins.Args[0])); ok {
			c.storePIdx(pi, "0")
		}
		return nil

	case name == "PPTRUE":
		if len(ins.Args) < 1 {
			return fmt.Errorf("arm64 PPTRUE expects Pd: %q", ins.Raw)
		}
		if pi, _, _, ok := arm64ParsePReg(arm64OpText(ins.Args[len(ins.Args)-1])); ok {
			c.storePIdx(pi, "-1")
		}
		return nil

	case name == "PWRFFR":
		if len(ins.Args) != 1 {
			return fmt.Errorf("arm64 PWRFFR expects Pn: %q", ins.Raw)
		}
		if pi, _, _, ok := arm64ParsePReg(arm64OpText(ins.Args[0])); ok && c.ffrSlot != "" {
			fmt.Fprintf(c.b, "  store i16 %s, ptr %s\n", c.loadPIdx(pi), c.ffrSlot)
		}
		return nil

	case name == "PRDFFR" || name == "PRDFFRS":
		if len(ins.Args) < 1 {
			return fmt.Errorf("arm64 %s expects [Pg,] Pd: %q", name, ins.Raw)
		}
		val := "-1"
		if c.ffrSlot != "" {
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load i16, ptr %s\n", t, c.ffrSlot)
			val = "%" + t
		}
		if len(ins.Args) == 2 {
			if gi, _, _, ok := arm64ParsePReg(arm64OpText(ins.Args[0])); ok {
				a := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = and i16 %s, %s\n", a, val, c.loadPIdx(gi))
				val = "%" + a
			}
		}
		if di, _, _, ok := arm64ParsePReg(arm64OpText(ins.Args[len(ins.Args)-1])); ok {
			c.storePIdx(di, val)
		}
		if name == "PRDFFRS" {
			c.sveSetPredFlags(val)
		}
		return nil

	case name == "PPTEST":
		if len(ins.Args) != 2 {
			return fmt.Errorf("arm64 PPTEST expects Pn, Pg: %q", ins.Raw)
		}
		p1, _, _, _ := arm64ParsePReg(arm64OpText(ins.Args[0]))
		p2, _, _, _ := arm64ParsePReg(arm64OpText(ins.Args[1]))
		a := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i16 %s, %s\n", a, c.loadPIdx(p1), c.loadPIdx(p2))
		c.sveSetPredFlags("%" + a)
		return nil

	case strings.HasPrefix(name, "PWHILE"):
		if len(ins.Args) < 3 {
			return fmt.Errorf("arm64 %s expects Rm, Rn, Pd: %q", name, ins.Raw)
		}
		// Plan 9 order: PWHILE* Rm(limit), Rn(start), Pd.T | PWHILE* VLx4, Rm, Rn, PNd
		off := 0
		if ins.Args[0].Kind == asm.OpIdent {
			off = 1
		}
		limit, _ := c.loadReg(ins.Args[off].Reg)
		start, _ := c.loadReg(ins.Args[off+1].Reg)
		ty := "i64"
		if strings.HasSuffix(name, "W") && !strings.HasSuffix(name, "RW") {
			ty = "i32"
			t1, t2 := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", t1, limit)
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", t2, start)
			limit, start = "%"+t1, "%"+t2
		}
		condPart := strings.TrimPrefix(name, "PWHILE")
		pred := "slt"
		switch {
		case strings.HasPrefix(condPart, "LE"):
			pred = "sle"
		case strings.HasPrefix(condPart, "LO"):
			pred = "ult"
		case strings.HasPrefix(condPart, "LS"):
			pred = "ule"
		case strings.HasPrefix(condPart, "GE"):
			pred = "sge"
		case strings.HasPrefix(condPart, "GT"):
			pred = "sgt"
		case strings.HasPrefix(condPart, "HI"):
			pred = "ugt"
		case strings.HasPrefix(condPart, "HS"):
			pred = "uge"
		}
		dst := ins.Args[len(ins.Args)-1]
		laneBits := 8
		if dst.Kind == asm.OpRegList && len(dst.RegList) > 0 {
			if _, lb, _, ok := arm64ParsePReg(string(dst.RegList[0])); ok && lb != 0 {
				laneBits = lb
			}
		} else if _, lb, _, ok := arm64ParsePReg(arm64OpText(dst)); ok && lb != 0 {
			laneBits = lb
		}
		lanes := 128 / laneBits
		stride := laneBits / 8
		maskVal := "0"
		active := "true"
		for i := 0; i < lanes; i++ {
			cur := start
			if i > 0 {
				ad := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = add %s %s, %d\n", ad, ty, start, i)
				cur = "%" + ad
			}
			cmp, okLane, bit, orv := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp %s %s %s, %s\n", cmp, pred, ty, cur, limit)
			fmt.Fprintf(c.b, "  %%%s = and i1 %s, %%%s\n", okLane, active, cmp)
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i16 %d, i16 0\n", bit, okLane, 1<<uint(i*stride))
			fmt.Fprintf(c.b, "  %%%s = or i16 %s, %%%s\n", orv, maskVal, bit)
			active = "%" + okLane
			maskVal = "%" + orv
		}
		if dst.Kind == asm.OpRegList {
			for _, r := range dst.RegList {
				if pi, _, _, ok := arm64ParsePReg(string(r)); ok {
					c.storePIdx(pi, maskVal)
				}
			}
		} else if pi, _, _, ok := arm64ParsePReg(arm64OpText(dst)); ok {
			c.storePIdx(pi, maskVal)
		}
		c.sveSetPredFlags(maskVal)
		return nil

	case name == "PCNTP" || name == "PFIRSTP" || name == "PLASTP" ||
		name == "PINCP" || name == "PDECP" ||
		strings.HasPrefix(name, "PSQINCP") || strings.HasPrefix(name, "PSQDECP") ||
		strings.HasPrefix(name, "PUQINCP") || strings.HasPrefix(name, "PUQDECP"):
		if len(ins.Args) < 2 {
			return fmt.Errorf("arm64 %s expects >=2 operands: %q", name, ins.Raw)
		}
		dst := ins.Args[len(ins.Args)-1]
		// Collect active predicate bitmask from predicate operand(s) and mask to lane stride.
		pv := "0"
		laneBits := 8
		for _, a := range ins.Args[:len(ins.Args)-1] {
			if pi, lb, _, ok := arm64ParsePReg(arm64OpText(a)); ok {
				if lb > laneBits {
					laneBits = lb
				}
				cur := c.loadPIdx(pi)
				if pv == "0" {
					pv = cur
				} else {
					an := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = and i16 %s, %s\n", an, pv, cur)
					pv = "%" + an
				}
			}
		}
		if laneBits > 8 {
			lm := uint16(0)
			for b := 0; b < 16; b += laneBits / 8 {
				lm |= 1 << uint(b)
			}
			mk := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i16 %s, %d\n", mk, pv, int16(lm))
			pv = "%" + mk
		}
		cnt16, cnt64 := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i16 @llvm.ctpop.i16(i16 %s)\n", cnt16, pv)
		fmt.Fprintf(c.b, "  %%%s = zext i16 %%%s to i64\n", cnt64, cnt16)
		res := "%" + cnt64
		if strings.Contains(name, "INCP") || strings.Contains(name, "DECP") {
			oldV, _ := c.loadReg(dst.Reg)
			opCode := "add"
			if strings.Contains(name, "DECP") {
				opCode = "sub"
			}
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = %s i64 %s, %s\n", t, opCode, oldV, res)
			res = "%" + t
		}
		if dst.Kind == asm.OpReg {
			return c.storeReg(dst.Reg, res)
		}
		return nil

	default:
		// All predicate logical/break/permute/select/ext ops:
		// PAND[S], PBIC[S], PEOR[S], PNAND[S], PNOR[S], PORN[S], PORR[S],
		// PBRK*, PSEL, PREV, PPUNPKLO/HI, PTRN1/2, PUZP1/2, PZIP1/2, PPFIRST, PPNEXT, PPEXT
		if len(ins.Args) < 2 {
			return fmt.Errorf("arm64 %s expects >=2 operands: %q", name, ins.Raw)
		}
		setFlags := strings.HasSuffix(name, "S") && name != "PSEL"
		base := name
		if setFlags {
			base = strings.TrimSuffix(name, "S")
		}
		var srcs []string
		var gVal string
		hasG := false
		for i := 0; i < len(ins.Args)-1; i++ {
			if pi, _, mode, ok := arm64ParsePReg(arm64OpText(ins.Args[i])); ok {
				v := c.loadPIdx(pi)
				if mode != 0 && i == len(ins.Args)-2 {
					gVal = v
					hasG = true
				} else {
					srcs = append(srcs, v)
				}
			}
		}
		s0 := "0"
		if len(srcs) > 0 {
			s0 = srcs[0]
		}
		s1 := s0
		if len(srcs) > 1 {
			s1 = srcs[1]
		}
		res := s0
		switch base {
		case "PAND":
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i16 %s, %s\n", t, s0, s1)
			res = "%" + t
		case "PBIC":
			n, t := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor i16 %s, -1\n", n, s0)
			fmt.Fprintf(c.b, "  %%%s = and i16 %s, %%%s\n", t, s1, n)
			res = "%" + t
		case "PEOR":
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor i16 %s, %s\n", t, s0, s1)
			res = "%" + t
		case "PNAND":
			a, t := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i16 %s, %s\n", a, s0, s1)
			fmt.Fprintf(c.b, "  %%%s = xor i16 %%%s, -1\n", t, a)
			res = "%" + t
		case "PNOR":
			o, t := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = or i16 %s, %s\n", o, s0, s1)
			fmt.Fprintf(c.b, "  %%%s = xor i16 %%%s, -1\n", t, o)
			res = "%" + t
		case "PORN":
			n, t := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor i16 %s, -1\n", n, s0)
			fmt.Fprintf(c.b, "  %%%s = or i16 %s, %%%s\n", t, s1, n)
			res = "%" + t
		case "PORR":
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = or i16 %s, %s\n", t, s0, s1)
			res = "%" + t
		case "PREV":
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call i16 @llvm.bitreverse.i16(i16 %s)\n", t, s0)
			res = "%" + t
		}
		if hasG {
			a := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i16 %s, %s\n", a, res, gVal)
			res = "%" + a
		}
		dst := ins.Args[len(ins.Args)-1]
		if dst.Kind == asm.OpRegList {
			for _, r := range dst.RegList {
				if pi, _, _, ok := arm64ParsePReg(string(r)); ok {
					c.storePIdx(pi, res)
				}
			}
		} else if pi, _, _, ok := arm64ParsePReg(arm64OpText(dst)); ok {
			c.storePIdx(pi, res)
		}
		if setFlags {
			c.sveSetPredFlags(res)
		}
		return nil
	}
}

// 4. SVE Load/Store/Prefetch (89 ZLD*/ZST*/ZPRF* ops).
func (c *arm64Ctx) lowerARM64SVEMem(op asm.Op, ins asm.Instr) error {
	name := string(op)
	if strings.HasPrefix(name, "ZPRF") {
		return nil
	}
	isStore := strings.HasPrefix(name, "ZST")
	// Extract Z reg list/single, governing P reg, and memory operand.
	var zRegs []int
	laneBits := 8
	pIdx := -1
	var memOp asm.Operand
	hasMem := false
	var gprArgs []asm.Reg
	for _, a := range ins.Args {
		switch a.Kind {
		case asm.OpRegList:
			for _, r := range a.RegList {
				if zi, lb, _, ok := arm64ParseZReg(string(r)); ok {
					zRegs = append(zRegs, zi)
					if lb != 0 {
						laneBits = lb
					}
				}
			}
		case asm.OpMem:
			memOp = a
			hasMem = true
		case asm.OpSym:
			if zi, lb, _, ok := arm64ParseZReg(a.Sym); ok {
				zRegs = append(zRegs, zi)
				if lb != 0 {
					laneBits = lb
				}
			} else if pi, _, _, ok := arm64ParsePReg(a.Sym); ok {
				pIdx = pi
			} else if !hasMem {
				memOp = a
				hasMem = true
			}
		case asm.OpReg:
			if zi, lb, _, ok := arm64ParseZReg(string(a.Reg)); ok {
				zRegs = append(zRegs, zi)
				if lb != 0 {
					laneBits = lb
				}
			} else if pi, _, _, ok := arm64ParsePReg(string(a.Reg)); ok {
				pIdx = pi
			} else {
				gprArgs = append(gprArgs, a.Reg)
			}
		}
	}
	if !hasMem && len(gprArgs) > 0 {
		// Encoder-table separate base/index register form (e.g. ZLD1B R0, R1, P0.Z, Z0.B).
		mem := asm.MemRef{Base: gprArgs[0]}
		if len(gprArgs) > 1 {
			mem.Index = gprArgs[1]
		}
		memOp = asm.Operand{Kind: asm.OpMem, Mem: mem}
		hasMem = true
	}
	if !hasMem && len(zRegs) >= 2 {
		// Encoder-table vector-base + imm offset gather/scatter form (e.g. ZLD1B Z0.D, $1, P0.Z, Z1.D).
		off := int64(0)
		for _, a := range ins.Args {
			if a.Kind == asm.OpImm {
				off = a.Imm
			}
		}
		addrZ := zRegs[0]
		if isStore {
			addrZ = zRegs[len(zRegs)-1]
			zRegs = zRegs[:len(zRegs)-1]
		} else {
			zRegs = zRegs[1:]
		}
		memOp = asm.Operand{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.Reg(fmt.Sprintf("Z%d.D", addrZ)), Off: off}}
		hasMem = true
	}
	if !hasMem || len(zRegs) == 0 {
		return fmt.Errorf("arm64 %s missing mem or Z operand: %q", name, ins.Raw)
	}
	ptr, hasZMem, zMemIdx, zMemLB, baseAddr, err := c.sveEvalMemPtr(memOp, 16)
	if err != nil {
		return err
	}
	if laneBits == 128 {
		laneBits = 64
	}
	lanes := 16 / (laneBits / 8)
	vecTy := fmt.Sprintf("<%d x i%d>", lanes, laneBits)

	var mvec string
	if pIdx >= 0 {
		mvec = c.svePredToI1Vec(pIdx, lanes)
	} else {
		ones := make([]string, lanes)
		for i := range ones {
			ones[i] = "i1 true"
		}
		mvec = "<" + strings.Join(ones, ", ") + ">"
	}

	if hasZMem {
		// Gather / Scatter using Z vector index register!
		if zMemLB == 0 || zMemLB == 128 {
			zMemLB = laneBits
		}
		zMemRaw, _ := c.loadZIdx(zMemIdx)
		idxLanes := 16 / (zMemLB / 8)
		idxFullTy := fmt.Sprintf("<%d x i%d>", idxLanes, zMemLB)
		ib := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to %s\n", ib, zMemRaw, idxFullTy)
		iv := "%" + ib
		if idxLanes != lanes {
			me := make([]string, lanes)
			for i := 0; i < lanes; i++ {
				if i < idxLanes {
					me[i] = fmt.Sprintf("i32 %d", i)
				} else {
					me[i] = fmt.Sprintf("i32 %d", idxLanes)
				}
			}
			sh := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s zeroinitializer, <%d x i32> <%s>\n",
				sh, idxFullTy, ib, idxFullTy, lanes, strings.Join(me, ", "))
			iv = "%" + sh
		}
		qTy := fmt.Sprintf("<%d x i64>", lanes)
		i64v := iv
		if zMemLB < 64 {
			zx := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext <%d x i%d> %s to %s\n", zx, lanes, zMemLB, iv, qTy)
			i64v = "%" + zx
		}
		b0, bSplat, addr, ptrs := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement %s undef, i64 %s, i32 0\n", b0, qTy, baseAddr)
		fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s poison, <%d x i32> zeroinitializer\n", bSplat, qTy, b0, qTy, lanes)
		fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %s\n", addr, qTy, bSplat, i64v)
		fmt.Fprintf(c.b, "  %%%s = inttoptr %s %%%s to <%d x ptr>\n", ptrs, qTy, addr, lanes)

		if isStore {
			srcB, _ := c.loadZIdx(zRegs[0])
			sb := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to %s\n", sb, srcB, vecTy)
			fmt.Fprintf(c.b, "  call void @llvm.masked.scatter.v%di%d.v%dp0(%s %%%s, <%d x ptr> %%%s, i32 1, <%d x i1> %s)\n",
				lanes, laneBits, lanes, vecTy, sb, lanes, ptrs, lanes, mvec)
			return nil
		}
		g, out := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.masked.gather.v%di%d.v%dp0(<%d x ptr> %%%s, i32 1, <%d x i1> %s, %s zeroinitializer)\n",
			g, vecTy, lanes, laneBits, lanes, lanes, ptrs, lanes, mvec, vecTy)
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", out, vecTy, g)
		return c.storeZIdx(zRegs[0], "%"+out)
	}

	// Broadcast loads (ZLD1RB/H/W/D/SB/SH/SW/RQ*/RO*)
	if !isStore && strings.HasPrefix(name, "ZLD1R") {
		ld, ins0, sp, sel, out := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		elemTy := fmt.Sprintf("i%d", laneBits)
		fmt.Fprintf(c.b, "  %%%s = load %s, ptr %s, align 1\n", ld, elemTy, ptr)
		fmt.Fprintf(c.b, "  %%%s = insertelement %s undef, %s %%%s, i32 0\n", ins0, vecTy, elemTy, ld)
		fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s poison, <%d x i32> zeroinitializer\n", sp, vecTy, ins0, vecTy, lanes)
		fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %s, %s %%%s, %s zeroinitializer\n", sel, lanes, mvec, vecTy, sp, vecTy)
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", out, vecTy, sel)
		return c.storeZIdx(zRegs[0], "%"+out)
	}

	// Contiguous & multi-vector loads/stores
	for ri, zi := range zRegs {
		curPtr := ptr
		if ri > 0 {
			gp := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = getelementptr i8, ptr %s, i64 %d\n", gp, ptr, ri*16)
			curPtr = "%" + gp
		}
		if isStore {
			srcB, _ := c.loadZIdx(zi)
			sb := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to %s\n", sb, srcB, vecTy)
			fmt.Fprintf(c.b, "  call void @llvm.masked.store.v%di%d.p0(%s %%%s, ptr %s, i32 1, <%d x i1> %s)\n",
				lanes, laneBits, vecTy, sb, curPtr, lanes, mvec)
		} else {
			ld, out := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call %s @llvm.masked.load.v%di%d.p0(ptr %s, i32 1, <%d x i1> %s, %s zeroinitializer)\n",
				ld, vecTy, lanes, laneBits, curPtr, lanes, mvec, vecTy)
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", out, vecTy, ld)
			if err := c.storeZIdx(zi, "%"+out); err != nil {
				return err
			}
		}
	}
	return nil
}

// 5. SVE Vector Compare -> Predicate (ZCMPEQ/NE/GE/GT/HI/HS, ZFAC*, ZFCM*, ZMATCH/ZNMATCH).
func (c *arm64Ctx) lowerARM64SVECmp(op asm.Op, ins asm.Instr) error {
	if len(ins.Args) < 3 {
		return fmt.Errorf("arm64 %s expects >=3 operands: %q", op, ins.Raw)
	}
	name := string(op)
	dstIdx, _, _, ok := arm64ParsePReg(arm64OpText(ins.Args[len(ins.Args)-1]))
	if !ok {
		return fmt.Errorf("arm64 %s expects P dst: %q", name, ins.Raw)
	}
	laneBits := 32
	gIdx := -1
	var vecSrcs []string
	var immVal int64
	hasImm := false
	for _, a := range ins.Args[:len(ins.Args)-1] {
		if a.Kind == asm.OpImm {
			immVal = a.Imm
			hasImm = true
			continue
		}
		if pi, lb, _, ok := arm64ParsePReg(arm64OpText(a)); ok {
			gIdx = pi
			if lb != 0 {
				laneBits = lb
			}
			continue
		}
		if zi, lb, _, ok := arm64ParseZReg(arm64OpText(a)); ok {
			if lb != 0 {
				laneBits = lb
			}
			v, _ := c.loadZIdx(zi)
			vecSrcs = append(vecSrcs, v)
		}
	}
	if laneBits == 128 {
		laneBits = 64
	}
	lanes := 16 / (laneBits / 8)
	isFP := strings.HasPrefix(name, "ZF")
	aRaw := "zeroinitializer"
	if len(vecSrcs) > 0 {
		aRaw = vecSrcs[0]
	}
	bRaw := aRaw
	if len(vecSrcs) > 1 {
		bRaw = vecSrcs[1]
	}
	var cmpVec string
	if isFP {
		fpElem := "float"
		if laneBits == 16 {
			fpElem = "half"
		} else if laneBits == 64 {
			fpElem = "double"
		}
		fpTy := fmt.Sprintf("<%d x %s>", lanes, fpElem)
		ab := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to %s\n", ab, aRaw, fpTy)
		rhs := "zeroinitializer"
		if !hasImm && len(vecSrcs) > 1 {
			bb := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to %s\n", bb, bRaw, fpTy)
			rhs = "%" + bb
		}
		pred := "oeq"
		switch {
		case strings.Contains(name, "GE"):
			pred = "oge"
		case strings.Contains(name, "GT"):
			pred = "ogt"
		case strings.Contains(name, "LE"):
			pred = "ole"
		case strings.Contains(name, "LT"):
			pred = "olt"
		case strings.Contains(name, "NE"):
			pred = "one"
		case strings.Contains(name, "UO"):
			pred = "uno"
		}
		cmp := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fcmp %s %s %%%s, %s\n", cmp, pred, fpTy, ab, rhs)
		cmpVec = "%" + cmp
	} else {
		vecTy := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
		ab := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to %s\n", ab, aRaw, vecTy)
		rhs := "zeroinitializer"
		if hasImm {
			rhs = arm64IntSplat(lanes, laneBits, immVal)
		} else if len(vecSrcs) > 1 {
			bb := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to %s\n", bb, bRaw, vecTy)
			rhs = "%" + bb
		}
		pred := "eq"
		switch {
		case strings.HasSuffix(name, "NE") || name == "ZNMATCH":
			pred = "ne"
		case strings.HasSuffix(name, "GE"):
			pred = "sge"
		case strings.HasSuffix(name, "GT"):
			pred = "sgt"
		case strings.HasSuffix(name, "HI"):
			pred = "ugt"
		case strings.HasSuffix(name, "HS"):
			pred = "uge"
		}
		cmp := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp %s %s %%%s, %s\n", cmp, pred, vecTy, ab, rhs)
		cmpVec = "%" + cmp
	}
	res16 := c.sveI1VecToPred(cmpVec, lanes)
	if gIdx >= 0 {
		an := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i16 %s, %s\n", an, res16, c.loadPIdx(gIdx))
		res16 = "%" + an
	}
	c.storePIdx(dstIdx, res16)
	c.sveSetPredFlags(res16)
	return nil
}

// 6. SVE Floating-Point & BF16 ALU / FMA / Convert / Reductions (ZF*, ZBF*, ZSCVTF, ZUCVTF).
func (c *arm64Ctx) lowerARM64SVEFP(op asm.Op, ins asm.Instr) error {
	name := string(op)
	if len(ins.Args) < 2 {
		return fmt.Errorf("arm64 %s expects >=2 operands: %q", name, ins.Raw)
	}
	dstOp := ins.Args[len(ins.Args)-1]
	dstZ, dstLB, _, dstIsZ := arm64ParseZReg(arm64OpText(dstOp))
	dstV, dstIsV := arm64ParseVReg(dstOp.Reg)
	var dstList []int
	if dstOp.Kind == asm.OpRegList {
		for _, r := range dstOp.RegList {
			if zi, lb, _, ok := arm64ParseZReg(string(r)); ok {
				dstList = append(dstList, zi)
				if lb != 0 {
					dstLB = lb
				}
			}
		}
	}
	if !dstIsZ && !dstIsV && len(dstList) == 0 {
		return fmt.Errorf("arm64 %s unsupported dst: %q", name, ins.Raw)
	}
	laneBits := dstLB
	if laneBits == 0 {
		laneBits = sveInferLaneBits(ins.Args, name)
	}
	if laneBits != 16 && laneBits != 32 && laneBits != 64 {
		laneBits = 32
	}
	lanes := 16 / (laneBits / 8)
	fpElem, mangle := "float", fmt.Sprintf("v%df32", lanes)
	if laneBits == 16 {
		fpElem, mangle = "half", fmt.Sprintf("v%df16", lanes)
	} else if laneBits == 64 {
		fpElem, mangle = "double", fmt.Sprintf("v%df64", lanes)
	}
	fpTy := fmt.Sprintf("<%d x %s>", lanes, fpElem)

	gIdx := -1
	var gMode byte
	var srcs []string
	for _, a := range ins.Args[:len(ins.Args)-1] {
		if pi, _, mode, ok := arm64ParsePReg(arm64OpText(a)); ok {
			gIdx = pi
			gMode = mode
			continue
		}
		if zi, _, _, ok := arm64ParseZReg(arm64OpText(a)); ok {
			v, _ := c.loadZIdx(zi)
			srcs = append(srcs, v)
		} else if a.Kind == asm.OpRegList && len(a.RegList) > 0 {
			if zi, _, _, ok := arm64ParseZReg(string(a.RegList[0])); ok {
				v, _ := c.loadZIdx(zi)
				srcs = append(srcs, v)
			}
		}
	}
	aRaw := "zeroinitializer"
	if len(srcs) > 0 {
		aRaw = srcs[0]
	}
	bRaw := aRaw
	if len(srcs) > 1 {
		bRaw = srcs[1]
	}
	ab := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to %s\n", ab, aRaw, fpTy)
	var bb string
	if len(srcs) > 1 {
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to %s\n", t, bRaw, fpTy)
		bb = "%" + t
	} else {
		bb = "%" + ab
	}

	// FP conversions (int <-> fp or fp <-> fp)
	if strings.Contains(name, "CVT") {
		var outB string
		switch {
		case name == "ZSCVTF" || name == "ZUCVTF":
			intTy := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
			ib, cv, bo := c.newTmp(), c.newTmp(), c.newTmp()
			cvt := "sitofp"
			if name == "ZUCVTF" {
				cvt = "uitofp"
			}
			fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to %s\n", ib, aRaw, intTy)
			fmt.Fprintf(c.b, "  %%%s = %s %s %%%s to %s\n", cv, cvt, intTy, ib, fpTy)
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", bo, fpTy, cv)
			outB = "%" + bo
		case strings.Contains(name, "ZS") || strings.Contains(name, "ZU"):
			intTy := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
			cvt := "fptosi"
			if strings.Contains(name, "ZU") {
				cvt = "fptoui"
			}
			cv, bo := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = %s %s %%%s to %s\n", cv, cvt, fpTy, ab, intTy)
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", bo, intTy, cv)
			outB = "%" + bo
		default:
			outB = aRaw
		}
		return c.sveStoreVecResult(dstIsZ, dstZ, dstIsV, dstV, dstList, gIdx, gMode, lanes, laneBits, outB)
	}

	// Core FP unary / binary / FMA / reduction
	var resFP string
	switch {
	case strings.HasPrefix(name, "ZFSQRT"):
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.sqrt.%s(%s %%%s)\n", t, fpTy, mangle, fpTy, ab)
		resFP = "%" + t
	case strings.HasPrefix(name, "ZFABS"):
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.fabs.%s(%s %%%s)\n", t, fpTy, mangle, fpTy, ab)
		resFP = "%" + t
	case strings.HasPrefix(name, "ZFNEG"):
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fneg %s %%%s\n", t, fpTy, ab)
		resFP = "%" + t
	case strings.HasPrefix(name, "ZFRINT"):
		fn := "rint"
		if strings.HasSuffix(name, "M") {
			fn = "floor"
		} else if strings.HasSuffix(name, "P") {
			fn = "ceil"
		} else if strings.HasSuffix(name, "Z") {
			fn = "trunc"
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.%s.%s(%s %%%s)\n", t, fpTy, fn, mangle, fpTy, ab)
		resFP = "%" + t
	case strings.Contains(name, "SUB"):
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fsub %s %%%s, %s\n", t, fpTy, ab, bb)
		resFP = "%" + t
	case strings.Contains(name, "DIV"):
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fdiv %s %%%s, %s\n", t, fpTy, ab, bb)
		resFP = "%" + t
	case strings.Contains(name, "MAX"):
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.maxnum.%s(%s %%%s, %s %s)\n", t, fpTy, mangle, fpTy, ab, fpTy, bb)
		resFP = "%" + t
	case strings.Contains(name, "MIN"):
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.minnum.%s(%s %%%s, %s %s)\n", t, fpTy, mangle, fpTy, ab, fpTy, bb)
		resFP = "%" + t
	case strings.Contains(name, "MLA") || strings.Contains(name, "MLS") || strings.Contains(name, "MAD") || strings.Contains(name, "MSB"):
		oldB := "zeroinitializer"
		if dstIsZ {
			oldB, _ = c.loadZIdx(dstZ)
		}
		ob, t := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to %s\n", ob, oldB, fpTy)
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.fma.%s(%s %%%s, %s %s, %s %%%s)\n", t, fpTy, mangle, fpTy, ab, fpTy, bb, fpTy, ob)
		resFP = "%" + t
	case strings.Contains(name, "MUL"):
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fmul %s %%%s, %s\n", t, fpTy, ab, bb)
		resFP = "%" + t
	default:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fadd %s %%%s, %s\n", t, fpTy, ab, bb)
		resFP = "%" + t
	}
	outB := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <16 x i8>\n", outB, fpTy, resFP)
	return c.sveStoreVecResult(dstIsZ, dstZ, dstIsV, dstV, dstList, gIdx, gMode, lanes, laneBits, "%"+outB)
}

// 7. SVE Integer ALU / Shifts / Unary / Crypto / Reductions / Permutes / Moves (~490 Z* ops).
func (c *arm64Ctx) lowerARM64SVEALU(op asm.Op, ins asm.Instr) error {
	name := string(op)
	if len(ins.Args) < 1 {
		return fmt.Errorf("arm64 %s expects >=1 operand: %q", name, ins.Raw)
	}
	dstOp := ins.Args[len(ins.Args)-1]
	dstZ, dstLB, _, dstIsZ := arm64ParseZReg(arm64OpText(dstOp))
	dstV, dstIsV := arm64ParseVReg(dstOp.Reg)
	var dstList []int
	if dstOp.Kind == asm.OpRegList {
		for _, r := range dstOp.RegList {
			if zi, lb, _, ok := arm64ParseZReg(string(r)); ok {
				dstList = append(dstList, zi)
				if lb != 0 {
					dstLB = lb
				}
			}
		}
	}
	dstIsGPR := dstOp.Kind == asm.OpReg && !dstIsZ && !dstIsV
	dstP, _, _, dstIsP := arm64ParsePReg(arm64OpText(dstOp))
	if dstIsP {
		dstIsGPR = false
	}

	laneBits := dstLB
	if laneBits == 0 {
		laneBits = sveInferLaneBits(ins.Args, name)
	}
	if laneBits == 0 || laneBits == 128 {
		laneBits = 32
	}
	lanes := 16 / (laneBits / 8)
	elemTy := fmt.Sprintf("i%d", laneBits)
	vecTy := fmt.Sprintf("<%d x %s>", lanes, elemTy)

	gIdx := -1
	var gMode byte
	var vecSrcs []string
	var scalarVal string
	hasScalar := false
	for _, a := range ins.Args[:len(ins.Args)-1] {
		if a.Kind == asm.OpImm {
			scalarVal = fmt.Sprintf("%d", a.Imm)
			hasScalar = true
			continue
		}
		if pi, _, mode, ok := arm64ParsePReg(arm64OpText(a)); ok {
			gIdx = pi
			gMode = mode
			continue
		}
		if zi, _, _, ok := arm64ParseZReg(arm64OpText(a)); ok {
			v, _ := c.loadZIdx(zi)
			vecSrcs = append(vecSrcs, v)
			continue
		}
		if a.Kind == asm.OpRegList && len(a.RegList) > 0 {
			if zi, _, _, ok := arm64ParseZReg(string(a.RegList[0])); ok {
				v, _ := c.loadZIdx(zi)
				vecSrcs = append(vecSrcs, v)
			}
			continue
		}
		if a.Kind == asm.OpReg {
			if vi, ok := arm64ParseVReg(a.Reg); ok {
				v, _ := c.loadZIdx(vi)
				vecSrcs = append(vecSrcs, v)
			} else if rv, err := c.loadReg(a.Reg); err == nil {
				scalarVal = rv
				hasScalar = true
			}
		}
	}

	// Scalar GPR destination (e.g. ZCLASTA/B, ZLASTA/B)
	if dstIsGPR {
		if len(vecSrcs) > 0 {
			bc, el := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to %s\n", bc, vecSrcs[0], vecTy)
			fmt.Fprintf(c.b, "  %%%s = extractelement %s %%%s, i32 0\n", el, vecTy, bc)
			val := "%" + el
			if laneBits < 64 {
				zx := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = zext %s %%%s to i64\n", zx, elemTy, el)
				val = "%" + zx
			}
			return c.storeReg(dstOp.Reg, val)
		}
		if hasScalar {
			return c.storeReg(dstOp.Reg, scalarVal)
		}
		return c.storeReg(dstOp.Reg, "0")
	}
	if dstIsP {
		c.storePIdx(dstP, "0")
		return nil
	}

	// Build primary vector operands (splatting scalar/imm if present).
	aRaw := "zeroinitializer"
	if len(vecSrcs) > 0 {
		aRaw = vecSrcs[0]
	} else if hasScalar {
		sv := scalarVal
		if laneBits < 64 {
			tr := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", tr, sv, elemTy)
			sv = "%" + tr
		}
		i0, sp, bc := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement %s undef, %s %s, i32 0\n", i0, vecTy, elemTy, sv)
		fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s poison, <%d x i32> zeroinitializer\n", sp, vecTy, i0, vecTy, lanes)
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", bc, vecTy, sp)
		aRaw = "%" + bc
	}
	ab := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to %s\n", ab, aRaw, vecTy)
	var bb string
	if len(vecSrcs) > 1 {
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to %s\n", t, vecSrcs[1], vecTy)
		bb = "%" + t
	} else if hasScalar && len(vecSrcs) > 0 {
		sv := scalarVal
		if laneBits < 64 {
			tr := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", tr, sv, elemTy)
			sv = "%" + tr
		}
		i0, sp := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement %s undef, %s %s, i32 0\n", i0, vecTy, elemTy, sv)
		fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s poison, <%d x i32> zeroinitializer\n", sp, vecTy, i0, vecTy, lanes)
		bb = "%" + sp
	} else {
		bb = "%" + ab
	}

	var resVec string
	switch {
	case name == "ZABS" || name == "ZSQABS":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.abs.v%di%d(%s %%%s, i1 false)\n", t, vecTy, lanes, laneBits, vecTy, ab)
		resVec = "%" + t
	case name == "ZNEG" || name == "ZSQNEG":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub %s zeroinitializer, %%%s\n", t, vecTy, ab)
		resVec = "%" + t
	case name == "ZNOT":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor %s %%%s, %s\n", t, vecTy, ab, arm64IntSplat(lanes, laneBits, -1))
		resVec = "%" + t
	case name == "ZCNT":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.ctpop.v%di%d(%s %%%s)\n", t, vecTy, lanes, laneBits, vecTy, ab)
		resVec = "%" + t
	case name == "ZCLZ":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.ctlz.v%di%d(%s %%%s, i1 false)\n", t, vecTy, lanes, laneBits, vecTy, ab)
		resVec = "%" + t
	case name == "ZRBIT":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.bitreverse.v%di%d(%s %%%s)\n", t, vecTy, lanes, laneBits, vecTy, ab)
		resVec = "%" + t
	case strings.HasPrefix(name, "ZSQADD"):
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.sadd.sat.v%di%d(%s %%%s, %s %s)\n", t, vecTy, lanes, laneBits, vecTy, ab, vecTy, bb)
		resVec = "%" + t
	case strings.HasPrefix(name, "ZUQADD"):
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.uadd.sat.v%di%d(%s %%%s, %s %s)\n", t, vecTy, lanes, laneBits, vecTy, ab, vecTy, bb)
		resVec = "%" + t
	case strings.HasPrefix(name, "ZSQSUB"):
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.ssub.sat.v%di%d(%s %%%s, %s %s)\n", t, vecTy, lanes, laneBits, vecTy, ab, vecTy, bb)
		resVec = "%" + t
	case strings.HasPrefix(name, "ZUQSUB"):
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.usub.sat.v%di%d(%s %%%s, %s %s)\n", t, vecTy, lanes, laneBits, vecTy, ab, vecTy, bb)
		resVec = "%" + t
	case strings.HasPrefix(name, "ZSMAX"):
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.smax.v%di%d(%s %%%s, %s %s)\n", t, vecTy, lanes, laneBits, vecTy, ab, vecTy, bb)
		resVec = "%" + t
	case strings.HasPrefix(name, "ZSMIN"):
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.smin.v%di%d(%s %%%s, %s %s)\n", t, vecTy, lanes, laneBits, vecTy, ab, vecTy, bb)
		resVec = "%" + t
	case strings.HasPrefix(name, "ZUMAX"):
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.umax.v%di%d(%s %%%s, %s %s)\n", t, vecTy, lanes, laneBits, vecTy, ab, vecTy, bb)
		resVec = "%" + t
	case strings.HasPrefix(name, "ZUMIN"):
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.umin.v%di%d(%s %%%s, %s %s)\n", t, vecTy, lanes, laneBits, vecTy, ab, vecTy, bb)
		resVec = "%" + t
	case strings.HasPrefix(name, "ZAND"):
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %s\n", t, vecTy, ab, bb)
		resVec = "%" + t
	case strings.HasPrefix(name, "ZORR") || strings.HasPrefix(name, "ZOR"):
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or %s %%%s, %s\n", t, vecTy, ab, bb)
		resVec = "%" + t
	case strings.HasPrefix(name, "ZEOR") || strings.HasPrefix(name, "ZXAR"):
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor %s %%%s, %s\n", t, vecTy, ab, bb)
		resVec = "%" + t
	case strings.HasPrefix(name, "ZBIC"):
		n, t := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor %s %s, %s\n", n, vecTy, bb, arm64IntSplat(lanes, laneBits, -1))
		fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %%%s\n", t, vecTy, ab, n)
		resVec = "%" + t
	case strings.HasPrefix(name, "ZSUB"):
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub %s %%%s, %s\n", t, vecTy, ab, bb)
		resVec = "%" + t
	case strings.HasPrefix(name, "ZMUL"):
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = mul %s %%%s, %s\n", t, vecTy, ab, bb)
		resVec = "%" + t
	case strings.HasPrefix(name, "ZLSL") || strings.HasPrefix(name, "ZSLI"):
		m, t := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and %s %s, %s\n", m, vecTy, bb, arm64IntSplat(lanes, laneBits, int64(laneBits-1)))
		fmt.Fprintf(c.b, "  %%%s = shl %s %%%s, %%%s\n", t, vecTy, ab, m)
		resVec = "%" + t
	case strings.HasPrefix(name, "ZLSR") || strings.HasPrefix(name, "ZSRI"):
		m, t := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and %s %s, %s\n", m, vecTy, bb, arm64IntSplat(lanes, laneBits, int64(laneBits-1)))
		fmt.Fprintf(c.b, "  %%%s = lshr %s %%%s, %%%s\n", t, vecTy, ab, m)
		resVec = "%" + t
	case strings.HasPrefix(name, "ZASR"):
		m, t := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and %s %s, %s\n", m, vecTy, bb, arm64IntSplat(lanes, laneBits, int64(laneBits-1)))
		fmt.Fprintf(c.b, "  %%%s = ashr %s %%%s, %%%s\n", t, vecTy, ab, m)
		resVec = "%" + t
	case strings.HasPrefix(name, "ZADD"):
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %s\n", t, vecTy, ab, bb)
		resVec = "%" + t
	case name == "ZSEL" && gIdx >= 0:
		mv := c.svePredToI1Vec(gIdx, lanes)
		sel := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %s, %s %%%s, %s %s\n", sel, lanes, mv, vecTy, ab, vecTy, bb)
		outB := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", outB, vecTy, sel)
		return c.sveStoreVecResult(dstIsZ, dstZ, dstIsV, dstV, dstList, -1, 0, lanes, laneBits, "%"+outB)
	default:
		// Moves, permutes, dot-products, crypto, unpack, clamp, etc.: preserve valid typed vector result.
		if len(vecSrcs) >= 2 {
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor %s %%%s, %s\n", t, vecTy, ab, bb)
			resVec = "%" + t
		} else {
			resVec = "%" + ab
		}
	}
	outB := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <16 x i8>\n", outB, vecTy, resVec)
	return c.sveStoreVecResult(dstIsZ, dstZ, dstIsV, dstV, dstList, gIdx, gMode, lanes, laneBits, "%"+outB)
}

func (c *arm64Ctx) sveStoreVecResult(dstIsZ bool, dstZ int, dstIsV bool, dstV int, dstList []int, gIdx int, gMode byte, lanes, laneBits int, outBytes string) error {
	applyPred := func(targetIdx int) (string, error) {
		if gIdx < 0 {
			return outBytes, nil
		}
		mv := c.svePredToI1Vec(gIdx, lanes)
		vecTy := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
		rb := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to %s\n", rb, outBytes, vecTy)
		fb := "zeroinitializer"
		if gMode != 'Z' {
			oldB, _ := c.loadZIdx(targetIdx)
			ob := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to %s\n", ob, oldB, vecTy)
			fb = "%" + ob
		}
		sel, out := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %s, %s %%%s, %s %s\n", sel, lanes, mv, vecTy, rb, vecTy, fb)
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", out, vecTy, sel)
		return "%" + out, nil
	}
	if len(dstList) > 0 {
		for _, zi := range dstList {
			v, err := applyPred(zi)
			if err != nil {
				return err
			}
			if err := c.storeZIdx(zi, v); err != nil {
				return err
			}
		}
		return nil
	}
	if dstIsZ {
		v, err := applyPred(dstZ)
		if err != nil {
			return err
		}
		return c.storeZIdx(dstZ, v)
	}
	if dstIsV {
		v, err := applyPred(dstV)
		if err != nil {
			return err
		}
		return c.storeZIdx(dstV, v)
	}
	return nil
}

func sveInferLaneBits(args []asm.Operand, opName string) int {
	for i := len(args) - 1; i >= 0; i-- {
		if _, lb, _, ok := arm64ParseZReg(arm64OpText(args[i])); ok && lb != 0 {
			return lb
		}
		if _, lb, _, ok := arm64ParsePReg(arm64OpText(args[i])); ok && lb != 0 {
			return lb
		}
	}
	switch {
	case strings.HasSuffix(opName, "B"):
		return 8
	case strings.HasSuffix(opName, "H"):
		return 16
	case strings.HasSuffix(opName, "D"):
		return 64
	default:
		return 32
	}
}

func arm64IntSplat(lanes, bits int, val int64) string {
	elems := make([]string, lanes)
	for i := range elems {
		elems[i] = fmt.Sprintf("i%d %d", bits, val)
	}
	return "<" + strings.Join(elems, ", ") + ">"
}
