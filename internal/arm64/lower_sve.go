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

// arm64ParsePReg parses an SVE predicate register such as P4, P4.B, P4.M, P1.Z,
// or P1/Z. Predicate-as-counter registers (PN8..PN15) are intentionally rejected
// because they hold element counts rather than per-lane bitmasks.
func arm64ParsePReg(s string) (idx int, laneBits int, mode byte, ok bool) {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "/", ".")
	if br := strings.IndexByte(s, '['); br >= 0 {
		return 0, 0, 0, false
	}
	if !strings.HasPrefix(s, "P") || len(s) < 2 || s[1] < '0' || s[1] > '9' {
		return 0, 0, 0, false
	}
	rest := s[1:]
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
	if slot, ok := c.zRegSlot[idx]; ok {
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load <vscale x 16 x i8>, ptr %s\n", t, slot)
		return "%" + t, nil
	}
	if slot, ok := c.vRegSlot[idx]; ok {
		v, ins := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load <16 x i8>, ptr %s\n", v, slot)
		fmt.Fprintf(c.b, "  %%%s = call <vscale x 16 x i8> @llvm.vector.insert.nxv16i8.v16i8(<vscale x 16 x i8> zeroinitializer, <16 x i8> %%%s, i64 0)\n", ins, v)
		return "%" + ins, nil
	}
	return "zeroinitializer", nil
}

func (c *arm64Ctx) storeZIdx(idx int, v string) error {
	if slot, ok := c.zRegSlot[idx]; ok {
		fmt.Fprintf(c.b, "  store <vscale x 16 x i8> %s, ptr %s\n", v, slot)
	}
	if vSlot, ok := c.vRegSlot[idx]; ok {
		lo := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call <16 x i8> @llvm.vector.extract.v16i8.nxv16i8(<vscale x 16 x i8> %s, i64 0)\n", lo, v)
		fmt.Fprintf(c.b, "  store <16 x i8> %%%s, ptr %s\n", lo, vSlot)
	}
	return nil
}

func (c *arm64Ctx) loadPIdx(idx int) string {
	slot, ok := c.pRegSlot[idx]
	if !ok {
		return "zeroinitializer"
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load <vscale x 16 x i1>, ptr %s\n", t, slot)
	return "%" + t
}

func (c *arm64Ctx) storePIdx(idx int, p16 string) {
	slot, ok := c.pRegSlot[idx]
	if !ok {
		return
	}
	fmt.Fprintf(c.b, "  store <vscale x 16 x i1> %s, ptr %s\n", p16, slot)
}

func (c *arm64Ctx) sveAllTruePred(baseLanes int) string {
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call <vscale x %d x i1> @llvm.aarch64.sve.ptrue.nxv%di1(i32 31)\n", t, baseLanes, baseLanes)
	return "%" + t
}

func (c *arm64Ctx) sveSetPredFlags(p16 string) {
	// Architectural scalable SVE predicate flag semantics:
	// N = first active element is true, Z = no active element is true,
	// C = last active element is NOT true, V = 0.
	pg := c.sveAllTruePred(16)
	n, any, z, last, cf := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call i1 @llvm.aarch64.sve.ptest.first(<vscale x 16 x i1> %s, <vscale x 16 x i1> %s)\n", n, pg, p16)
	fmt.Fprintf(c.b, "  %%%s = call i1 @llvm.aarch64.sve.ptest.any(<vscale x 16 x i1> %s, <vscale x 16 x i1> %s)\n", any, pg, p16)
	fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, true\n", z, any)
	fmt.Fprintf(c.b, "  %%%s = call i1 @llvm.aarch64.sve.ptest.last(<vscale x 16 x i1> %s, <vscale x 16 x i1> %s)\n", last, pg, p16)
	fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, true\n", cf, last)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", n, c.flagsNSlot)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", z, c.flagsZSlot)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCSlot)
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsVSlot)
	c.flagsWritten = true
}

func (c *arm64Ctx) svePredToI1Vec(pIdx, baseLanes int) string {
	pv := c.loadPIdx(pIdx)
	if baseLanes == 16 {
		return pv
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call <vscale x %d x i1> @llvm.aarch64.sve.convert.from.svbool.nxv%di1(<vscale x 16 x i1> %s)\n",
		t, baseLanes, baseLanes, pv)
	return "%" + t
}

func (c *arm64Ctx) sveI1VecToPred(vec string, baseLanes int) string {
	if baseLanes == 16 {
		return vec
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call <vscale x 16 x i1> @llvm.aarch64.sve.convert.to.svbool.nxv%di1(<vscale x %d x i1> %s)\n",
		t, baseLanes, baseLanes, vec)
	return "%" + t
}

func (c *arm64Ctx) sveSplatVal(baseLanes int, elemTy, val string) string {
	vecTy := fmt.Sprintf("<vscale x %d x %s>", baseLanes, elemTy)
	i0, sp := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement %s poison, %s %s, i64 0\n", i0, vecTy, elemTy, val)
	fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s poison, <vscale x %d x i32> zeroinitializer\n",
		sp, vecTy, i0, vecTy, baseLanes)
	return "%" + sp
}

func (c *arm64Ctx) sveScaledVLBytes(mult, baseBytes int64) string {
	vs := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call i64 @llvm.vscale.i64()\n", vs)
	factor := mult * baseBytes
	if factor == 1 {
		return "%" + vs
	}
	sc := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = mul i64 %%%s, %d\n", sc, vs, factor)
	return "%" + sc
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

// 1. Non-SVE privileged & system instructions.
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
	return fmt.Errorf("arm64: unsupported system instruction %s", op)
}

// 2. Scalable SVE scalar VL/PL arithmetic & loop termination.
func (c *arm64Ctx) lowerARM64SVEScalar(op asm.Op, ins asm.Instr) error {
	switch op {
	case "RDVL":
		if len(ins.Args) != 2 || ins.Args[0].Kind != asm.OpImm || ins.Args[1].Kind != asm.OpReg {
			return fmt.Errorf("arm64 RDVL expects $imm, Rd: %q", ins.Raw)
		}
		scaled := c.sveScaledVLBytes(ins.Args[0].Imm, 16)
		return c.storeReg(ins.Args[1].Reg, scaled)
	case "ADDVL", "ADDPL":
		if len(ins.Args) != 3 || ins.Args[0].Kind != asm.OpImm || ins.Args[1].Kind != asm.OpReg || ins.Args[2].Kind != asm.OpReg {
			return fmt.Errorf("arm64 %s expects $imm, Rn, Rd: %q", op, ins.Raw)
		}
		rn, err := c.loadReg(ins.Args[1].Reg)
		if err != nil {
			return err
		}
		baseBytes := int64(16)
		if op == "ADDPL" {
			baseBytes = 2
		}
		scaled := c.sveScaledVLBytes(ins.Args[0].Imm, baseBytes)
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i64 %s, %s\n", t, rn, scaled)
		return c.storeReg(ins.Args[2].Reg, "%"+t)
	case "CNTB", "CNTH", "CNTW", "CNTD":
		if len(ins.Args) != 1 || ins.Args[0].Kind != asm.OpReg {
			return fmt.Errorf("arm64 %s expects Rd: %q", op, ins.Raw)
		}
		suf := strings.ToLower(string(op[len(op)-1]))
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i64 @llvm.aarch64.sve.cnt%s(i32 31)\n", t, suf)
		return c.storeReg(ins.Args[0].Reg, "%"+t)
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

// arm64ParseZRegMod parses an SVE vector register together with any optional
// extension (.UXTW/.SXTW) and scale shift (<<0..<<3) attached in text form.
func arm64ParseZRegMod(s string) (idx int, laneBits int, ext asm.ExtendOp, shift uint, ok bool) {
	s = strings.ToUpper(strings.TrimSpace(s))
	if len(s) < 2 || s[0] != 'Z' || s[1] < '0' || s[1] > '9' {
		return 0, 0, "", 0, false
	}
	if sh := strings.Index(s, "<<"); sh >= 0 {
		n, err := strconv.ParseUint(strings.TrimSpace(s[sh+2:]), 10, 64)
		if err != nil || n > 3 {
			return 0, 0, "", 0, false
		}
		shift = uint(n)
		s = strings.TrimSpace(s[:sh])
	}
	if br := strings.IndexByte(s, '['); br >= 0 {
		return 0, 0, "", 0, false
	}
	parts := strings.Split(s, ".")
	n, err := strconv.Atoi(parts[0][1:])
	if err != nil || n < 0 || n > 31 {
		return 0, 0, "", 0, false
	}
	if len(parts) >= 2 {
		laneBits = sveLaneBitsFromSuffix(parts[1])
		if laneBits == 0 {
			return 0, 0, "", 0, false
		}
	}
	if len(parts) == 3 {
		switch asm.ExtendOp(parts[2]) {
		case asm.ExtendUXTW, asm.ExtendSXTW:
			ext = asm.ExtendOp(parts[2])
		default:
			return 0, 0, "", 0, false
		}
	} else if len(parts) > 3 {
		return 0, 0, "", 0, false
	}
	return n, laneBits, ext, shift, true
}

func sveScaleToShift(scale int64) (uint, bool) {
	switch scale {
	case 0, 1:
		return 0, true
	case 2:
		return 1, true
	case 4:
		return 2, true
	case 8:
		return 3, true
	default:
		return 0, false
	}
}

func sveParseVLMult(s string) (int64, bool) {
	up := strings.ToUpper(strings.Trim(strings.TrimSpace(s), " ()"))
	if !strings.Contains(up, "VL") {
		return 0, false
	}
	mult := int64(1)
	if strings.HasPrefix(up, "-") {
		mult = -1
		up = strings.TrimPrefix(up, "-")
	}
	if star := strings.IndexByte(up, '*'); star >= 0 {
		k, err := strconv.ParseInt(strings.TrimSpace(up[star+1:]), 10, 64)
		if err != nil {
			return 0, false
		}
		mult *= k
	}
	return mult, true
}

type sveMemEval struct {
	ptr           string
	hasZ          bool
	zIsVectorBase bool // true for (Zn.S/D) + imm, false for (baseGPR)(Zm.S/D[.ext][<<sh])
	zIdx          int
	zLaneBits     int
	zExt          asm.ExtendOp
	zShift        uint
	baseAddr      string
}

// sveEvalMemPtr evaluates a scalar, runtime-scalable VL-scaled, or SVE
// gather/scatter memory operand. Preserves index extension (UXTW/SXTW) and
// scale/shift (<<1/<<2/<<3) on both GPR and Z vector indices.
func (c *arm64Ctx) sveEvalMemPtr(op asm.Operand, baseScaleBytes int64) (sveMemEval, error) {
	switch op.Kind {
	case asm.OpSym:
		s := strings.TrimSpace(op.Sym)
		if strings.HasSuffix(s, "(SB)") {
			p, e := c.ptrFromSB(s)
			return sveMemEval{ptr: p}, e
		}
		off := int64(0)
		vlMult := int64(0)
		hasVL := false
		regName := ""
		if lp := strings.LastIndexByte(s, '('); lp >= 0 && strings.HasSuffix(s, ")") {
			regName = s[lp+1 : len(s)-1]
			prefix := strings.Trim(s[:lp], " ()")
			if m, ok := sveParseVLMult(prefix); ok {
				hasVL = true
				vlMult = m
			} else if k, e := strconv.ParseInt(prefix, 10, 64); e == nil {
				off = k
			}
		}
		base, _ := c.sveEvalRegName(regName)
		addr := base
		if hasVL && vlMult != 0 {
			scaled := c.sveScaledVLBytes(vlMult, baseScaleBytes)
			ad := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add i64 %s, %s\n", ad, addr, scaled)
			addr = "%" + ad
		}
		if off != 0 {
			ad := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add i64 %s, %d\n", ad, addr, off)
			addr = "%" + ad
		}
		p := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", p, addr)
		return sveMemEval{ptr: "%" + p, baseAddr: addr}, nil

	case asm.OpMem:
		mem := op.Mem
		if zi, zlb, zext, zshift, ok := arm64ParseZRegMod(string(mem.Base)); ok {
			bVal := "0"
			isVecBase := true
			if mem.Index != "" {
				isVecBase = false
				bVal, _ = c.sveEvalRegName(string(mem.Index))
			}
			if mem.Off != 0 {
				ad := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = add i64 %s, %d\n", ad, bVal, mem.Off)
				bVal = "%" + ad
			}
			if mem.Scale > 1 {
				sh, shOK := sveScaleToShift(mem.Scale)
				if !shOK {
					return sveMemEval{}, fmt.Errorf("arm64 SVE unsupported gather/scatter scale %d", mem.Scale)
				}
				if zshift == 0 {
					zshift = sh
				}
			}
			if zext == "" && mem.IndexExt != "" {
				zext = mem.IndexExt
			}
			return sveMemEval{
				hasZ:          true,
				zIsVectorBase: isVecBase,
				zIdx:          zi,
				zLaneBits:     zlb,
				zExt:          zext,
				zShift:        zshift,
				baseAddr:      bVal,
			}, nil
		}
		if zi, zlb, zext, zshift, ok := arm64ParseZRegMod(string(mem.Index)); ok {
			bVal := "0"
			if mem.Base != "" {
				bVal, _ = c.sveEvalRegName(string(mem.Base))
			}
			if mem.Off != 0 {
				ad := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = add i64 %s, %d\n", ad, bVal, mem.Off)
				bVal = "%" + ad
			}
			sh, shOK := sveScaleToShift(mem.Scale)
			if !shOK {
				return sveMemEval{}, fmt.Errorf("arm64 SVE unsupported gather/scatter scale %d", mem.Scale)
			}
			if zshift == 0 {
				zshift = sh
			}
			if zext == "" {
				zext = mem.IndexExt
			}
			return sveMemEval{
				hasZ:          true,
				zIsVectorBase: false,
				zIdx:          zi,
				zLaneBits:     zlb,
				zExt:          zext,
				zShift:        zshift,
				baseAddr:      bVal,
			}, nil
		}
		baseStr := string(mem.Base)
		idxStr := string(mem.Index)
		addr := "0"
		if mult, ok := sveParseVLMult(baseStr); ok {
			baseVal := "0"
			if idxStr != "" {
				baseVal, _ = c.sveEvalRegName(idxStr)
			}
			addr = baseVal
			if mult != 0 {
				scaled := c.sveScaledVLBytes(mult, baseScaleBytes)
				ad := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = add i64 %s, %s\n", ad, addr, scaled)
				addr = "%" + ad
			}
		} else {
			if baseStr != "" {
				addr, _ = c.sveEvalRegName(baseStr)
			}
			if idxStr != "" {
				iv, _ := c.sveEvalRegName(idxStr)
				switch mem.IndexExt {
				case asm.ExtendUXTW:
					t32, z64 := c.newTmp(), c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", t32, iv)
					fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z64, t32)
					iv = "%" + z64
				case asm.ExtendSXTW:
					t32, s64 := c.newTmp(), c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", t32, iv)
					fmt.Fprintf(c.b, "  %%%s = sext i32 %%%s to i64\n", s64, t32)
					iv = "%" + s64
				}
				if mem.Scale > 1 {
					sh, shOK := sveScaleToShift(mem.Scale)
					if !shOK {
						return sveMemEval{}, fmt.Errorf("arm64 SVE unsupported index scale %d", mem.Scale)
					}
					sc := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = shl i64 %s, %d\n", sc, iv, sh)
					iv = "%" + sc
				}
				ad := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = add i64 %s, %s\n", ad, addr, iv)
				addr = "%" + ad
			}
		}
		if mult, ok := sveParseVLMult(mem.OffRaw); ok && mult != 0 {
			scaled := c.sveScaledVLBytes(mult, baseScaleBytes)
			ad := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add i64 %s, %s\n", ad, addr, scaled)
			addr = "%" + ad
		}
		if mem.Off != 0 {
			ad := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add i64 %s, %d\n", ad, addr, mem.Off)
			addr = "%" + ad
		}
		p := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", p, addr)
		return sveMemEval{ptr: "%" + p, baseAddr: addr}, nil

	default:
		return sveMemEval{}, fmt.Errorf("arm64 SVE unsupported memory operand %s", op.String())
	}
}

// 3. Scalable SVE Predicate Engine.
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
		var ptr string
		if len(ins.Args) == 3 && ins.Args[0].Kind == asm.OpReg && ins.Args[1].Kind == asm.OpImm {
			base, e := c.loadReg(ins.Args[0].Reg)
			if e != nil {
				return e
			}
			addr := base
			if ins.Args[1].Imm != 0 {
				scaled := c.sveScaledVLBytes(ins.Args[1].Imm, 2)
				ad := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = add i64 %s, %s\n", ad, addr, scaled)
				addr = "%" + ad
			}
			pt := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pt, addr)
			ptr = "%" + pt
		} else {
			me, e := c.sveEvalMemPtr(ins.Args[0], 2)
			if e != nil {
				return e
			}
			ptr = me.ptr
		}
		ld := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load <vscale x 16 x i1>, ptr %s, align 1\n", ld, ptr)
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
		var ptr string
		if len(ins.Args) == 3 && ins.Args[1].Kind == asm.OpReg && ins.Args[2].Kind == asm.OpImm {
			base, e := c.loadReg(ins.Args[1].Reg)
			if e != nil {
				return e
			}
			addr := base
			if ins.Args[2].Imm != 0 {
				scaled := c.sveScaledVLBytes(ins.Args[2].Imm, 2)
				ad := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = add i64 %s, %s\n", ad, addr, scaled)
				addr = "%" + ad
			}
			pt := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pt, addr)
			ptr = "%" + pt
		} else {
			me, e := c.sveEvalMemPtr(ins.Args[1], 2)
			if e != nil {
				return e
			}
			ptr = me.ptr
		}
		fmt.Fprintf(c.b, "  store <vscale x 16 x i1> %s, ptr %s, align 1\n", c.loadPIdx(pi), ptr)
		return nil

	case name == "PPFALSE":
		if len(ins.Args) != 1 {
			return fmt.Errorf("arm64 PPFALSE expects Pd: %q", ins.Raw)
		}
		if pi, _, _, ok := arm64ParsePReg(arm64OpText(ins.Args[0])); ok {
			c.storePIdx(pi, "zeroinitializer")
			return nil
		}
		return fmt.Errorf("arm64 PPFALSE expects P dst: %q", ins.Raw)

	case name == "PPTRUE":
		if len(ins.Args) < 1 {
			return fmt.Errorf("arm64 PPTRUE expects Pd: %q", ins.Raw)
		}
		pi, lb, _, ok := arm64ParsePReg(arm64OpText(ins.Args[len(ins.Args)-1]))
		if !ok {
			return fmt.Errorf("arm64 PPTRUE expects P dst: %q", ins.Raw)
		}
		if lb == 0 || lb == 128 {
			lb = 8
		}
		baseLanes := 128 / lb
		p := c.sveAllTruePred(baseLanes)
		c.storePIdx(pi, c.sveI1VecToPred(p, baseLanes))
		return nil

	case name == "PWRFFR":
		if len(ins.Args) != 1 {
			return fmt.Errorf("arm64 PWRFFR expects Pn: %q", ins.Raw)
		}
		pi, _, _, ok := arm64ParsePReg(arm64OpText(ins.Args[0]))
		if !ok {
			return fmt.Errorf("arm64 PWRFFR expects P src: %q", ins.Raw)
		}
		if c.ffrSlot != "" {
			fmt.Fprintf(c.b, "  store <vscale x 16 x i1> %s, ptr %s\n", c.loadPIdx(pi), c.ffrSlot)
		}
		return nil

	case name == "PRDFFR" || name == "PRDFFRS":
		if len(ins.Args) < 1 {
			return fmt.Errorf("arm64 %s expects [Pg,] Pd: %q", name, ins.Raw)
		}
		val := c.sveAllTruePred(16)
		if c.ffrSlot != "" {
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load <vscale x 16 x i1>, ptr %s\n", t, c.ffrSlot)
			val = "%" + t
		}
		if len(ins.Args) == 2 {
			if gi, _, _, ok := arm64ParsePReg(arm64OpText(ins.Args[0])); ok {
				a := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = and <vscale x 16 x i1> %s, %s\n", a, val, c.loadPIdx(gi))
				val = "%" + a
			}
		}
		di, _, _, ok := arm64ParsePReg(arm64OpText(ins.Args[len(ins.Args)-1]))
		if !ok {
			return fmt.Errorf("arm64 %s expects P dst: %q", name, ins.Raw)
		}
		c.storePIdx(di, val)
		if name == "PRDFFRS" {
			c.sveSetPredFlags(val)
		}
		return nil

	case name == "PPTEST":
		if len(ins.Args) != 2 {
			return fmt.Errorf("arm64 PPTEST expects Pn, Pg: %q", ins.Raw)
		}
		p1, _, _, ok1 := arm64ParsePReg(arm64OpText(ins.Args[0]))
		p2, _, _, ok2 := arm64ParsePReg(arm64OpText(ins.Args[1]))
		if !ok1 || !ok2 {
			return fmt.Errorf("arm64 PPTEST expects P operands: %q", ins.Raw)
		}
		pg, pn := c.loadPIdx(p2), c.loadPIdx(p1)
		n, any, z, last, cf := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i1 @llvm.aarch64.sve.ptest.first(<vscale x 16 x i1> %s, <vscale x 16 x i1> %s)\n", n, pg, pn)
		fmt.Fprintf(c.b, "  %%%s = call i1 @llvm.aarch64.sve.ptest.any(<vscale x 16 x i1> %s, <vscale x 16 x i1> %s)\n", any, pg, pn)
		fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, true\n", z, any)
		fmt.Fprintf(c.b, "  %%%s = call i1 @llvm.aarch64.sve.ptest.last(<vscale x 16 x i1> %s, <vscale x 16 x i1> %s)\n", last, pg, pn)
		fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, true\n", cf, last)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", n, c.flagsNSlot)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", z, c.flagsZSlot)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCSlot)
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsVSlot)
		c.flagsWritten = true
		return nil

	case name == "PWHILELT" || name == "PWHILELTW" || name == "PWHILELE" || name == "PWHILELEW" ||
		name == "PWHILELO" || name == "PWHILELOW" || name == "PWHILELS" || name == "PWHILELSW" ||
		name == "PWHILEGE" || name == "PWHILEGEW" || name == "PWHILEGT" || name == "PWHILEGTW" ||
		name == "PWHILEHI" || name == "PWHILEHIW" || name == "PWHILEHS" || name == "PWHILEHSW":
		if len(ins.Args) != 3 || ins.Args[0].Kind != asm.OpReg || ins.Args[1].Kind != asm.OpReg {
			return fmt.Errorf("arm64 %s expects Rm, Rn, Pd: %q", name, ins.Raw)
		}
		limit, err := c.loadReg(ins.Args[0].Reg)
		if err != nil {
			return err
		}
		start, err := c.loadReg(ins.Args[1].Reg)
		if err != nil {
			return err
		}
		ty := "i64"
		if strings.HasSuffix(name, "W") {
			ty = "i32"
			t1, t2 := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", t1, limit)
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", t2, start)
			limit, start = "%"+t1, "%"+t2
		}
		condPart := strings.TrimPrefix(name, "PWHILE")
		condPart = strings.TrimSuffix(condPart, "W")
		intrName := "while" + strings.ToLower(condPart)
		dst := ins.Args[2]
		pi, laneBits, _, ok := arm64ParsePReg(arm64OpText(dst))
		if !ok {
			return fmt.Errorf("arm64 %s expects single P dst: %q", name, ins.Raw)
		}
		if laneBits == 0 {
			laneBits = 8
		}
		if laneBits == 128 {
			laneBits = 64
		}
		baseLanes := 128 / laneBits
		w := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call <vscale x %d x i1> @llvm.aarch64.sve.%s.nxv%di1.%s(%s %s, %s %s)\n",
			w, baseLanes, intrName, baseLanes, ty, ty, start, ty, limit)
		p16 := c.sveI1VecToPred("%"+w, baseLanes)
		c.storePIdx(pi, p16)
		c.sveSetPredFlags(p16)
		return nil

	case name == "PCNTP" || name == "PINCP" || name == "PDECP" ||
		name == "PSQINCP" || name == "PSQINCPW" || name == "PSQDECP" || name == "PSQDECPW" ||
		name == "PUQINCP" || name == "PUQINCPW" || name == "PUQDECP" || name == "PUQDECPW":
		if len(ins.Args) < 2 {
			return fmt.Errorf("arm64 %s expects >=2 operands: %q", name, ins.Raw)
		}
		dst := ins.Args[len(ins.Args)-1]
		var pRegs []int
		laneBits := 8
		for _, a := range ins.Args[:len(ins.Args)-1] {
			if pi, lb, _, ok := arm64ParsePReg(arm64OpText(a)); ok {
				if lb > laneBits {
					laneBits = lb
				}
				pRegs = append(pRegs, pi)
			}
		}
		if len(pRegs) == 0 {
			return fmt.Errorf("arm64 %s expects predicate source: %q", name, ins.Raw)
		}
		if laneBits == 128 {
			laneBits = 64
		}
		baseLanes := 128 / laneBits
		pn := c.svePredToI1Vec(pRegs[0], baseLanes)
		pg := pn
		if len(pRegs) > 1 {
			pg = c.svePredToI1Vec(pRegs[1], baseLanes)
		}
		cnt := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i64 @llvm.aarch64.sve.cntp.nxv%di1(<vscale x %d x i1> %s, <vscale x %d x i1> %s)\n",
			cnt, baseLanes, baseLanes, pg, baseLanes, pn)
		res := "%" + cnt
		if strings.Contains(name, "INCP") || strings.Contains(name, "DECP") {
			if dst.Kind != asm.OpReg {
				return fmt.Errorf("arm64 %s expects register destination: %q", name, ins.Raw)
			}
			oldV, err := c.loadReg(dst.Reg)
			if err != nil {
				return err
			}
			isSub := strings.Contains(name, "DECP")
			is32 := strings.HasSuffix(name, "W")
			if strings.HasPrefix(name, "PSQ") || strings.HasPrefix(name, "PUQ") {
				ty := "i64"
				if is32 {
					ty = "i32"
					t1, t2 := c.newTmp(), c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", t1, oldV)
					fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", t2, res)
					oldV, res = "%"+t1, "%"+t2
				}
				satFn := "sadd.sat"
				switch {
				case strings.HasPrefix(name, "PSQ") && isSub:
					satFn = "ssub.sat"
				case strings.HasPrefix(name, "PUQ") && !isSub:
					satFn = "uadd.sat"
				case strings.HasPrefix(name, "PUQ") && isSub:
					satFn = "usub.sat"
				}
				sat := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = call %s @llvm.%s.%s(%s %s, %s %s)\n", sat, ty, satFn, ty, ty, oldV, ty, res)
				res = "%" + sat
				if is32 {
					z := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, sat)
					res = "%" + z
				}
			} else {
				opCode := "add"
				if isSub {
					opCode = "sub"
				}
				t := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = %s i64 %s, %s\n", t, opCode, oldV, res)
				res = "%" + t
			}
		}
		if dst.Kind == asm.OpReg {
			return c.storeReg(dst.Reg, res)
		}
		return fmt.Errorf("arm64 %s expects register destination: %q", name, ins.Raw)

	case name == "PAND" || name == "PANDS" || name == "PBIC" || name == "PBICS" ||
		name == "PEOR" || name == "PEORS" || name == "PNAND" || name == "PNANDS" ||
		name == "PNOR" || name == "PNORS" || name == "PORN" || name == "PORNS" ||
		name == "PORR" || name == "PORRS" || name == "PREV" ||
		name == "PBRKA" || name == "PBRKAS" || name == "PBRKB" || name == "PBRKBS" ||
		name == "PBRKPA" || name == "PBRKPAS" || name == "PBRKPB" || name == "PBRKPBS" ||
		name == "PBRKN" || name == "PBRKNS" ||
		name == "PPUNPKLO" || name == "PPUNPKHI" || name == "PTRN1" || name == "PTRN2" ||
		name == "PUZP1" || name == "PUZP2" || name == "PZIP1" || name == "PZIP2":
		if len(ins.Args) < 2 {
			return fmt.Errorf("arm64 %s expects >=2 operands: %q", name, ins.Raw)
		}
		setFlags := strings.HasSuffix(name, "S")
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
		s0 := "zeroinitializer"
		if len(srcs) > 0 {
			s0 = srcs[0]
		}
		s1 := s0
		if len(srcs) > 1 {
			s1 = srcs[1]
		}
		allTrue := c.sveAllTruePred(16)
		var res string
		switch base {
		case "PAND":
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and <vscale x 16 x i1> %s, %s\n", t, s0, s1)
			res = "%" + t
		case "PBIC":
			n, t := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor <vscale x 16 x i1> %s, %s\n", n, s0, allTrue)
			fmt.Fprintf(c.b, "  %%%s = and <vscale x 16 x i1> %s, %%%s\n", t, s1, n)
			res = "%" + t
		case "PEOR":
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor <vscale x 16 x i1> %s, %s\n", t, s0, s1)
			res = "%" + t
		case "PNAND":
			a, t := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and <vscale x 16 x i1> %s, %s\n", a, s0, s1)
			fmt.Fprintf(c.b, "  %%%s = xor <vscale x 16 x i1> %%%s, %s\n", t, a, allTrue)
			res = "%" + t
		case "PNOR":
			o, t := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = or <vscale x 16 x i1> %s, %s\n", o, s0, s1)
			fmt.Fprintf(c.b, "  %%%s = xor <vscale x 16 x i1> %%%s, %s\n", t, o, allTrue)
			res = "%" + t
		case "PORN":
			n, t := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor <vscale x 16 x i1> %s, %s\n", n, s0, allTrue)
			fmt.Fprintf(c.b, "  %%%s = or <vscale x 16 x i1> %s, %%%s\n", t, s1, n)
			res = "%" + t
		case "PORR":
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = or <vscale x 16 x i1> %s, %s\n", t, s0, s1)
			res = "%" + t
		case "PREV":
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call <vscale x 16 x i1> @llvm.aarch64.sve.rev.nxv16i1(<vscale x 16 x i1> %s)\n", t, s0)
			res = "%" + t
		case "PBRKA":
			pg := allTrue
			if hasG {
				pg = gVal
			}
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call <vscale x 16 x i1> @llvm.aarch64.sve.brka.z(<vscale x 16 x i1> %s, <vscale x 16 x i1> %s)\n", t, pg, s0)
			res = "%" + t
			hasG = false
		case "PBRKB":
			pg := allTrue
			if hasG {
				pg = gVal
			}
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call <vscale x 16 x i1> @llvm.aarch64.sve.brkb.z(<vscale x 16 x i1> %s, <vscale x 16 x i1> %s)\n", t, pg, s0)
			res = "%" + t
			hasG = false
		case "PBRKPA":
			pg := allTrue
			if hasG {
				pg = gVal
			}
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call <vscale x 16 x i1> @llvm.aarch64.sve.brkpa.z(<vscale x 16 x i1> %s, <vscale x 16 x i1> %s, <vscale x 16 x i1> %s)\n", t, pg, s1, s0)
			res = "%" + t
			hasG = false
		case "PBRKPB":
			pg := allTrue
			if hasG {
				pg = gVal
			}
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call <vscale x 16 x i1> @llvm.aarch64.sve.brkpb.z(<vscale x 16 x i1> %s, <vscale x 16 x i1> %s, <vscale x 16 x i1> %s)\n", t, pg, s1, s0)
			res = "%" + t
			hasG = false
		case "PBRKN":
			pg := allTrue
			if hasG {
				pg = gVal
			}
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call <vscale x 16 x i1> @llvm.aarch64.sve.brkn.z(<vscale x 16 x i1> %s, <vscale x 16 x i1> %s, <vscale x 16 x i1> %s)\n", t, pg, s0, s1)
			res = "%" + t
			hasG = false
		case "PPUNPKLO", "PPUNPKHI":
			fn := "punpklo"
			if base == "PPUNPKHI" {
				fn = "punpkhi"
			}
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call <vscale x 8 x i1> @llvm.aarch64.sve.%s(<vscale x 16 x i1> %s)\n", t, fn, s0)
			res = c.sveI1VecToPred("%"+t, 8)
		case "PTRN1", "PTRN2", "PUZP1", "PUZP2", "PZIP1", "PZIP2":
			fn := strings.ToLower(strings.TrimPrefix(base, "P"))
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call <vscale x 16 x i1> @llvm.aarch64.sve.%s.nxv16i1(<vscale x 16 x i1> %s, <vscale x 16 x i1> %s)\n", t, fn, s1, s0)
			res = "%" + t
		}
		if hasG {
			a := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and <vscale x 16 x i1> %s, %s\n", a, res, gVal)
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
		} else {
			return fmt.Errorf("arm64 %s expects P dst: %q", name, ins.Raw)
		}
		if setFlags {
			c.sveSetPredFlags(res)
		}
		return nil

	default:
		return fmt.Errorf("arm64: unsupported SVE predicate instruction %s", name)
	}
}

func sveMemSpec(name string) (isStore, isBcast, isSigned bool, memBits int, ok bool) {
	switch name {
	case "ZLDR":
		return false, false, false, 8, true
	case "ZSTR":
		return true, false, false, 8, true
	case "ZLD1B", "ZLDNT1B":
		return false, false, false, 8, true
	case "ZLD1H", "ZLDNT1H":
		return false, false, false, 16, true
	case "ZLD1W", "ZLDNT1W":
		return false, false, false, 32, true
	case "ZLD1D", "ZLDNT1D":
		return false, false, false, 64, true
	case "ZLD1SB", "ZLDNT1SB":
		return false, false, true, 8, true
	case "ZLD1SH", "ZLDNT1SH":
		return false, false, true, 16, true
	case "ZLD1SW", "ZLDNT1SW":
		return false, false, true, 32, true
	case "ZLD1RB":
		return false, true, false, 8, true
	case "ZLD1RH":
		return false, true, false, 16, true
	case "ZLD1RW":
		return false, true, false, 32, true
	case "ZLD1RD":
		return false, true, false, 64, true
	case "ZLD1RSB":
		return false, true, true, 8, true
	case "ZLD1RSH":
		return false, true, true, 16, true
	case "ZLD1RSW":
		return false, true, true, 32, true
	case "ZST1B", "ZSTNT1B":
		return true, false, false, 8, true
	case "ZST1H", "ZSTNT1H":
		return true, false, false, 16, true
	case "ZST1W", "ZSTNT1W":
		return true, false, false, 32, true
	case "ZST1D", "ZSTNT1D":
		return true, false, false, 64, true
	default:
		return false, false, false, 0, false
	}
}

// 4. Scalable SVE Load/Store/Prefetch.
func (c *arm64Ctx) lowerARM64SVEMem(op asm.Op, ins asm.Instr) error {
	name := string(op)
	if name == "ZPRFB" || name == "ZPRFD" || name == "ZPRFH" || name == "ZPRFW" {
		return nil
	}
	isStore, isBcast, isSigned, memBits, supported := sveMemSpec(name)
	if !supported {
		return fmt.Errorf("arm64: unsupported SVE memory instruction %s", name)
	}
	var zRegs []int
	laneBits := memBits
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
		mem := asm.MemRef{Base: gprArgs[0]}
		if len(gprArgs) > 1 {
			mem.Index = gprArgs[1]
		}
		memOp = asm.Operand{Kind: asm.OpMem, Mem: mem}
		hasMem = true
	}
	if !hasMem && len(zRegs) >= 2 {
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
	if name != "ZLDR" && name != "ZSTR" && pIdx < 0 {
		return fmt.Errorf("arm64 %s requires predicate register P0..P15: %q", name, ins.Raw)
	}
	if name == "ZLDR" || name == "ZSTR" {
		me, err := c.sveEvalMemPtr(memOp, 16)
		if err != nil {
			return err
		}
		ptr := me.ptr
		if isStore {
			srcB, _ := c.loadZIdx(zRegs[0])
			fmt.Fprintf(c.b, "  store <vscale x 16 x i8> %s, ptr %s, align 1\n", srcB, ptr)
			return nil
		}
		ld := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load <vscale x 16 x i8>, ptr %s, align 1\n", ld, ptr)
		return c.storeZIdx(zRegs[0], "%"+ld)
	}
	if laneBits == 128 {
		laneBits = 64
	}
	if laneBits < memBits {
		laneBits = memBits
	}
	baseLanes := 16 / (laneBits / 8)
	// For contiguous widening/narrowing SVE loads and stores (LD1B/H/W/D, ST1B/H/W/D),
	// the MUL VL immediate unit is the number of memory bytes accessed per vector:
	// (baseLanes * vscale) * (memBits / 8). For example, ZLD1B (-VL*2)(R14), P, [Z13.D]
	// has baseLanes=2 and memBits=8, so each VL step is 2*vscale bytes (-4*vscale total),
	// whereas ZLD1B (-VL*2)(R14), P, [Z13.B] has baseLanes=16 -> 16*vscale (-32*vscale).
	memBytesPerVec := int64(baseLanes * (memBits / 8))
	me, err := c.sveEvalMemPtr(memOp, memBytesPerVec)
	if err != nil {
		return err
	}
	ptr := me.ptr
	vecTy := fmt.Sprintf("<vscale x %d x i%d>", baseLanes, laneBits)
	memVecTy := fmt.Sprintf("<vscale x %d x i%d>", baseLanes, memBits)
	predTy := fmt.Sprintf("<vscale x %d x i1>", baseLanes)
	mvec := c.svePredToI1Vec(pIdx, baseLanes)

	extendLoaded := func(loaded string) string {
		if memBits == laneBits {
			return loaded
		}
		extOp := "zext"
		if isSigned {
			extOp = "sext"
		}
		ext := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", ext, extOp, memVecTy, loaded, vecTy)
		return "%" + ext
	}
	truncForStore := func(srcVec string) string {
		if memBits == laneBits {
			return srcVec
		}
		tr := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc %s %s to %s\n", tr, vecTy, srcVec, memVecTy)
		return "%" + tr
	}

	if me.hasZ {
		// Scalable Gather / Scatter using Z vector base or index register.
		// Validate and preserve index extension (UXTW/SXTW) and element shift (<<1/<<2/<<3).
		zMemLB := me.zLaneBits
		if zMemLB == 0 {
			zMemLB = laneBits
		}
		if zMemLB != 32 && zMemLB != 64 {
			return fmt.Errorf("arm64 %s unsupported SVE gather/scatter index width %d: %q", name, zMemLB, ins.Raw)
		}
		if zMemLB != laneBits {
			return fmt.Errorf("arm64 %s gather/scatter index width %d must match data lane width %d: %q", name, zMemLB, laneBits, ins.Raw)
		}
		var maxShift uint
		switch memBits {
		case 8:
			maxShift = 0
		case 16:
			maxShift = 1
		case 32:
			maxShift = 2
		case 64:
			maxShift = 3
		}
		if me.zShift != 0 && me.zShift != maxShift {
			return fmt.Errorf("arm64 %s invalid gather/scatter shift <<%d for %d-bit memory element: %q", name, me.zShift, memBits, ins.Raw)
		}
		if me.zExt != "" && me.zExt != asm.ExtendUXTW && me.zExt != asm.ExtendSXTW {
			return fmt.Errorf("arm64 %s unsupported gather/scatter extension %s: %q", name, me.zExt, ins.Raw)
		}
		zMemRaw, _ := c.loadZIdx(me.zIdx)
		idxFullTy := fmt.Sprintf("<vscale x %d x i%d>", baseLanes, zMemLB)
		ib := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <vscale x 16 x i8> %s to %s\n", ib, zMemRaw, idxFullTy)
		qTy := fmt.Sprintf("<vscale x %d x i64>", baseLanes)
		i64v := "%" + ib
		if zMemLB == 32 {
			extOp := "zext"
			if me.zExt == asm.ExtendSXTW {
				extOp = "sext"
			}
			ex := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = %s %s %%%s to %s\n", ex, extOp, idxFullTy, ib, qTy)
			i64v = "%" + ex
		} else if me.zExt == asm.ExtendUXTW || me.zExt == asm.ExtendSXTW {
			// 64-bit container with 32-bit word extension (.UXTW/.SXTW): truncate to i32 then extend.
			wTy := fmt.Sprintf("<vscale x %d x i32>", baseLanes)
			tr, ex := c.newTmp(), c.newTmp()
			extOp := "zext"
			if me.zExt == asm.ExtendSXTW {
				extOp = "sext"
			}
			fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to %s\n", tr, idxFullTy, ib, wTy)
			fmt.Fprintf(c.b, "  %%%s = %s %s %%%s to %s\n", ex, extOp, wTy, tr, qTy)
			i64v = "%" + ex
		}
		if me.zShift > 0 {
			shAmt := c.sveSplatVal(baseLanes, "i64", fmt.Sprintf("%d", me.zShift))
			sc := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shl %s %s, %s\n", sc, qTy, i64v, shAmt)
			i64v = "%" + sc
		}
		bSplat := c.sveSplatVal(baseLanes, "i64", me.baseAddr)
		addr, ptrs := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add %s %s, %s\n", addr, qTy, bSplat, i64v)
		fmt.Fprintf(c.b, "  %%%s = inttoptr %s %%%s to <vscale x %d x ptr>\n", ptrs, qTy, addr, baseLanes)

		if isStore {
			srcB, _ := c.loadZIdx(zRegs[0])
			sb := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <vscale x 16 x i8> %s to %s\n", sb, srcB, vecTy)
			sv := truncForStore("%" + sb)
			fmt.Fprintf(c.b, "  call void @llvm.masked.scatter.nxv%di%d.nxv%dp0(%s %s, <vscale x %d x ptr> %%%s, i32 1, %s %s)\n",
				baseLanes, memBits, baseLanes, memVecTy, sv, baseLanes, ptrs, predTy, mvec)
			return nil
		}
		g := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.masked.gather.nxv%di%d.nxv%dp0(<vscale x %d x ptr> %%%s, i32 1, %s %s, %s zeroinitializer)\n",
			g, memVecTy, baseLanes, memBits, baseLanes, baseLanes, ptrs, predTy, mvec, memVecTy)
		gv := extendLoaded("%" + g)
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <vscale x 16 x i8>\n", out, vecTy, gv)
		return c.storeZIdx(zRegs[0], "%"+out)
	}

	// Broadcast loads (ZLD1RB/H/W/D/RSB/RSH/RSW): per ARM SVE specification,
	// if no active element exists in the governing predicate, NO memory access
	// occurs and the destination vector is zeroed.
	if isBcast {
		memElemTy := fmt.Sprintf("i%d", memBits)
		elemTy := fmt.Sprintf("i%d", laneBits)
		all16 := c.sveAllTruePred(16)
		elemPred16 := c.sveI1VecToPred(mvec, baseLanes)
		anyActive, m1, ldv, ld := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i1 @llvm.aarch64.sve.ptest.any(<vscale x 16 x i1> %s, <vscale x 16 x i1> %s)\n",
			anyActive, all16, elemPred16)
		fmt.Fprintf(c.b, "  %%%s = insertelement <1 x i1> poison, i1 %%%s, i64 0\n", m1, anyActive)
		fmt.Fprintf(c.b, "  %%%s = call <1 x %s> @llvm.masked.load.v1i%d.p0(ptr %s, i32 1, <1 x i1> %%%s, <1 x %s> zeroinitializer)\n",
			ldv, memElemTy, memBits, ptr, m1, memElemTy)
		fmt.Fprintf(c.b, "  %%%s = extractelement <1 x %s> %%%s, i64 0\n", ld, memElemTy, ldv)
		val := "%" + ld
		if memBits < laneBits {
			extOp := "zext"
			if isSigned {
				extOp = "sext"
			}
			ex := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", ex, extOp, memElemTy, val, elemTy)
			val = "%" + ex
		}
		sp := c.sveSplatVal(baseLanes, elemTy, val)
		sel, out := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select %s %s, %s %s, %s zeroinitializer\n", sel, predTy, mvec, vecTy, sp, vecTy)
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <vscale x 16 x i8>\n", out, vecTy, sel)
		return c.storeZIdx(zRegs[0], "%"+out)
	}

	// Scalable contiguous & multi-vector loads/stores (stepping by runtime memory bytes per vector)
	for ri, zi := range zRegs {
		curPtr := ptr
		if ri > 0 {
			step := c.sveScaledVLBytes(int64(ri), memBytesPerVec)
			gp := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = getelementptr i8, ptr %s, i64 %s\n", gp, ptr, step)
			curPtr = "%" + gp
		}
		if isStore {
			srcB, _ := c.loadZIdx(zi)
			sb := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <vscale x 16 x i8> %s to %s\n", sb, srcB, vecTy)
			sv := truncForStore("%" + sb)
			fmt.Fprintf(c.b, "  call void @llvm.masked.store.nxv%di%d.p0(%s %s, ptr %s, i32 1, %s %s)\n",
				baseLanes, memBits, memVecTy, sv, curPtr, predTy, mvec)
		} else {
			ld := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call %s @llvm.masked.load.nxv%di%d.p0(ptr %s, i32 1, %s %s, %s zeroinitializer)\n",
				ld, memVecTy, baseLanes, memBits, curPtr, predTy, mvec, memVecTy)
			lv := extendLoaded("%" + ld)
			out := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <vscale x 16 x i8>\n", out, vecTy, lv)
			if err := c.storeZIdx(zi, "%"+out); err != nil {
				return err
			}
		}
	}
	return nil
}

// 5. Scalable SVE Vector Compare -> Predicate.
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
	baseLanes := 16 / (laneBits / 8)
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
		fpElem, mangle := "float", fmt.Sprintf("nxv%df32", baseLanes)
		if laneBits == 16 {
			fpElem, mangle = "half", fmt.Sprintf("nxv%df16", baseLanes)
		} else if laneBits == 64 {
			fpElem, mangle = "double", fmt.Sprintf("nxv%df64", baseLanes)
		}
		fpTy := fmt.Sprintf("<vscale x %d x %s>", baseLanes, fpElem)
		ab := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <vscale x 16 x i8> %s to %s\n", ab, aRaw, fpTy)
		lhs := "%" + ab
		rhs := "zeroinitializer"
		if !hasImm && len(vecSrcs) > 1 {
			bb := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <vscale x 16 x i8> %s to %s\n", bb, bRaw, fpTy)
			rhs = "%" + bb
		}
		if name == "ZFACGE" || name == "ZFACGT" {
			la, ra := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call %s @llvm.fabs.%s(%s %s)\n", la, fpTy, mangle, fpTy, lhs)
			fmt.Fprintf(c.b, "  %%%s = call %s @llvm.fabs.%s(%s %s)\n", ra, fpTy, mangle, fpTy, rhs)
			lhs, rhs = "%"+la, "%"+ra
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
		fmt.Fprintf(c.b, "  %%%s = fcmp %s %s %s, %s\n", cmp, pred, fpTy, lhs, rhs)
		cmpVec = "%" + cmp
	} else {
		elemTy := fmt.Sprintf("i%d", laneBits)
		vecTy := fmt.Sprintf("<vscale x %d x %s>", baseLanes, elemTy)
		ab := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <vscale x 16 x i8> %s to %s\n", ab, aRaw, vecTy)
		rhs := "zeroinitializer"
		if hasImm {
			rhs = c.sveSplatVal(baseLanes, elemTy, fmt.Sprintf("%d", immVal))
		} else if len(vecSrcs) > 1 {
			bb := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <vscale x 16 x i8> %s to %s\n", bb, bRaw, vecTy)
			rhs = "%" + bb
		}
		pred := "eq"
		switch {
		case strings.HasSuffix(name, "NE"):
			pred = "ne"
		case strings.HasSuffix(name, "GE"):
			pred = "sge"
		case strings.HasSuffix(name, "GT"):
			pred = "sgt"
		case strings.HasSuffix(name, "LE"):
			pred = "sle"
		case strings.HasSuffix(name, "LT"):
			pred = "slt"
		case strings.HasSuffix(name, "HI"):
			pred = "ugt"
		case strings.HasSuffix(name, "HS"):
			pred = "uge"
		case strings.HasSuffix(name, "LO"):
			pred = "ult"
		case strings.HasSuffix(name, "LS"):
			pred = "ule"
		case name == "ZMATCH" || name == "ZNMATCH":
			return fmt.Errorf("arm64: unsupported SVE match instruction %s", name)
		}
		cmp := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp %s %s %%%s, %s\n", cmp, pred, vecTy, ab, rhs)
		cmpVec = "%" + cmp
	}
	res16 := c.sveI1VecToPred(cmpVec, baseLanes)
	if gIdx >= 0 {
		an := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and <vscale x 16 x i1> %s, %s\n", an, res16, c.loadPIdx(gIdx))
		res16 = "%" + an
	}
	c.storePIdx(dstIdx, res16)
	c.sveSetPredFlags(res16)
	return nil
}

// 6. Scalable SVE Floating-Point ALU / FMA / Convert.
func (c *arm64Ctx) lowerARM64SVEFP(op asm.Op, ins asm.Instr) error {
	name := string(op)
	if len(ins.Args) < 2 {
		return fmt.Errorf("arm64 %s expects >=2 operands: %q", name, ins.Raw)
	}
	dstOp := ins.Args[len(ins.Args)-1]
	dstZ, dstLB, _, dstIsZ := arm64ParseZReg(arm64OpText(dstOp))
	if !dstIsZ {
		return fmt.Errorf("arm64 %s unsupported dst: %q", name, ins.Raw)
	}
	laneBits := dstLB
	if laneBits == 0 {
		laneBits = sveInferLaneBits(ins.Args, name)
	}
	if laneBits != 16 && laneBits != 32 && laneBits != 64 {
		laneBits = 32
	}
	baseLanes := 16 / (laneBits / 8)
	fpElem, mangle := "float", fmt.Sprintf("nxv%df32", baseLanes)
	if laneBits == 16 {
		fpElem, mangle = "half", fmt.Sprintf("nxv%df16", baseLanes)
	} else if laneBits == 64 {
		fpElem, mangle = "double", fmt.Sprintf("nxv%df64", baseLanes)
	}
	fpTy := fmt.Sprintf("<vscale x %d x %s>", baseLanes, fpElem)

	gIdx := -1
	var gMode byte
	var srcs []string
	var srcLBs []int
	for _, a := range ins.Args[:len(ins.Args)-1] {
		if pi, _, mode, ok := arm64ParsePReg(arm64OpText(a)); ok {
			gIdx = pi
			gMode = mode
			continue
		}
		if zi, lb, _, ok := arm64ParseZReg(arm64OpText(a)); ok {
			v, _ := c.loadZIdx(zi)
			srcs = append(srcs, v)
			srcLBs = append(srcLBs, lb)
		}
	}
	if len(srcs) == 0 {
		return fmt.Errorf("arm64 %s missing vector source: %q", name, ins.Raw)
	}
	aRaw := srcs[0]
	bRaw := aRaw
	if len(srcs) > 1 {
		bRaw = srcs[1]
	}
	ab := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <vscale x 16 x i8> %s to %s\n", ab, aRaw, fpTy)
	bb := "%" + ab
	if len(srcs) > 1 {
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <vscale x 16 x i8> %s to %s\n", t, bRaw, fpTy)
		bb = "%" + t
	}

	switch name {
	case "ZSCVTF", "ZUCVTF":
		if len(srcLBs) > 0 && srcLBs[0] != 0 && srcLBs[0] != laneBits {
			return fmt.Errorf("arm64 %s mismatched source/dest lane widths (%d vs %d): %q", name, srcLBs[0], laneBits, ins.Raw)
		}
		intTy := fmt.Sprintf("<vscale x %d x i%d>", baseLanes, laneBits)
		ib, cv, bo := c.newTmp(), c.newTmp(), c.newTmp()
		cvt := "sitofp"
		if name == "ZUCVTF" {
			cvt = "uitofp"
		}
		fmt.Fprintf(c.b, "  %%%s = bitcast <vscale x 16 x i8> %s to %s\n", ib, aRaw, intTy)
		fmt.Fprintf(c.b, "  %%%s = %s %s %%%s to %s\n", cv, cvt, intTy, ib, fpTy)
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <vscale x 16 x i8>\n", bo, fpTy, cv)
		return c.sveStoreVecResult(dstZ, nil, gIdx, gMode, baseLanes, laneBits, "%"+bo)

	case "ZFCVTZS", "ZFCVTZU":
		if len(srcLBs) > 0 && srcLBs[0] != 0 && srcLBs[0] != laneBits {
			return fmt.Errorf("arm64 %s mismatched source/dest lane widths (%d vs %d): %q", name, srcLBs[0], laneBits, ins.Raw)
		}
		intTy := fmt.Sprintf("<vscale x %d x i%d>", baseLanes, laneBits)
		cvt := "fptosi"
		if name == "ZFCVTZU" {
			cvt = "fptoui"
		}
		cv, bo := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s %s %%%s to %s\n", cv, cvt, fpTy, ab, intTy)
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <vscale x 16 x i8>\n", bo, intTy, cv)
		return c.sveStoreVecResult(dstZ, nil, gIdx, gMode, baseLanes, laneBits, "%"+bo)
	}

	var resFP string
	switch name {
	case "ZFSQRT":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.sqrt.%s(%s %%%s)\n", t, fpTy, mangle, fpTy, ab)
		resFP = "%" + t
	case "ZFABS":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.fabs.%s(%s %%%s)\n", t, fpTy, mangle, fpTy, ab)
		resFP = "%" + t
	case "ZFNEG":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fneg %s %%%s\n", t, fpTy, ab)
		resFP = "%" + t
	case "ZFRINTN", "ZFRINTI", "ZFRINTX", "ZFRINTM", "ZFRINTP", "ZFRINTZ", "ZFRINTA":
		fn := "rint"
		switch name {
		case "ZFRINTM":
			fn = "floor"
		case "ZFRINTP":
			fn = "ceil"
		case "ZFRINTZ":
			fn = "trunc"
		case "ZFRINTA":
			fn = "round"
		case "ZFRINTN":
			fn = "roundeven"
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.%s.%s(%s %%%s)\n", t, fpTy, fn, mangle, fpTy, ab)
		resFP = "%" + t
	case "ZFADD":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fadd %s %%%s, %s\n", t, fpTy, ab, bb)
		resFP = "%" + t
	case "ZFSUB":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fsub %s %%%s, %s\n", t, fpTy, ab, bb)
		resFP = "%" + t
	case "ZFMUL":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fmul %s %%%s, %s\n", t, fpTy, ab, bb)
		resFP = "%" + t
	case "ZFDIV":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fdiv %s %%%s, %s\n", t, fpTy, ab, bb)
		resFP = "%" + t
	case "ZFMAX":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.maximum.%s(%s %%%s, %s %s)\n", t, fpTy, mangle, fpTy, ab, fpTy, bb)
		resFP = "%" + t
	case "ZFMAXNM":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.maxnum.%s(%s %%%s, %s %s)\n", t, fpTy, mangle, fpTy, ab, fpTy, bb)
		resFP = "%" + t
	case "ZFMIN":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.minimum.%s(%s %%%s, %s %s)\n", t, fpTy, mangle, fpTy, ab, fpTy, bb)
		resFP = "%" + t
	case "ZFMINNM":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.minnum.%s(%s %%%s, %s %s)\n", t, fpTy, mangle, fpTy, ab, fpTy, bb)
		resFP = "%" + t
	case "ZFMLA", "ZFMLS", "ZFMAD", "ZFMSB":
		oldB, _ := c.loadZIdx(dstZ)
		ob, t := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <vscale x 16 x i8> %s to %s\n", ob, oldB, fpTy)
		mulA, mulB, acc := "%"+ab, bb, "%"+ob
		if name == "ZFMAD" || name == "ZFMSB" {
			mulA, mulB, acc = "%"+ob, "%"+ab, bb
		}
		if name == "ZFMLS" || name == "ZFMSB" {
			neg := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = fneg %s %s\n", neg, fpTy, mulA)
			mulA = "%" + neg
		}
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.fma.%s(%s %s, %s %s, %s %s)\n", t, fpTy, mangle, fpTy, mulA, fpTy, mulB, fpTy, acc)
		resFP = "%" + t
	default:
		return fmt.Errorf("arm64: unsupported SVE floating-point instruction %s", name)
	}
	outB := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <vscale x 16 x i8>\n", outB, fpTy, resFP)
	return c.sveStoreVecResult(dstZ, nil, gIdx, gMode, baseLanes, laneBits, "%"+outB)
}

// 7. Scalable SVE Integer ALU / Shifts / Unary / Select / Moves.
func (c *arm64Ctx) lowerARM64SVEALU(op asm.Op, ins asm.Instr) error {
	name := string(op)
	if len(ins.Args) < 1 {
		return fmt.Errorf("arm64 %s expects >=1 operand: %q", name, ins.Raw)
	}
	dstOp := ins.Args[len(ins.Args)-1]
	dstZ, dstLB, _, dstIsZ := arm64ParseZReg(arm64OpText(dstOp))
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
	if !dstIsZ && len(dstList) == 0 {
		return fmt.Errorf("arm64: unsupported SVE instruction %s", name)
	}

	laneBits := dstLB
	if laneBits == 0 {
		laneBits = sveInferLaneBits(ins.Args, name)
	}
	if laneBits == 0 || laneBits == 128 {
		laneBits = 32
	}
	baseLanes := 16 / (laneBits / 8)
	elemTy := fmt.Sprintf("i%d", laneBits)
	vecTy := fmt.Sprintf("<vscale x %d x %s>", baseLanes, elemTy)

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
		if a.Kind == asm.OpReg {
			if rv, err := c.loadReg(a.Reg); err == nil {
				scalarVal = rv
				hasScalar = true
			}
		}
	}

	// Build primary scalable vector operands (splatting scalar/imm if present).
	var aVec string
	if len(vecSrcs) > 0 {
		ab := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <vscale x 16 x i8> %s to %s\n", ab, vecSrcs[0], vecTy)
		aVec = "%" + ab
	} else if hasScalar {
		sv := scalarVal
		if laneBits < 64 {
			tr := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", tr, sv, elemTy)
			sv = "%" + tr
		}
		aVec = c.sveSplatVal(baseLanes, elemTy, sv)
	} else {
		return fmt.Errorf("arm64 %s missing source operand: %q", name, ins.Raw)
	}
	bVec := aVec
	if len(vecSrcs) > 1 {
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <vscale x 16 x i8> %s to %s\n", t, vecSrcs[1], vecTy)
		bVec = "%" + t
	} else if hasScalar && len(vecSrcs) > 0 {
		sv := scalarVal
		if laneBits < 64 {
			tr := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", tr, sv, elemTy)
			sv = "%" + tr
		}
		bVec = c.sveSplatVal(baseLanes, elemTy, sv)
	}

	var resVec string
	switch name {
	case "ZMOV", "ZDUP", "ZCPY":
		resVec = aVec
	case "ZABS":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.abs.nxv%di%d(%s %s, i1 false)\n", t, vecTy, baseLanes, laneBits, vecTy, aVec)
		resVec = "%" + t
	case "ZNEG":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub %s zeroinitializer, %s\n", t, vecTy, aVec)
		resVec = "%" + t
	case "ZNOT":
		allOnes := c.sveSplatVal(baseLanes, elemTy, "-1")
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor %s %s, %s\n", t, vecTy, aVec, allOnes)
		resVec = "%" + t
	case "ZCNT":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.ctpop.nxv%di%d(%s %s)\n", t, vecTy, baseLanes, laneBits, vecTy, aVec)
		resVec = "%" + t
	case "ZCLZ":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.ctlz.nxv%di%d(%s %s, i1 false)\n", t, vecTy, baseLanes, laneBits, vecTy, aVec)
		resVec = "%" + t
	case "ZRBIT":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.bitreverse.nxv%di%d(%s %s)\n", t, vecTy, baseLanes, laneBits, vecTy, aVec)
		resVec = "%" + t
	case "ZSQADD":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.sadd.sat.nxv%di%d(%s %s, %s %s)\n", t, vecTy, baseLanes, laneBits, vecTy, aVec, vecTy, bVec)
		resVec = "%" + t
	case "ZUQADD":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.uadd.sat.nxv%di%d(%s %s, %s %s)\n", t, vecTy, baseLanes, laneBits, vecTy, aVec, vecTy, bVec)
		resVec = "%" + t
	case "ZSQSUB":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.ssub.sat.nxv%di%d(%s %s, %s %s)\n", t, vecTy, baseLanes, laneBits, vecTy, aVec, vecTy, bVec)
		resVec = "%" + t
	case "ZUQSUB":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.usub.sat.nxv%di%d(%s %s, %s %s)\n", t, vecTy, baseLanes, laneBits, vecTy, aVec, vecTy, bVec)
		resVec = "%" + t
	case "ZSMAX":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.smax.nxv%di%d(%s %s, %s %s)\n", t, vecTy, baseLanes, laneBits, vecTy, aVec, vecTy, bVec)
		resVec = "%" + t
	case "ZSMIN":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.smin.nxv%di%d(%s %s, %s %s)\n", t, vecTy, baseLanes, laneBits, vecTy, aVec, vecTy, bVec)
		resVec = "%" + t
	case "ZUMAX":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.umax.nxv%di%d(%s %s, %s %s)\n", t, vecTy, baseLanes, laneBits, vecTy, aVec, vecTy, bVec)
		resVec = "%" + t
	case "ZUMIN":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.umin.nxv%di%d(%s %s, %s %s)\n", t, vecTy, baseLanes, laneBits, vecTy, aVec, vecTy, bVec)
		resVec = "%" + t
	case "ZAND":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and %s %s, %s\n", t, vecTy, aVec, bVec)
		resVec = "%" + t
	case "ZORR":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or %s %s, %s\n", t, vecTy, aVec, bVec)
		resVec = "%" + t
	case "ZEOR":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor %s %s, %s\n", t, vecTy, aVec, bVec)
		resVec = "%" + t
	case "ZBIC":
		allOnes := c.sveSplatVal(baseLanes, elemTy, "-1")
		n, t := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor %s %s, %s\n", n, vecTy, bVec, allOnes)
		fmt.Fprintf(c.b, "  %%%s = and %s %s, %%%s\n", t, vecTy, aVec, n)
		resVec = "%" + t
	case "ZADD":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add %s %s, %s\n", t, vecTy, aVec, bVec)
		resVec = "%" + t
	case "ZSUB":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub %s %s, %s\n", t, vecTy, aVec, bVec)
		resVec = "%" + t
	case "ZMUL":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = mul %s %s, %s\n", t, vecTy, aVec, bVec)
		resVec = "%" + t
	case "ZLSL":
		mask := c.sveSplatVal(baseLanes, elemTy, fmt.Sprintf("%d", laneBits-1))
		m, t := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and %s %s, %s\n", m, vecTy, bVec, mask)
		fmt.Fprintf(c.b, "  %%%s = shl %s %s, %%%s\n", t, vecTy, aVec, m)
		resVec = "%" + t
	case "ZLSR":
		mask := c.sveSplatVal(baseLanes, elemTy, fmt.Sprintf("%d", laneBits-1))
		m, t := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and %s %s, %s\n", m, vecTy, bVec, mask)
		fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %%%s\n", t, vecTy, aVec, m)
		resVec = "%" + t
	case "ZASR":
		mask := c.sveSplatVal(baseLanes, elemTy, fmt.Sprintf("%d", laneBits-1))
		m, t := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and %s %s, %s\n", m, vecTy, bVec, mask)
		fmt.Fprintf(c.b, "  %%%s = ashr %s %s, %%%s\n", t, vecTy, aVec, m)
		resVec = "%" + t
	case "ZSEL":
		if gIdx < 0 {
			return fmt.Errorf("arm64 ZSEL requires predicate register: %q", ins.Raw)
		}
		mv := c.svePredToI1Vec(gIdx, baseLanes)
		sel := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select <vscale x %d x i1> %s, %s %s, %s %s\n", sel, baseLanes, mv, vecTy, aVec, vecTy, bVec)
		outB := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <vscale x 16 x i8>\n", outB, vecTy, sel)
		return c.sveStoreVecResult(dstZ, dstList, -1, 0, baseLanes, laneBits, "%"+outB)
	default:
		return fmt.Errorf("arm64: unsupported SVE instruction %s", name)
	}
	outB := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <vscale x 16 x i8>\n", outB, vecTy, resVec)
	return c.sveStoreVecResult(dstZ, dstList, gIdx, gMode, baseLanes, laneBits, "%"+outB)
}

func (c *arm64Ctx) sveStoreVecResult(dstZ int, dstList []int, gIdx int, gMode byte, baseLanes, laneBits int, outBytes string) error {
	applyPred := func(targetIdx int) (string, error) {
		if gIdx < 0 {
			return outBytes, nil
		}
		mv := c.svePredToI1Vec(gIdx, baseLanes)
		vecTy := fmt.Sprintf("<vscale x %d x i%d>", baseLanes, laneBits)
		rb := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <vscale x 16 x i8> %s to %s\n", rb, outBytes, vecTy)
		fb := "zeroinitializer"
		if gMode != 'Z' {
			oldB, _ := c.loadZIdx(targetIdx)
			ob := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <vscale x 16 x i8> %s to %s\n", ob, oldB, vecTy)
			fb = "%" + ob
		}
		sel, out := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select <vscale x %d x i1> %s, %s %%%s, %s %s\n", sel, baseLanes, mv, vecTy, rb, vecTy, fb)
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <vscale x 16 x i8>\n", out, vecTy, sel)
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
	v, err := applyPred(dstZ)
	if err != nil {
		return err
	}
	return c.storeZIdx(dstZ, v)
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
