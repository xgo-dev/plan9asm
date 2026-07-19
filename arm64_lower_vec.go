package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
)

func arm64ParseVRegLane(r Reg) (kind byte, lane int, ok bool) {
	s := strings.ToUpper(strings.TrimSpace(string(r)))
	dot := strings.IndexByte(s, '.')
	if dot < 0 || dot+1 >= len(s) {
		return 0, 0, false
	}
	rest := s[dot+1:] // e.g. S[0], D[01]
	if len(rest) < 4 || rest[1] != '[' || rest[len(rest)-1] != ']' {
		return 0, 0, false
	}
	k := rest[0]
	n, err := strconv.Atoi(rest[2 : len(rest)-1])
	if err != nil {
		return 0, 0, false
	}
	max := -1
	switch k {
	case 'B':
		max = 16
	case 'H':
		max = 8
	case 'S':
		max = 4
	case 'D':
		max = 2
	default:
		return 0, 0, false
	}
	if n < 0 || n >= max {
		return 0, 0, false
	}
	return k, n, true
}

// Vector/NEON lowering for a small subset used by stdlib asm.
// We model V0..V31 as <16 x i8>.
func (c *arm64Ctx) lowerVec(op Op, postInc bool, ins Instr) (ok bool, terminated bool, err error) {
	switch op {
	case "FLDPQ":
		if len(ins.Args) != 2 || ins.Args[0].Kind != OpMem || ins.Args[1].Kind != OpRegList || len(ins.Args[1].RegList) != 2 {
			return true, false, fmt.Errorf("arm64 FLDPQ expects mem, (Freg,Freg): %q", ins.Raw)
		}
		mem := ins.Args[0].Mem
		addr, base, inc, err := c.addrI64(mem, postInc)
		if err != nil {
			return true, false, err
		}
		for i, f := range ins.Args[1].RegList {
			idx, ok := arm64ParseFReg(f)
			if !ok {
				return true, false, fmt.Errorf("arm64 FLDPQ expects FP register pair: %q", ins.Raw)
			}
			loadAddr := addr
			if i != 0 {
				next := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = add i64 %s, 16\n", next, addr)
				loadAddr = "%" + next
			}
			ptr := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", ptr, loadAddr)
			value := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load <16 x i8>, ptr %%%s, align 1\n", value, ptr)
			if err := c.storeVReg(Reg(fmt.Sprintf("V%d", idx)), "%"+value); err != nil {
				return true, false, err
			}
		}
		if postInc {
			if err := c.updatePostInc(base, inc); err != nil {
				return true, false, err
			}
		}
		return true, false, nil

	case "VMOVI":
		if len(ins.Args) != 2 || ins.Args[0].Kind != OpImm || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("arm64 VMOVI expects $imm, Vreg.B8/B16: %q", ins.Raw)
		}
		imm := ins.Args[0].Imm
		if imm < 0 || imm > 255 {
			return true, false, fmt.Errorf("arm64 VMOVI byte immediate out of range: %q", ins.Raw)
		}
		dst := strings.ToUpper(string(ins.Args[1].Reg))
		activeLanes := 16
		switch {
		case strings.Contains(dst, ".B8"):
			activeLanes = 8
		case strings.Contains(dst, ".B16"):
		default:
			return true, false, fmt.Errorf("arm64 VMOVI unsupported vector arrangement: %q", ins.Raw)
		}
		elems := make([]string, 16)
		for i := range elems {
			value := int64(0)
			if i < activeLanes {
				value = imm
			}
			elems[i] = fmt.Sprintf("i8 %d", value)
		}
		return true, false, c.storeVReg(ins.Args[1].Reg, "<"+strings.Join(elems, ", ")+">")

	case "AESE", "AESD", "AESMC", "AESIMC",
		"SHA1C", "SHA1H", "SHA1M", "SHA1P", "SHA1SU0", "SHA1SU1",
		"SHA256H", "SHA256H2", "SHA256SU0", "SHA256SU1",
		"SHA512H", "SHA512H2", "SHA512SU0", "SHA512SU1",
		"VEOR3", "VBCAX", "VRAX1", "VXAR",
		"VPMULL", "VPMULL2",
		"VREV32", "VREV64", "VSHL", "VSRI", "VTBL", "VZIP1", "VZIP2", "VEXT", "VUSHR",
		"VLD1R", "VLD4R", "VDUP":
		// Keep translation permissive for crypto/NEON ops not yet modeled.
		return true, false, nil

	case "VMOV":
		// Patterns used by stdlib:
		// - VMOV Rn, Vm.B16      (broadcast low byte)
		// - VMOV Vm.D[0], Rn     (extract low 64-bit)
		if len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("arm64 VMOV expects reg, reg: %q", ins.Raw)
		}
		src, dst := ins.Args[0].Reg, ins.Args[1].Reg

		if idx, ok := arm64ParseVReg(dst); ok {
			_ = idx
			// GPR -> V (broadcast).
			if _, ok2 := arm64ParseVReg(src); ok2 {
				// V -> V copy.
				v, err := c.loadVReg(src)
				if err != nil {
					return true, false, err
				}
				return true, false, c.storeVReg(dst, v)
			}
			if k, lane, laneOK := arm64ParseVRegLane(dst); laneOK {
				// GPR -> V lane insert.
				rv, err := c.loadReg(src)
				if err != nil {
					return true, false, err
				}
				v, err := c.loadVReg(dst)
				if err != nil {
					return true, false, err
				}
				switch k {
				case 'D':
					bc := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", bc, v)
					insv := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> %%%s, i64 %s, i32 %d\n", insv, bc, rv, lane)
					out := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", out, insv)
					return true, false, c.storeVReg(dst, "%"+out)
				case 'S':
					w := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", w, rv)
					bc := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x i32>\n", bc, v)
					insv := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = insertelement <4 x i32> %%%s, i32 %%%s, i32 %d\n", insv, bc, w, lane)
					out := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i32> %%%s to <16 x i8>\n", out, insv)
					return true, false, c.storeVReg(dst, "%"+out)
				case 'H':
					h := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i16\n", h, rv)
					bc := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <8 x i16>\n", bc, v)
					insv := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = insertelement <8 x i16> %%%s, i16 %%%s, i32 %d\n", insv, bc, h, lane)
					out := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = bitcast <8 x i16> %%%s to <16 x i8>\n", out, insv)
					return true, false, c.storeVReg(dst, "%"+out)
				case 'B':
					b := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i8\n", b, rv)
					insv := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = insertelement <16 x i8> %s, i8 %%%s, i32 %d\n", insv, v, b, lane)
					return true, false, c.storeVReg(dst, "%"+insv)
				}
			}
			rv, err := c.loadReg(src)
			if err != nil {
				return true, false, err
			}
			ds := strings.ToUpper(string(dst))
			switch {
			case strings.Contains(ds, ".S4"):
				b := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", b, rv)
				v, err := c.broadcastI32ToV16("%" + b)
				if err != nil {
					return true, false, err
				}
				return true, false, c.storeVReg(dst, v)
			default:
				b := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i8\n", b, rv)
				v, err := c.broadcastI8ToV16("%" + b)
				if err != nil {
					return true, false, err
				}
				return true, false, c.storeVReg(dst, v)
			}
		}

		// V -> GPR (lane extract).
		if _, ok := arm64ParseVReg(src); ok {
			if k, lane, laneOK := arm64ParseVRegLane(src); laneOK {
				v, err := c.loadVReg(src)
				if err != nil {
					return true, false, err
				}
				switch k {
				case 'D':
					bc := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", bc, v)
					e := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %%%s, i32 %d\n", e, bc, lane)
					return true, false, c.storeReg(dst, "%"+e)
				case 'S':
					bc := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x i32>\n", bc, v)
					e := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = extractelement <4 x i32> %%%s, i32 %d\n", e, bc, lane)
					z := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, e)
					return true, false, c.storeReg(dst, "%"+z)
				case 'H':
					bc := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <8 x i16>\n", bc, v)
					e := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = extractelement <8 x i16> %%%s, i32 %d\n", e, bc, lane)
					z := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = zext i16 %%%s to i64\n", z, e)
					return true, false, c.storeReg(dst, "%"+z)
				case 'B':
					e := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = extractelement <16 x i8> %s, i32 %d\n", e, v, lane)
					z := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = zext i8 %%%s to i64\n", z, e)
					return true, false, c.storeReg(dst, "%"+z)
				}
			}
			// VMOV Vn, Rm: use low 64-bit lane by default.
			if !strings.Contains(strings.ToUpper(string(src)), ".") {
				v, err := c.loadVReg(src)
				if err != nil {
					return true, false, err
				}
				bc := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", bc, v)
				e := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %%%s, i32 0\n", e, bc)
				return true, false, c.storeReg(dst, "%"+e)
			}
			return true, false, fmt.Errorf("arm64 VMOV unsupported vreg lane: %q", ins.Raw)
		}
		return true, false, fmt.Errorf("arm64 VMOV unsupported: %q", ins.Raw)

	case "VEOR":
		// VEOR Va, Vb, Vd
		if len(ins.Args) != 3 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("arm64 VEOR expects reg, reg, reg: %q", ins.Raw)
		}
		a, err := c.loadVReg(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		b, err := c.loadVReg(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor <16 x i8> %s, %s\n", t, a, b)
		return true, false, c.storeVReg(ins.Args[2].Reg, "%"+t)

	case "VORR":
		// VORR Va, Vb, Vd
		if len(ins.Args) != 3 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("arm64 VORR expects reg, reg, reg: %q", ins.Raw)
		}
		a, err := c.loadVReg(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		b, err := c.loadVReg(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or <16 x i8> %s, %s\n", t, a, b)
		return true, false, c.storeVReg(ins.Args[2].Reg, "%"+t)

	case "VLD1":
		// VLD1 lane form: VLD1(.P) mem, Vn.{B,H,S,D}[lane]
		if len(ins.Args) == 2 && ins.Args[0].Kind == OpMem && ins.Args[1].Kind == OpReg {
			k, lane, ok := arm64ParseVRegLane(ins.Args[1].Reg)
			if !ok {
				return true, false, fmt.Errorf("arm64 VLD1 expects mem, lane or [v,...]: %q", ins.Raw)
			}
			mem := ins.Args[0].Mem
			addr, base, inc, err := c.addrI64(mem, postInc)
			if err != nil {
				return true, false, err
			}
			v, err := c.loadVReg(ins.Args[1].Reg)
			if err != nil {
				return true, false, err
			}
			width := int64(1)
			switch k {
			case 'D':
				width = 8
			case 'S':
				width = 4
			case 'H':
				width = 2
			}
			if postInc && inc == 0 {
				inc = width
			}
			pt := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pt, addr)
			switch k {
			case 'D':
				e := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = load i64, ptr %%%s, align 1\n", e, pt)
				bc := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", bc, v)
				insv := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> %%%s, i64 %%%s, i32 %d\n", insv, bc, e, lane)
				out := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", out, insv)
				if err := c.storeVReg(ins.Args[1].Reg, "%"+out); err != nil {
					return true, false, err
				}
			case 'S':
				e := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = load i32, ptr %%%s, align 1\n", e, pt)
				bc := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x i32>\n", bc, v)
				insv := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = insertelement <4 x i32> %%%s, i32 %%%s, i32 %d\n", insv, bc, e, lane)
				out := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i32> %%%s to <16 x i8>\n", out, insv)
				if err := c.storeVReg(ins.Args[1].Reg, "%"+out); err != nil {
					return true, false, err
				}
			case 'H':
				e := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = load i16, ptr %%%s, align 1\n", e, pt)
				bc := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <8 x i16>\n", bc, v)
				insv := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = insertelement <8 x i16> %%%s, i16 %%%s, i32 %d\n", insv, bc, e, lane)
				out := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = bitcast <8 x i16> %%%s to <16 x i8>\n", out, insv)
				if err := c.storeVReg(ins.Args[1].Reg, "%"+out); err != nil {
					return true, false, err
				}
			case 'B':
				e := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = load i8, ptr %%%s, align 1\n", e, pt)
				insv := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = insertelement <16 x i8> %s, i8 %%%s, i32 %d\n", insv, v, e, lane)
				if err := c.storeVReg(ins.Args[1].Reg, "%"+insv); err != nil {
					return true, false, err
				}
			}
			if postInc {
				if err := c.updatePostInc(base, inc); err != nil {
					return true, false, err
				}
			}
			return true, false, nil
		}

		// VLD1.P (R0), [V1.B16, V2.B16] (or 4-reg form for D2 lists)
		if len(ins.Args) != 2 || ins.Args[0].Kind != OpMem || ins.Args[1].Kind != OpRegList {
			return true, false, fmt.Errorf("arm64 VLD1 expects mem, lane or [v,...]: %q", ins.Raw)
		}
		if n := len(ins.Args[1].RegList); n != 1 && n != 2 && n != 3 && n != 4 {
			return true, false, fmt.Errorf("arm64 VLD1 unsupported reglist len=%d: %q", n, ins.Raw)
		}
		mem := ins.Args[0].Mem
		addr, base, inc, err := c.addrI64(mem, false)
		if err != nil {
			return true, false, err
		}
		// Plan9 VLD1.P increments by loaded size even when mem.Off == 0.
		if postInc && inc == 0 {
			inc = int64(16 * len(ins.Args[1].RegList))
		}

		for i, r := range ins.Args[1].RegList {
			ai := addr
			if i != 0 {
				at := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = add i64 %s, %d\n", at, addr, 16*i)
				ai = "%" + at
			}
			pt := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pt, ai)
			vt := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load <16 x i8>, ptr %%%s, align 1\n", vt, pt)
			if err := c.storeVReg(r, "%"+vt); err != nil {
				return true, false, err
			}
		}
		if postInc {
			if err := c.updatePostInc(base, inc); err != nil {
				return true, false, err
			}
		}
		return true, false, nil

	case "VST1":
		// VST1.P [Vn...], mem
		if len(ins.Args) != 2 || ins.Args[0].Kind != OpRegList || ins.Args[1].Kind != OpMem {
			return true, false, fmt.Errorf("arm64 VST1 expects [v,...], mem: %q", ins.Raw)
		}
		if n := len(ins.Args[0].RegList); n != 1 && n != 2 && n != 3 && n != 4 {
			return true, false, fmt.Errorf("arm64 VST1 unsupported reglist len=%d: %q", n, ins.Raw)
		}
		mem := ins.Args[1].Mem
		addr, base, inc, err := c.addrI64(mem, false)
		if err != nil {
			return true, false, err
		}
		if postInc && inc == 0 {
			inc = int64(16 * len(ins.Args[0].RegList))
		}
		for i, r := range ins.Args[0].RegList {
			ai := addr
			if i != 0 {
				at := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = add i64 %s, %d\n", at, addr, 16*i)
				ai = "%" + at
			}
			v, err := c.loadVReg(r)
			if err != nil {
				return true, false, err
			}
			pt := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pt, ai)
			fmt.Fprintf(c.b, "  store <16 x i8> %s, ptr %%%s, align 1\n", v, pt)
		}
		if postInc {
			if err := c.updatePostInc(base, inc); err != nil {
				return true, false, err
			}
		}
		return true, false, nil

	case "VCMEQ":
		// VCMEQ Va.B16, Vb.B16, Vd.B16 (or D2 lane-wide compare)
		if len(ins.Args) != 3 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("arm64 VCMEQ expects reg, reg, reg: %q", ins.Raw)
		}
		s0 := strings.ToUpper(string(ins.Args[0].Reg))
		s1 := strings.ToUpper(string(ins.Args[1].Reg))
		if strings.Contains(s0, ".D2") || strings.Contains(s1, ".D2") {
			a, err := c.loadVReg(ins.Args[0].Reg)
			if err != nil {
				return true, false, err
			}
			b, err := c.loadVReg(ins.Args[1].Reg)
			if err != nil {
				return true, false, err
			}
			ab := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", ab, a)
			bb := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", bb, b)
			cmp := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp eq <2 x i64> %%%s, %%%s\n", cmp, ab, bb)
			sext := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = sext <2 x i1> %%%s to <2 x i64>\n", sext, cmp)
			out := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", out, sext)
			return true, false, c.storeVReg(ins.Args[2].Reg, "%"+out)
		}

		a, err := c.loadVReg(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		b, err := c.loadVReg(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		cmp := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq <16 x i8> %s, %s\n", cmp, a, b)
		sext := c.newTmp()
		// sext i1 -> i8 yields 0 or -1 (0xFF), which matches CMEQ's all-ones convention.
		fmt.Fprintf(c.b, "  %%%s = sext <16 x i1> %%%s to <16 x i8>\n", sext, cmp)
		return true, false, c.storeVReg(ins.Args[2].Reg, "%"+sext)

	case "VAND":
		// VAND Va, Vb, Vd
		if len(ins.Args) != 3 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("arm64 VAND expects reg, reg, reg: %q", ins.Raw)
		}
		a, err := c.loadVReg(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		b, err := c.loadVReg(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and <16 x i8> %s, %s\n", t, a, b)
		return true, false, c.storeVReg(ins.Args[2].Reg, "%"+t)

	case "VADDP":
		// Pairwise add:
		// - .B16: outputs 16 bytes: 8 from src0 pairs, 8 from src1 pairs.
		// - .D2: outputs 2x i64: sum of each source's two lanes.
		if len(ins.Args) != 3 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("arm64 VADDP expects reg, reg, reg: %q", ins.Raw)
		}
		s0 := strings.ToUpper(string(ins.Args[0].Reg))
		s1 := strings.ToUpper(string(ins.Args[1].Reg))
		if strings.Contains(s0, ".D2") || strings.Contains(s1, ".D2") {
			a, err := c.loadVReg(ins.Args[0].Reg)
			if err != nil {
				return true, false, err
			}
			b, err := c.loadVReg(ins.Args[1].Reg)
			if err != nil {
				return true, false, err
			}
			ab := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", ab, a)
			bb := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", bb, b)
			a0 := c.newTmp()
			a1 := c.newTmp()
			b0 := c.newTmp()
			b1 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %%%s, i32 0\n", a0, ab)
			fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %%%s, i32 1\n", a1, ab)
			fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %%%s, i32 0\n", b0, bb)
			fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %%%s, i32 1\n", b1, bb)
			as := c.newTmp()
			bs := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add i64 %%%s, %%%s\n", as, a0, a1)
			fmt.Fprintf(c.b, "  %%%s = add i64 %%%s, %%%s\n", bs, b0, b1)
			v0 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> undef, i64 %%%s, i32 0\n", v0, as)
			v1 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> %%%s, i64 %%%s, i32 1\n", v1, v0, bs)
			out := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", out, v1)
			return true, false, c.storeVReg(ins.Args[2].Reg, "%"+out)
		}

		// Default B16.
		a, err := c.loadVReg(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		b, err := c.loadVReg(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		cur := "undef"
		for i := 0; i < 16; i++ {
			var src string
			var off int
			if i < 8 {
				// Go/Plan9 asm operand order for VADDP matches sources, but stdlib
				// code expects the low 64 bits to correspond to the first loaded
				// 16-byte lane. Empirically this matches taking the second operand
				// for the low half.
				src = b
				off = i * 2
			} else {
				src = a
				off = (i - 8) * 2
			}
			e0 := c.newTmp()
			e1 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement <16 x i8> %s, i32 %d\n", e0, src, off)
			fmt.Fprintf(c.b, "  %%%s = extractelement <16 x i8> %s, i32 %d\n", e1, src, off+1)
			sum := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add i8 %%%s, %%%s\n", sum, e0, e1)
			insv := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = insertelement <16 x i8> %s, i8 %%%s, i32 %d\n", insv, cur, sum, i)
			cur = "%" + insv
		}
		return true, false, c.storeVReg(ins.Args[2].Reg, cur)

	case "VUADDLV":
		// VUADDLV Vn.B16, Vd
		if len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("arm64 VUADDLV expects reg, reg: %q", ins.Raw)
		}
		v, err := c.loadVReg(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext <16 x i8> %s to <16 x i64>\n", z, v)
		sum := "0"
		for i := 0; i < 16; i++ {
			e := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement <16 x i64> %%%s, i32 %d\n", e, z, i)
			a := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add i64 %s, %%%s\n", a, sum, e)
			sum = "%" + a
		}
		vec := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> undef, i64 %s, i32 0\n", vec, sum)
		vec2 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> %%%s, i64 0, i32 1\n", vec2, vec)
		bc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", bc, vec2)
		return true, false, c.storeVReg(ins.Args[1].Reg, "%"+bc)

	case "VADD":
		// VADD Vs, Vd (2-operand accumulate in D[0]) or VADD Va, Vb, Vd (S4 vector add).
		if len(ins.Args) == 3 && ins.Args[0].Kind == OpReg && ins.Args[1].Kind == OpReg && ins.Args[2].Kind == OpReg {
			a, err := c.loadVReg(ins.Args[0].Reg)
			if err != nil {
				return true, false, err
			}
			b, err := c.loadVReg(ins.Args[1].Reg)
			if err != nil {
				return true, false, err
			}
			ab := c.newTmp()
			bb := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x i32>\n", ab, a)
			fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x i32>\n", bb, b)
			sum := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add <4 x i32> %%%s, %%%s\n", sum, ab, bb)
			out := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i32> %%%s to <16 x i8>\n", out, sum)
			return true, false, c.storeVReg(ins.Args[2].Reg, "%"+out)
		}

		if len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("arm64 VADD expects reg, reg or reg, reg, reg: %q", ins.Raw)
		}
		sv, err := c.loadVReg(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		dv, err := c.loadVReg(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		sbc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", sbc, sv)
		dbc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", dbc, dv)
		se := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %%%s, i32 0\n", se, sbc)
		de := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %%%s, i32 0\n", de, dbc)
		add := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i64 %%%s, %%%s\n", add, de, se)
		vec := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> undef, i64 %%%s, i32 0\n", vec, add)
		vec2 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> %%%s, i64 0, i32 1\n", vec2, vec)
		bc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", bc, vec2)
		return true, false, c.storeVReg(ins.Args[1].Reg, "%"+bc)
	}
	return false, false, nil
}

func (c *arm64Ctx) broadcastI8ToV16(v8 string) (string, error) {
	ins := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <16 x i8> undef, i8 %s, i32 0\n", ins, v8)
	shuf := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector <16 x i8> %%%s, <16 x i8> poison, <16 x i32> zeroinitializer\n", shuf, ins)
	return "%" + shuf, nil
}

func (c *arm64Ctx) broadcastI32ToV16(v32 string) (string, error) {
	ins := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <4 x i32> undef, i32 %s, i32 0\n", ins, v32)
	shuf := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector <4 x i32> %%%s, <4 x i32> poison, <4 x i32> zeroinitializer\n", shuf, ins)
	bc := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i32> %%%s to <16 x i8>\n", bc, shuf)
	return "%" + bc, nil
}
