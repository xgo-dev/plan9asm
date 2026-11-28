package arm64

import (
	"fmt"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

func (c *arm64Ctx) lowerTableLookup(ins asm.Instr, extend bool) error {
	a := ins.Args
	if len(a) != 3 || a[0].Kind != asm.OpReg || a[1].Kind != asm.OpRegList || len(a[1].RegList) < 1 || len(a[1].RegList) > 4 || a[2].Kind != asm.OpReg {
		return fmt.Errorf("invalid arm64 table lookup: %s", ins.Raw)
	}
	dst := a[2].Reg
	sh := parseNEONShape(dst, false)
	if sh.elemBits != 8 {
		return fmt.Errorf("expected byte table indices: %s", ins.Raw)
	}
	indices, err := c.loadVShape(a[0].Reg, sh)
	if err != nil {
		return err
	}
	out := "zeroinitializer"
	if extend {
		out, err = c.loadVShape(dst, sh)
		if err != nil {
			return err
		}
	}
	var tables []string
	for _, r := range a[1].RegList {
		v, err := c.loadVReg(r)
		if err != nil {
			return err
		}
		tables = append(tables, v)
	}
	for lane := 0; lane < sh.lanes; lane++ {
		idx, low, group, old := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", idx, sh.vecTy(), indices, lane)
		fmt.Fprintf(c.b, "  %%%s = and i8 %%%s, 15\n  %%%s = lshr i8 %%%s, 4\n", low, idx, group, idx)
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", old, sh.vecTy(), out, lane)
		value := "%" + old
		for i, table := range tables {
			item, match, selected := c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement <16 x i8> %s, i8 %%%s\n  %%%s = icmp eq i8 %%%s, %d\n", item, table, low, match, group, i)
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i8 %%%s, i8 %s\n", selected, match, item, value)
			value = "%" + selected
		}
		next := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, i8 %s, i32 %d\n", next, sh.vecTy(), out, value, lane)
		out = "%" + next
	}
	return c.storeVShape(dst, out, sh)
}

func neonShiftShape(dst asm.Reg) neonShape {
	if !strings.Contains(string(dst), ".") {
		return neonShape{lanes: 1, elemBits: 64, half64: true}
	}
	return parseNEONShape(dst, false)
}

func (c *arm64Ctx) lowerVecImmediate(op asm.Op, ins asm.Instr) error {
	args := ins.Args
	if len(args) < 2 || args[len(args)-1].Kind != asm.OpReg {
		return fmt.Errorf("invalid arm64 vector operands: %s", ins.Raw)
	}
	dst := args[len(args)-1].Reg
	sh := parseNEONShape(dst, false)
	if op == "VSRI" || op == "VSHL" || op == "VUSHR" {
		sh = neonShiftShape(dst)
	}
	if op == "VDUP" {
		if len(args) != 2 || args[0].Kind != asm.OpReg {
			return fmt.Errorf("invalid VDUP: %s", ins.Raw)
		}
		var elem string
		if k, lane, ok := arm64ParseVRegLane(args[0].Reg); ok {
			ty := map[byte]int{'B': 8, 'H': 16, 'S': 32, 'D': 64}[k]
			scalar := !strings.Contains(string(dst), ".")
			if !scalar && ty != sh.elemBits {
				return fmt.Errorf("incompatible VDUP sizes: %s", ins.Raw)
			}
			vecShape := neonShape{lanes: 128 / ty, elemBits: ty}
			v, err := c.loadVShape(args[0].Reg, vecShape)
			if err != nil {
				return err
			}
			bit := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", bit, vecShape.vecTy(), v, lane)
			elem = "%" + bit
			if scalar {
				t := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = insertelement %s zeroinitializer, %s %s, i32 0\n", t, vecShape.vecTy(), vecShape.elemTy(), elem)
				return c.storeVShape(dst, "%"+t, vecShape)
			}
		} else {
			v, err := c.loadReg(args[0].Reg)
			if err != nil {
				return err
			}
			elem = v
			if sh.elemBits < 64 {
				t := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", t, v, sh.elemTy())
				elem = "%" + t
			}
		}
		i, b := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement %s poison, %s %s, i32 0\n", i, sh.vecTy(), sh.elemTy(), elem)
		fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s poison, <%d x i32> zeroinitializer\n", b, sh.vecTy(), i, sh.vecTy(), sh.lanes)
		return c.storeVShape(dst, "%"+b, sh)
	}
	if args[0].Kind != asm.OpImm || args[0].ImmRaw != "" || args[1].Kind != asm.OpReg {
		return fmt.Errorf("invalid arm64 vector immediate: %s", ins.Raw)
	}
	n := args[0].Imm
	if op == "VEXT" {
		if len(args) != 4 || args[2].Kind != asm.OpReg || sh.elemBits != 8 || n < 0 || n >= int64(sh.lanes) {
			return fmt.Errorf("invalid VEXT: %s", ins.Raw)
		}
		left, err := c.loadVShape(args[2].Reg, sh)
		if err != nil {
			return err
		}
		right, err := c.loadVShape(args[1].Reg, sh)
		if err != nil {
			return err
		}
		var mask []string
		for i := 0; i < sh.lanes; i++ {
			mask = append(mask, fmt.Sprintf("i32 %d", int(n)+i))
		}
		v := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector %s %s, %s %s, <%d x i32> <%s>\n", v, sh.vecTy(), left, sh.vecTy(), right, sh.lanes, strings.Join(mask, ", "))
		return c.storeVShape(dst, "%"+v, sh)
	}
	width := int64(sh.elemBits)
	if len(args) != 3 || n < 0 || n > width || (op == "VSHL" && n == width) || (op != "VSHL" && n == 0) {
		return fmt.Errorf("invalid %s immediate width: %s", op, ins.Raw)
	}
	if n == width {
		if op == "VSRI" {
			v, err := c.loadVShape(dst, sh)
			if err != nil {
				return err
			}
			return c.storeVShape(dst, v, sh)
		}
		return c.storeVShape(dst, "zeroinitializer", sh)
	}
	v, err := c.loadVShape(args[1].Reg, sh)
	if err != nil {
		return err
	}
	operator := "lshr"
	if op == "VSHL" {
		operator = "shl"
	}
	res := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s %s %s, %s\n", res, operator, sh.vecTy(), v, neonSplatInt(sh, n))
	if op == "VSRI" {
		d, err := c.loadVShape(dst, sh)
		if err != nil {
			return err
		}
		high, merged := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and %s %s, %s\n  %%%s = or %s %%%s, %%%s\n", high, sh.vecTy(), d, neonSplatInt(sh, -1<<(width-n)), merged, sh.vecTy(), high, res)
		res = merged
	}
	return c.storeVShape(dst, "%"+res, sh)
}
