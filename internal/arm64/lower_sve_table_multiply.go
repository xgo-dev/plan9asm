package arm64

import (
	"fmt"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

// Both operations use a scalable vector intrinsic. TBL takes the table(s)
// before the indices, whereas UMULLB doubles the result element width.
func (c *arm64Ctx) lowerSVETableOrMultiply(op asm.Op, ins asm.Instr, dest, width int) error {
	bad := func() error { return fmt.Errorf("unsupported %s operands: %s", op, ins.Raw) }
	if len(ins.Args) != 3 || width < 8 || width > 64 {
		return bad()
	}
	index, iw, lane, ok := arm64ParseZReg(arm64OpText(ins.Args[0]))
	if !ok {
		return bad()
	}
	inWidth := width
	fn := "tbl"
	var regs []asm.Reg
	if op == "ZTBL" {
		regs = ins.Args[1].RegList
		if len(regs) < 1 || len(regs) > 2 || lane >= 0 || iw != width {
			return bad()
		}
		if len(regs) == 2 {
			fn = "tbl2"
		}
	} else {
		inWidth = width / 2
		fn = "umullb"
		if iw != inWidth || (lane >= 0 && (inWidth < 16 || lane >= 128/inWidth)) {
			return bad()
		}
		regs = []asm.Reg{asm.Reg(arm64OpText(ins.Args[1]))}
		if lane >= 0 {
			fn += ".lane"
		}
	}
	load := func(r int) string {
		v, _ := c.loadZIdx(r)
		tmp := c.newTmp()
		ty := fmt.Sprintf("<vscale x %d x i%d>", 128/inWidth, inWidth)
		fmt.Fprintf(c.b, "  %%%s = bitcast <vscale x 16 x i8> %s to %s\n", tmp, v, ty)
		return ty + " %" + tmp
	}
	var args []string
	last := -1
	for _, r := range regs {
		num, w, idx, ok := arm64ParseZReg(string(r))
		if !ok || w != inWidth || idx >= 0 || (last >= 0 && num != (last+1)%32) {
			return bad()
		}
		last = num
		args = append(args, load(num))
	}
	args = append(args, load(index))
	if lane >= 0 {
		args = append(args, fmt.Sprintf("i32 %d", lane))
	}
	res, out := c.newTmp(), c.newTmp()
	ty := fmt.Sprintf("<vscale x %d x i%d>", 128/width, width)
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s)\n", res, ty, fn, 128/width, width, strings.Join(args, ", "))
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <vscale x 16 x i8>\n", out, ty, res)
	return c.storeZIdx(dest, "%"+out)
}
