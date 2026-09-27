package plan9asm

import "fmt"

type arm64RawSVELDST1W struct {
	load           bool
	immediate      int
	registerOffset bool
	index          int
	predicate      int
	base           int
	vector         int
}

// decodeARM64RawSVELDST1W covers the SVE LD1W/ST1W scalar-base forms used by
// generated Go assembly: predicated zero/merge load-store with either a
// signed MUL VL immediate or a scalar register offset scaled by four bytes.
func decodeARM64RawSVELDST1W(word uint32) (arm64RawSVELDST1W, bool) {
	form := arm64RawSVELDST1W{}
	switch word & 0xffe0e000 {
	case 0xa5404000:
		form.load = true
		form.registerOffset = true
	case 0xe5404000:
		form.registerOffset = true
	case 0xa540a000:
		form.load = true
	case 0xe540e000:
	default:
		return arm64RawSVELDST1W{}, false
	}
	form.predicate = int(word>>10) & 7
	form.base = int(word>>5) & 31
	form.vector = int(word) & 31
	if form.registerOffset {
		form.index = int(word>>16) & 31
		return form, true
	}
	form.immediate = int(word>>16) & 15
	if form.immediate&8 != 0 {
		form.immediate -= 16
	}
	return form, true
}

func (c *arm64Ctx) lowerRawSVELDST1W(form arm64RawSVELDST1W) error {
	predicate, err := c.loadPReg(form.predicate)
	if err != nil {
		return err
	}
	narrowPredicate := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call <vscale x 4 x i1> @llvm.aarch64.sve.convert.from.svbool.nxv4i1(<vscale x 16 x i1> %s)\n", narrowPredicate, predicate)

	baseReg := Reg(fmt.Sprintf("R%d", form.base))
	if form.base == 31 {
		baseReg = SP
	}
	base, err := c.loadReg(baseReg)
	if err != nil {
		return err
	}
	address := base
	if form.registerOffset {
		indexReg := ZR
		if form.index != 31 {
			indexReg = Reg(fmt.Sprintf("R%d", form.index))
		}
		index, err := c.loadReg(indexReg)
		if err != nil {
			return err
		}
		scaled := c.newTmp()
		adjusted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shl i64 %s, 2\n", scaled, index)
		fmt.Fprintf(c.b, "  %%%s = add i64 %s, %%%s\n", adjusted, base, scaled)
		address = "%" + adjusted
	} else if form.immediate != 0 {
		vscale := c.newTmp()
		offset := c.newTmp()
		adjusted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i64 @llvm.vscale.i64()\n", vscale)
		fmt.Fprintf(c.b, "  %%%s = mul i64 %%%s, %d\n", offset, vscale, form.immediate*16)
		fmt.Fprintf(c.b, "  %%%s = add i64 %s, %%%s\n", adjusted, base, offset)
		address = "%" + adjusted
	}
	pointer := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pointer, address)
	if form.load {
		loaded := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call <vscale x 4 x i32> @llvm.masked.load.nxv4i32.p0(ptr align 1 %%%s, <vscale x 4 x i1> %%%s, <vscale x 4 x i32> zeroinitializer)\n", loaded, pointer, narrowPredicate)
		bytes := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <vscale x 4 x i32> %%%s to <vscale x 16 x i8>\n", bytes, loaded)
		return c.storeZReg(form.vector, "%"+bytes)
	}
	bytes, err := c.loadZReg(form.vector)
	if err != nil {
		return err
	}
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <vscale x 16 x i8> %s to <vscale x 4 x i32>\n", value, bytes)
	fmt.Fprintf(c.b, "  call void @llvm.masked.store.nxv4i32.p0(<vscale x 4 x i32> %%%s, ptr align 1 %%%s, <vscale x 4 x i1> %%%s)\n", value, pointer, narrowPredicate)
	return nil
}
