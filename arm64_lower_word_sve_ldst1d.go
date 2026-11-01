package plan9asm

import "fmt"

type arm64RawSVELDST1D struct {
	load           bool
	immediate      int
	registerOffset bool
	index          int
	predicate      int
	base           int
	vector         int
}

// decodeARM64RawSVELDST1D recognizes the SVE contiguous, scalar-base,
// signed-imm4 MUL VL forms of LD1D and ST1D. Other SVE addressing classes are
// deliberately left for their own decoders so an adjacent encoding cannot be
// silently assigned the wrong semantics.
func decodeARM64RawSVELDST1D(word uint32) (arm64RawSVELDST1D, bool) {
	form := arm64RawSVELDST1D{}
	switch word & 0xffe0e000 {
	case 0xa5e04000:
		form.load = true
		form.registerOffset = true
	case 0xe5e04000:
		form.registerOffset = true
	}
	if form.registerOffset {
		form.index = int(word>>16) & 31
		form.predicate = int(word>>10) & 7
		form.base = int(word>>5) & 31
		form.vector = int(word) & 31
		return form, true
	}
	switch word & 0xfff0e000 {
	case 0xa5e0a000:
		form.load = true
	case 0xe5e0e000:
		form.load = false
	default:
		return arm64RawSVELDST1D{}, false
	}
	immediate := int(word>>16) & 15
	if immediate&8 != 0 {
		immediate -= 16
	}
	form.immediate = immediate
	form.predicate = int(word>>10) & 7
	form.base = int(word>>5) & 31
	form.vector = int(word) & 31
	return form, true
}

func (c *arm64Ctx) lowerRawSVELDST1D(form arm64RawSVELDST1D) error {
	predicate, err := c.loadPReg(form.predicate)
	if err != nil {
		return err
	}
	narrowPredicate := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call <vscale x 2 x i1> @llvm.aarch64.sve.convert.from.svbool.nxv2i1(<vscale x 16 x i1> %s)\n", narrowPredicate, predicate)

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
		fmt.Fprintf(c.b, "  %%%s = shl i64 %s, 3\n", scaled, index)
		fmt.Fprintf(c.b, "  %%%s = add i64 %s, %%%s\n", adjusted, base, scaled)
		address = "%" + adjusted
	} else if form.immediate != 0 {
		vscale := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i64 @llvm.vscale.i64()\n", vscale)
		offset := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = mul i64 %%%s, %d\n", offset, vscale, form.immediate*16)
		adjusted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i64 %s, %%%s\n", adjusted, base, offset)
		address = "%" + adjusted
	}
	pointer := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pointer, address)

	if form.load {
		loaded := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call <vscale x 2 x i64> @llvm.masked.load.nxv2i64.p0(ptr align 1 %%%s, <vscale x 2 x i1> %%%s, <vscale x 2 x i64> zeroinitializer)\n", loaded, pointer, narrowPredicate)
		bytes := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <vscale x 2 x i64> %%%s to <vscale x 16 x i8>\n", bytes, loaded)
		return c.storeZReg(form.vector, "%"+bytes)
	}

	bytes, err := c.loadZReg(form.vector)
	if err != nil {
		return err
	}
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <vscale x 16 x i8> %s to <vscale x 2 x i64>\n", value, bytes)
	fmt.Fprintf(c.b, "  call void @llvm.masked.store.nxv2i64.p0(<vscale x 2 x i64> %%%s, ptr align 1 %%%s, <vscale x 2 x i1> %%%s)\n", value, pointer, narrowPredicate)
	return nil
}
