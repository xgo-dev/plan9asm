package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVEAddressGenerationSpec struct {
	elementBits int
	extension   ExtendOp
}

var arm64SVEAddressGenerationForms = [...]arm64SVEAddressGenerationSpec{
	{elementBits: 64, extension: ExtendSXTW},
	{elementBits: 64, extension: ExtendUXTW},
	{elementBits: 32},
	{elementBits: 64},
}

func decodeARM64RawSVEAddressGeneration(word uint32) (Instr, bool) {
	if word&0xff20f000 != 0x0420a000 {
		return Instr{}, false
	}
	spec := arm64SVEAddressGenerationForms[word>>22&3]
	width := byte('D')
	if spec.elementBits == 32 {
		width = 'S'
	}
	reg := func(number uint32) Reg {
		return Reg(fmt.Sprintf("Z%d.%c", number, width))
	}
	return Instr{Op: "ZADR", Raw: fmt.Sprintf("WORD $%#08x", word), Args: []Operand{
		{Kind: OpMem, Mem: MemRef{Base: reg(word >> 5 & 31), Index: reg(word >> 16 & 31),
			IndexExt: spec.extension, Scale: 1 << (word >> 10 & 3)}},
		{Kind: OpReg, Reg: reg(word & 31)},
	}}, true
}

func (c *arm64Ctx) lowerARM64SVEAddressGeneration(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZADR" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 || ins.Args[0].Kind != OpMem {
		return true, false, fmt.Errorf("arm64 ZADR expects one complete Go 1.27 memory-vector form without a suffix: %q", ins.Raw)
	}
	memory := ins.Args[0].Mem
	if memory.Sym != "" || memory.Off != 0 || memory.OffRaw != "" || memory.Base == "" || memory.Index == "" {
		return true, false, fmt.Errorf("arm64 ZADR requires scalable-vector base and index registers: %q", ins.Raw)
	}
	shift, shiftOK := map[int64]int{1: 0, 2: 1, 4: 2, 8: 3}[memory.Scale]
	if !shiftOK {
		return true, false, fmt.Errorf("arm64 ZADR shift amount must be 0..3: %q", ins.Raw)
	}
	base, baseBits, baseOK := arm64ParseSVEZElementReg(Operand{Kind: OpReg, Reg: memory.Base})
	index, indexBits, indexOK := arm64ParseSVEZElementReg(Operand{Kind: OpReg, Reg: memory.Index})
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[1])
	if !baseOK || !indexOK || !destinationOK {
		return true, false, fmt.Errorf("arm64 ZADR operands must be scalable-vector element registers: %q", ins.Raw)
	}
	extended := memory.IndexExt == ExtendSXTW || memory.IndexExt == ExtendUXTW
	valid := false
	for _, spec := range arm64SVEAddressGenerationForms {
		if baseBits == spec.elementBits && memory.IndexExt == spec.extension {
			valid = true
			break
		}
	}
	if !valid || baseBits != indexBits || indexBits != destinationBits {
		return true, false, fmt.Errorf("arm64 ZADR requires matching S/D operands, with UXTW/SXTW only for D elements: %q", ins.Raw)
	}
	baseValue, vectorType, err := c.loadZRegElements(base, baseBits)
	if err != nil {
		return true, false, err
	}
	indexValue, _, err := c.loadZRegElements(index, indexBits)
	if err != nil {
		return true, false, err
	}
	if extended {
		truncated := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc <vscale x 2 x i64> %s to <vscale x 2 x i32>\n", truncated, indexValue)
		extendedValue := c.newTmp()
		extension := "zext"
		if memory.IndexExt == ExtendSXTW {
			extension = "sext"
		}
		fmt.Fprintf(c.b, "  %%%s = %s <vscale x 2 x i32> %%%s to <vscale x 2 x i64>\n", extendedValue, extension, truncated)
		indexValue = "%" + extendedValue
	}
	if shift != 0 {
		scaled := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shl %s %s, splat (i%d %d)\n", scaled, vectorType, indexValue, baseBits, shift)
		indexValue = "%" + scaled
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add %s %s, %s\n", result, vectorType, baseValue, indexValue)
	return true, false, c.storeZRegElements(destination, destinationBits, "%"+result)
}
