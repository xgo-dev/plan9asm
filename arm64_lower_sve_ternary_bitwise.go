package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVETernaryBitwiseSpec struct {
	intrinsic string
	rawBase   uint32
}

var arm64SVETernaryBitwiseSpecs = map[Op]arm64SVETernaryBitwiseSpec{
	"ZBCAX":  {"bcax", 0x04603800},
	"ZBSL":   {"bsl", 0x04203c00},
	"ZBSL1N": {"bsl1n", 0x04603c00},
	"ZBSL2N": {"bsl2n", 0x04a03c00},
	"ZEOR3":  {"eor3", 0x04203800},
	"ZNBSL":  {"nbsl", 0x04e03c00},
}

var arm64RawSVETernaryBitwiseOps = func() map[uint32]Op {
	ops := make(map[uint32]Op)
	for op, spec := range arm64SVETernaryBitwiseSpecs {
		ops[spec.rawBase] = op
	}
	return ops
}()

func decodeARM64RawSVETernaryBitwise(word uint32) (Instr, bool) {
	op, ok := arm64RawSVETernaryBitwiseOps[word&0xffe0fc00]
	if !ok {
		return Instr{}, false
	}
	vector := func(index uint32) Operand {
		return Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.D", index&31))}
	}
	return Instr{Op: op, Raw: fmt.Sprintf("WORD $%#08x", word), Args: []Operand{
		vector(word >> 5), vector(word >> 16), vector(word), vector(word),
	}}, true
}

func (c *arm64Ctx) lowerARM64SVETernaryBitwise(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVETernaryBitwiseSpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 4 {
		return true, false, fmt.Errorf("arm64 %s expects Zk.D, Zm.D, Zdn.D, Zdn.D without a suffix: %q", op, ins.Raw)
	}
	third, thirdBits, thirdOK := arm64ParseSVEZElementReg(ins.Args[0])
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[1])
	first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[2])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[3])
	if !thirdOK || !secondOK || !firstOK || !destinationOK || thirdBits != 64 || secondBits != 64 || firstBits != 64 || destinationBits != 64 || first != destination {
		return true, false, fmt.Errorf("arm64 %s requires D-width operands and one destructive destination: %q", op, ins.Raw)
	}
	firstValue, vectorType, err := c.loadZRegElements(first, 64)
	if err != nil {
		return true, false, err
	}
	secondValue, _, err := c.loadZRegElements(second, 64)
	if err != nil {
		return true, false, err
	}
	thirdValue, _, err := c.loadZRegElements(third, 64)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv2i64(%s %s, %s %s, %s %s)\n", result, vectorType, spec.intrinsic, vectorType, firstValue, vectorType, secondValue, vectorType, thirdValue)
	return true, false, c.storeZRegElements(destination, 64, "%"+result)
}
