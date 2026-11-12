package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVEPredicatePermuteSpec struct {
	intrinsic string
	inputs    int
	unpack    bool
	rawBase   uint32
}

var arm64SVEPredicatePermuteSpecs = map[Op]arm64SVEPredicatePermuteSpec{
	"PREV":     {intrinsic: "rev", inputs: 1, rawBase: 0x05344000},
	"PTRN1":    {intrinsic: "trn1", inputs: 2, rawBase: 0x05205000},
	"PTRN2":    {intrinsic: "trn2", inputs: 2, rawBase: 0x05205400},
	"PUZP1":    {intrinsic: "uzp1", inputs: 2, rawBase: 0x05204800},
	"PUZP2":    {intrinsic: "uzp2", inputs: 2, rawBase: 0x05204c00},
	"PZIP1":    {intrinsic: "zip1", inputs: 2, rawBase: 0x05204000},
	"PZIP2":    {intrinsic: "zip2", inputs: 2, rawBase: 0x05204400},
	"PPUNPKHI": {intrinsic: "punpkhi", inputs: 1, unpack: true, rawBase: 0x05314000},
	"PPUNPKLO": {intrinsic: "punpklo", inputs: 1, unpack: true, rawBase: 0x05304000},
}

func decodeARM64RawSVEPredicatePermute(word uint32) (Instr, bool) {
	for op, spec := range arm64SVEPredicatePermuteSpecs {
		variableBits := uint32(0x000001ef) // Pn[8:5], Pd[3:0]; bit 4/9 are fixed.
		if !spec.unpack {
			variableBits |= 0x00c00000
		}
		if spec.inputs == 2 {
			variableBits |= 0x000f0000
		}
		if word&^variableBits != spec.rawBase {
			continue
		}
		width := "BHSD"[word>>22&3]
		operand := func(number uint32, arrangement byte) Operand {
			return Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d.%c", number, arrangement))}
		}
		args := []Operand{operand(word>>5&15, width), operand(word&15, width)}
		if spec.unpack {
			args = []Operand{operand(word>>5&15, 'B'), operand(word&15, 'H')}
		} else if spec.inputs == 2 {
			args = append([]Operand{operand(word>>16&15, width)}, args...)
		}
		return Instr{Op: op, Args: args, Raw: fmt.Sprintf("WORD $%#08x", word)}, true
	}
	return Instr{}, false
}

func (c *arm64Ctx) lowerARM64SVEPredicatePermute(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVEPredicatePermuteSpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != spec.inputs+1 {
		return true, false, fmt.Errorf("arm64 %s expects %d source predicate(s) and one destination: %q", op, spec.inputs, ins.Raw)
	}
	first, firstBits, firstOK := arm64ParseSVEPredicateElement(ins.Args[0])
	if !firstOK {
		return true, false, fmt.Errorf("arm64 %s first source is not a Go 1.27 predicate arrangement: %q", op, ins.Raw)
	}
	if spec.unpack {
		destination, destinationBits, destinationOK := arm64ParseSVEPredicateElement(ins.Args[1])
		if firstBits != 8 || !destinationOK || destinationBits != 16 {
			return true, false, fmt.Errorf("arm64 %s only accepts Pn.B, Pd.H: %q", op, ins.Raw)
		}
		return true, false, c.lowerARM64SVEPredicateUnpack(spec, first, destination)
	}
	if spec.inputs == 1 {
		destination, destinationBits, destinationOK := arm64ParseSVEPredicateElement(ins.Args[1])
		if !destinationOK || destinationBits != firstBits {
			return true, false, fmt.Errorf("arm64 %s source and destination arrangements must match: %q", op, ins.Raw)
		}
		return true, false, c.lowerARM64SVEPredicateReverse(first, destination, firstBits)
	}

	second, secondBits, secondOK := arm64ParseSVEPredicateElement(ins.Args[1])
	destination, destinationBits, destinationOK := arm64ParseSVEPredicateElement(ins.Args[2])
	if !secondOK || !destinationOK || firstBits != secondBits || firstBits != destinationBits {
		return true, false, fmt.Errorf("arm64 %s predicate arrangements must all match: %q", op, ins.Raw)
	}
	return true, false, c.lowerARM64SVEPredicatePermuteBinary(spec, first, second, destination, firstBits)
}

func (c *arm64Ctx) lowerARM64SVEPredicateReverse(source, destination, elementBits int) error {
	sourceValue, err := c.loadPReg(source)
	if err != nil {
		return err
	}
	result := c.newTmp()
	if elementBits == 8 {
		fmt.Fprintf(c.b, "  %%%s = call <vscale x 16 x i1> @llvm.vector.reverse.nxv16i1(<vscale x 16 x i1> %s)\n", result, sourceValue)
	} else {
		fmt.Fprintf(c.b, "  %%%s = call <vscale x 16 x i1> @llvm.aarch64.sve.rev.b%d(<vscale x 16 x i1> %s)\n", result, elementBits, sourceValue)
	}
	return c.storePReg(destination, "%"+result)
}

func (c *arm64Ctx) lowerARM64SVEPredicatePermuteBinary(spec arm64SVEPredicatePermuteSpec, plan9First, plan9Second, destination, elementBits int) error {
	firstValue, err := c.loadPReg(plan9Second)
	if err != nil {
		return err
	}
	secondValue, err := c.loadPReg(plan9First)
	if err != nil {
		return err
	}
	intrinsic := spec.intrinsic + ".nxv16i1"
	if elementBits != 8 {
		intrinsic = fmt.Sprintf("%s.b%d", spec.intrinsic, elementBits)
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call <vscale x 16 x i1> @llvm.aarch64.sve.%s(<vscale x 16 x i1> %s, <vscale x 16 x i1> %s)\n", result, intrinsic, firstValue, secondValue)
	return c.storePReg(destination, "%"+result)
}

func (c *arm64Ctx) lowerARM64SVEPredicateUnpack(spec arm64SVEPredicatePermuteSpec, source, destination int) error {
	sourceValue, err := c.loadPReg(source)
	if err != nil {
		return err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call <vscale x 8 x i1> @llvm.aarch64.sve.%s.nxv16i1(<vscale x 16 x i1> %s)\n", result, spec.intrinsic, sourceValue)
	return c.storePRegElements(destination, 16, "%"+result)
}
