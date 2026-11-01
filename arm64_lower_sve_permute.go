package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
)

type arm64RawSVEPermute struct {
	op          Op
	elementBits int
	quad        bool
	first       int
	second      int
	destination int
}

var arm64SVEPermuteIntrinsics = map[Op]string{
	"ZZIP1":  "zip1",
	"ZZIP2":  "zip2",
	"ZUZP1":  "uzp1",
	"ZUZP2":  "uzp2",
	"ZTRN1":  "trn1",
	"ZTRN2":  "trn2",
	"ZZIPQ1": "zipq1",
	"ZZIPQ2": "zipq2",
	"ZUZPQ1": "uzpq1",
	"ZUZPQ2": "uzpq2",
}

var arm64SVEPermuteOpsByIndex = [...]Op{"ZZIP1", "ZZIP2", "ZUZP1", "ZUZP2", "ZTRN1", "ZTRN2"}
var arm64SVEQPermuteOpsByIndex = [...]Op{"ZZIPQ1", "ZZIPQ2", "ZUZPQ1", "ZUZPQ2"}

func arm64SVEIsQPermuteOp(op Op) bool {
	for _, candidate := range arm64SVEQPermuteOpsByIndex {
		if op == candidate {
			return true
		}
	}
	return false
}

// decodeARM64RawSVEPermute covers the complete ZIP1/2, UZP1/2 and TRN1/2
// family, including the F64MM 128-bit element forms exposed by Go 1.27.
func decodeARM64RawSVEPermute(word uint32) (arm64RawSVEPermute, bool) {
	form := arm64RawSVEPermute{
		first:       int(word>>5) & 31,
		second:      int(word>>16) & 31,
		destination: int(word) & 31,
	}
	selector := int(word>>10) & 7
	switch {
	case word&0xff20e000 == 0x05206000:
		if selector > 5 {
			return arm64RawSVEPermute{}, false
		}
		form.op = arm64SVEPermuteOpsByIndex[selector]
		form.elementBits = 8 << (int(word>>22) & 3)
	case word&0xffe0e000 == 0x05a00000:
		if selector == 4 || selector == 5 {
			return arm64RawSVEPermute{}, false
		}
		if selector >= 6 {
			selector -= 2
		}
		form.op = arm64SVEPermuteOpsByIndex[selector]
		form.elementBits = 128
		form.quad = true
	default:
		return arm64RawSVEPermute{}, false
	}
	return form, true
}

func arm64ParseSVEPermuteReg(operand Operand) (index, elementBits int, ok bool) {
	if index, elementBits, ok := arm64ParseSVEZElementReg(operand); ok {
		return index, elementBits, true
	}
	if operand.Kind != OpReg {
		return 0, 0, false
	}
	parts := strings.Split(strings.ToUpper(strings.TrimSpace(string(operand.Reg))), ".")
	if len(parts) != 2 || parts[1] != "Q" || !strings.HasPrefix(parts[0], "Z") {
		return 0, 0, false
	}
	index, err := strconv.Atoi(strings.TrimPrefix(parts[0], "Z"))
	return index, 128, err == nil && index >= 0 && index < 32
}

func arm64SVEPermuteNeedsF64MM(ins Instr) bool {
	if len(ins.Args) != 3 {
		return false
	}
	_, bits, ok := arm64ParseSVEPermuteReg(ins.Args[2])
	return ok && bits == 128
}

func (c *arm64Ctx) lowerARM64SVEPermute(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if _, ok := arm64SVEPermuteIntrinsics[op]; !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects Zm.T, Zn.T, Zd.T for T=B/H/S/D/Q: %q", op, ins.Raw)
	}
	second, secondBits, secondOK := arm64ParseSVEPermuteReg(ins.Args[0])
	first, firstBits, firstOK := arm64ParseSVEPermuteReg(ins.Args[1])
	destination, destinationBits, destinationOK := arm64ParseSVEPermuteReg(ins.Args[2])
	if !secondOK || !firstOK || !destinationOK || secondBits != firstBits || firstBits != destinationBits {
		return true, false, fmt.Errorf("arm64 %s operands must use one matching B/H/S/D/Q element width: %q", op, ins.Raw)
	}
	if arm64SVEIsQPermuteOp(op) && destinationBits == 128 {
		return true, false, fmt.Errorf("arm64 %s only accepts B/H/S/D element widths: %q", op, ins.Raw)
	}
	return true, false, c.lowerRawSVEPermute(arm64RawSVEPermute{
		op:          op,
		elementBits: firstBits,
		quad:        firstBits == 128,
		first:       first,
		second:      second,
		destination: destination,
	})
}

func (c *arm64Ctx) lowerRawSVEPermute(form arm64RawSVEPermute) error {
	intrinsic, ok := arm64SVEPermuteIntrinsics[form.op]
	if !ok {
		return fmt.Errorf("unsupported ARM64 SVE permute operation %s", form.op)
	}
	representationBits := form.elementBits
	if form.quad {
		representationBits = 64
		intrinsic += "q"
	}
	first, vectorType, err := c.loadZRegElements(form.first, representationBits)
	if err != nil {
		return err
	}
	second, _, err := c.loadZRegElements(form.second, representationBits)
	if err != nil {
		return err
	}
	_, lanes, err := arm64SVEVectorType(representationBits)
	if err != nil {
		return err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s)\n", result, vectorType, intrinsic, lanes, representationBits, vectorType, first, vectorType, second)
	return c.storeZRegElements(form.destination, representationBits, "%"+result)
}
