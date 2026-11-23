package plan9asm

import (
	"fmt"
	"strings"
)

// A zero encoding means the operand group is absent. Width is either fixed
// at 64 or selected by the B/H/S/D arrangement.
type arm64SVEPairwiseSpec struct {
	mnemonic         string
	feature          string
	width            int
	unpredicatedWord uint32
	mergingWord      uint32
	intrinsic        bool
}

var arm64SVEPairwiseSpecs = map[Op]arm64SVEPairwiseSpec{
	"ZADDP":    {feature: "+sve2", mergingWord: 0x4411a000, intrinsic: true},
	"ZADDPT":   {mnemonic: "addpt", feature: "+cpa", width: 64, unpredicatedWord: 0x04e00800, mergingWord: 0x04c40000},
	"ZSUBPT":   {mnemonic: "subpt", feature: "+cpa", width: 64, unpredicatedWord: 0x04e00c00, mergingWord: 0x04c50000},
	"ZADDQP":   {mnemonic: "addqp", feature: "+sve2p3", unpredicatedWord: 0x04207800},
	"ZADDSUBP": {mnemonic: "addsubp", feature: "+sve2p3", unpredicatedWord: 0x04207c00},
	"ZSUBP":    {mnemonic: "subp", feature: "+sve2p3", mergingWord: 0x4410a000},
}

// Raw decoding walks the same immutable rows. Their encoding masks are disjoint.
var arm64RawSVEPairwiseSpecs = func() []arm64SVEPairwiseSpec {
	specs := make([]arm64SVEPairwiseSpec, 0, len(arm64SVEPairwiseSpecs))
	for _, spec := range arm64SVEPairwiseSpecs {
		specs = append(specs, spec)
	}
	return specs
}()

type arm64SVEPairwiseForm struct {
	spec        arm64SVEPairwiseSpec
	first       int
	second      int
	destination int
	bits        int
	predicate   int // -1 for the unpredicated operand group.
}

func decodeARM64RawSVEPairwise(word uint32) (arm64SVEPairwiseForm, bool) {
	const unpredicatedRegisters = 0x001f03ff // Zm, Zn, Zd.
	const mergingRegisters = 0x00001fff      // Pg, Zm, Zdn.
	const size = 0x00c00000

	for _, spec := range arm64RawSVEPairwiseSpecs {
		bits, widthMask := spec.width, uint32(0)
		if bits == 0 {
			bits, widthMask = 8<<((word>>22)&3), size
		}
		destination := int(word & 31)
		if spec.unpredicatedWord != 0 && word&^(widthMask|unpredicatedRegisters) == spec.unpredicatedWord {
			return arm64SVEPairwiseForm{
				spec: spec, first: int(word>>5) & 31, second: int(word>>16) & 31,
				destination: destination, bits: bits, predicate: -1,
			}, true
		}
		if spec.mergingWord != 0 && word&^(widthMask|mergingRegisters) == spec.mergingWord {
			return arm64SVEPairwiseForm{
				spec: spec, first: destination, second: int(word>>5) & 31,
				destination: destination, bits: bits, predicate: int(word>>10) & 7,
			}, true
		}
	}
	return arm64SVEPairwiseForm{}, false
}

func (c *arm64Ctx) lowerARM64SVEPairwise(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVEPairwiseSpecs[op]
	if !ok {
		return false, false, nil
	}
	count := len(ins.Args)
	allowed := count == 3 && spec.unpredicatedWord != 0 || count == 4 && spec.mergingWord != 0
	if !allowed || !strings.EqualFold(string(ins.Op), string(op)) {
		return true, false, fmt.Errorf("arm64 %s requires an allowed pairwise operand group without an opcode suffix: %q", op, ins.Raw)
	}

	// Go writes Zm before Zn (or the destructive Zdn).
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
	first, bits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[count-1])
	if !firstOK || !secondOK || !destinationOK || secondBits != bits || destinationBits != bits || spec.width != 0 && spec.width != bits {
		return true, false, fmt.Errorf("arm64 %s requires matching, supported Z register arrangements: %q", op, ins.Raw)
	}
	predicate := -1
	if count == 4 {
		var predicateOK bool
		predicate, predicateOK = arm64ParseSVEPredicateMerge(ins.Args[2])
		if !predicateOK || first != destination {
			return true, false, fmt.Errorf("arm64 %s requires Pg/M and a repeated destructive destination: %q", op, ins.Raw)
		}
	}
	return true, false, c.lowerARM64SVEPairwiseForm(arm64SVEPairwiseForm{
		spec: spec, first: first, second: second, destination: destination,
		bits: bits, predicate: predicate,
	})
}

func (c *arm64Ctx) lowerARM64SVEPairwiseForm(form arm64SVEPairwiseForm) error {
	first, vectorType, err := c.loadZRegElements(form.first, form.bits)
	if err != nil {
		return err
	}
	second, _, err := c.loadZRegElements(form.second, form.bits)
	if err != nil {
		return err
	}

	result := c.newTmp()
	mnemonic := form.spec.mnemonic
	suffix := strings.ToLower(arm64SVEElementLetter(form.bits))
	switch {
	case form.spec.intrinsic:
		predicate, predicateType, err := c.loadPRegElements(form.predicate, form.bits)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.addp.nxv%di%d(%s %s, %s %s, %s %s)\n",
			result, vectorType, 128/form.bits, form.bits, predicateType, predicate, vectorType, first, vectorType, second)
	case form.predicate >= 0:
		predicate, err := c.loadPReg(form.predicate)
		if err != nil {
			return err
		}
		assembly := fmt.Sprintf("%s $0.%s, $3/m, $0.%s, $2.%s", mnemonic, suffix, suffix, suffix)
		fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q(%s %s, %s %s, <vscale x 16 x i1> %s)\n",
			result, vectorType, assembly, "=&w,0,w,@3Upl", vectorType, first, vectorType, second, predicate)
	default:
		assembly := fmt.Sprintf("%s $0.%s, $1.%s, $2.%s", mnemonic, suffix, suffix, suffix)
		fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q(%s %s, %s %s)\n",
			result, vectorType, assembly, "=w,w,w", vectorType, first, vectorType, second)
	}
	return c.storeZRegElements(form.destination, form.bits, "%"+result)
}
