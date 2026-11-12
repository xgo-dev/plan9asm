package plan9asm

import "fmt"

// Go asm5 types 15/17/99 and their opset aliases admit .S for exactly this
// ordinary multiply family. ARMv5 and newer preserve C/V, setting N/Z from
// the complete 32- or 64-bit result (Arm DUI 0489C sections 3.5.1/3.5.2).
type armBasicMultiplySpec struct {
	width      int
	signed     bool
	accumulate bool
}

var armBasicMultiplySpecs = map[string]armBasicMultiplySpec{
	"MUL":    {width: 32},
	"MULU":   {width: 32},
	"MULA":   {width: 32, accumulate: true},
	"MULL":   {width: 64, signed: true},
	"MULLU":  {width: 64},
	"MULAL":  {width: 64, signed: true, accumulate: true},
	"MULALU": {width: 64, accumulate: true},
}

func (c *armCtx) lowerARMBasicMultiply(op, condition string, setFlags bool, ins Instr) error {
	spec, ok := armBasicMultiplySpecs[op]
	if !ok {
		return fmt.Errorf("ARM multiply has no typed specification: %s", ins.Raw)
	}
	for _, suffix := range armInstructionSuffixes(ins) {
		if suffix != "" && suffix != "S" && !armCondCodes[suffix] {
			return fmt.Errorf("ARM %s suffix %q is absent from Go asm5: %s", op, suffix, ins.Raw)
		}
	}
	want := 3
	if spec.width == 32 && spec.accumulate {
		want = 4
	}
	if len(ins.Args) != want && !(spec.width == 32 && !spec.accumulate && len(ins.Args) == 2) {
		return fmt.Errorf("ARM %s has an invalid register operand count: %s", op, ins.Raw)
	}
	for i, source := range ins.Args {
		if i == len(ins.Args)-1 && spec.width == 64 {
			if source.Kind != OpRegList || len(source.RegList) != 2 || !armRegListAllGPR(source.RegList) {
				return fmt.Errorf("ARM %s requires an (hi,lo) register pair: %s", op, ins.Raw)
			}
		} else if source.Kind != OpReg || !isARMGeneralReg(source.Reg) {
			return fmt.Errorf("ARM %s requires general-register operands: %s", op, ins.Raw)
		}
	}
	return c.emitConditionalEffect(condition, func() error {
		first, err := c.loadReg(ins.Args[0].Reg)
		if err != nil {
			return err
		}
		second, err := c.loadReg(ins.Args[1].Reg)
		if err != nil {
			return err
		}
		if spec.width == 64 {
			extend := func(value string) string {
				if !spec.signed {
					return c.zextI32ToI64(value)
				}
				tmp := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = sext i32 %s to i64\n", tmp, value)
				return "%" + tmp
			}
			first, second = extend(first), extend(second)
		}
		product := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = mul i%d %s, %s\n", product, spec.width, first, second)
		result := "%" + product
		destination := ins.Args[len(ins.Args)-1]
		if spec.accumulate {
			var accumulator string
			if spec.width == 32 {
				accumulator, err = c.loadReg(ins.Args[2].Reg)
			} else {
				hi, loadErr := c.loadReg(destination.RegList[0])
				if loadErr != nil {
					return loadErr
				}
				lo, loadErr := c.loadReg(destination.RegList[1])
				if loadErr != nil {
					return loadErr
				}
				wideHi, wideLo := c.zextI32ToI64(hi), c.zextI32ToI64(lo)
				shifted, combined := c.newTmp(), c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = shl i64 %s, 32\n", shifted, wideHi)
				fmt.Fprintf(c.b, "  %%%s = or i64 %%%s, %s\n", combined, shifted, wideLo)
				accumulator = "%" + combined
			}
			if err != nil {
				return err
			}
			sum := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add i%d %s, %s\n", sum, spec.width, result, accumulator)
			result = "%" + sum
		}
		if spec.width == 32 {
			if err := c.storeReg(destination.Reg, result); err != nil {
				return err
			}
		} else {
			lo, shifted, hi := c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", lo, result)
			fmt.Fprintf(c.b, "  %%%s = lshr i64 %s, 32\n", shifted, result)
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", hi, shifted)
			if err := c.selectRegPairWrite(destination.RegList[0], destination.RegList[1], "", "%"+hi, "%"+lo); err != nil {
				return err
			}
		}
		if setFlags {
			zero, negative := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp eq i%d %s, 0\n", zero, spec.width, result)
			fmt.Fprintf(c.b, "  %%%s = icmp slt i%d %s, 0\n", negative, spec.width, result)
			c.storeFlag(c.flagsZSlot, "%"+zero)
			c.storeFlag(c.flagsNSlot, "%"+negative)
			c.flagsWritten = true
		}
		return nil
	})
}
