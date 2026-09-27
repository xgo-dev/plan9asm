package plan9asm

import "fmt"

func validateARM64CompareNegativeOperands(source, destination Operand, word bool) error {
	if destination.Kind != OpReg || !(isARM64GeneralOrZeroReg(destination.Reg) || destination.Reg == SP || destination.Reg == Reg("RSP")) {
		return fmt.Errorf("destination is outside Go 1.27's C_ZREG/C_RSP classes")
	}
	switch source.Kind {
	case OpImm:
		return nil
	case OpReg:
		if !isARM64GeneralOrZeroReg(source.Reg) {
			return fmt.Errorf("register source is outside Go 1.27's C_ZREG class")
		}
		return nil
	case OpRegShift:
		if !isARM64GeneralOrZeroReg(source.Reg) || source.ShiftReg != "" {
			return fmt.Errorf("shifted source is outside Go 1.27's C_SHIFT class")
		}
		if source.ShiftOp != ShiftLeft && source.ShiftOp != ShiftRight && source.ShiftOp != ShiftArith {
			return fmt.Errorf("shift operator %q is outside Go 1.27's C_SHIFT class", source.ShiftOp)
		}
		maximum := int64(63)
		if word {
			maximum = 31
		}
		if source.ShiftAmount < 0 || source.ShiftAmount > maximum {
			return fmt.Errorf("shift amount %d is outside 0..%d", source.ShiftAmount, maximum)
		}
		return nil
	case OpRegExtend:
		if !isARM64GeneralOrZeroReg(source.Reg) || source.ShiftReg != "" || source.ShiftAmount < 0 || source.ShiftAmount > 4 {
			return fmt.Errorf("extended source is outside Go 1.27's C_EXTREG class")
		}
		switch source.Ext {
		case ExtendUXTB, ExtendUXTH, ExtendUXTW, ExtendSXTB, ExtendSXTH, ExtendSXTW:
			return nil
		case ExtendUXTX, ExtendSXTX:
			if !word {
				return nil
			}
		}
		return fmt.Errorf("extension %q is invalid for the %d-bit form", source.Ext, map[bool]int{true: 32, false: 64}[word])
	default:
		return fmt.Errorf("source is outside Go 1.27's immediate/C_ZREG/C_SHIFT/C_EXTREG classes")
	}
}
