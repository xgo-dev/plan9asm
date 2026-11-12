package plan9asm

import "fmt"

// The validated form selects a memory format and direction, not a new source
// grammar. Hardware performs the exact ten-byte access, including its faults.
func x87NativeEncodedMnemonic(width byte, store bool) (string, error) {
	switch width {
	case 'B':
		if store {
			return "fbstp", nil
		}
		return "fbld", nil
	case 'X':
		if store {
			return "fstpt", nil
		}
		return "fldt", nil
	}
	return "", fmt.Errorf("unsupported x87 encoded memory width %c", width)
}

func (c *amd64Ctx) loadX87NativeEncoded(source Operand, width byte) (x87Value, error) {
	instruction, err := x87NativeEncodedMnemonic(width, false)
	if err != nil {
		return "", err
	}
	pointer, pointerType, err := c.x87MemoryPointer(source)
	if err != nil {
		return "", err
	}
	if pointerType != "ptr" {
		return "", fmt.Errorf("%w: x87 encoded native memory needs its bound default-address-space pointer", ErrProbeNeedsContext)
	}
	c.emitX87NativeAsm(instruction+" $1; fstpt $0",
		[]x87NativeOperand{{c.x87ValueScratch[0], x87ValueType}},
		[]x87NativeOperand{{pointer, "[10 x i8]"}})
	return c.readX87NativeOutput(0), nil
}

func (c *amd64Ctx) storeX87NativeEncoded(destination Operand, value x87Value, width byte) error {
	instruction, err := x87NativeEncodedMnemonic(width, true)
	if err != nil {
		return err
	}
	pointer, pointerType, err := c.x87MemoryPointer(destination)
	if err != nil {
		return err
	}
	if pointerType != "ptr" {
		return fmt.Errorf("%w: x87 encoded native memory needs its bound default-address-space pointer", ErrProbeNeedsContext)
	}
	input := c.saveX87NativeInput(1, value)
	c.emitX87NativeAsm("fldt $1; "+instruction+" $0",
		[]x87NativeOperand{{pointer, "[10 x i8]"}}, []x87NativeOperand{input})
	return nil
}
