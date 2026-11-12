package plan9asm

import "fmt"

// loadARMRawNEONVector reads a D register or the consecutive D-register pair
// that encodes a Q register and views the bits as an LLVM vector.
func (c *armCtx) loadARMRawNEONVector(first, elementBits int, quad bool, elementType string) (string, int, error) {
	lanes := 64 / elementBits
	low, err := c.loadFReg(armRawVFPBackingReg(first, 64))
	if err != nil {
		return "", 0, err
	}
	bits := low
	totalBits := 64
	if quad {
		lanes *= 2
		totalBits = 128
		high, err := c.loadFReg(armRawVFPBackingReg(first+1, 64))
		if err != nil {
			return "", 0, err
		}
		lowWide := c.newTmp()
		highWide := c.newTmp()
		highShifted := c.newTmp()
		joined := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i64 %s to i128\n", lowWide, low)
		fmt.Fprintf(c.b, "  %%%s = zext i64 %s to i128\n", highWide, high)
		fmt.Fprintf(c.b, "  %%%s = shl i128 %%%s, 64\n", highShifted, highWide)
		fmt.Fprintf(c.b, "  %%%s = or i128 %%%s, %%%s\n", joined, lowWide, highShifted)
		bits = "%" + joined
	}
	vector := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast i%d %s to <%d x %s>\n", vector, totalBits, bits, lanes, elementType)
	return "%" + vector, lanes, nil
}

func (c *armCtx) storeARMRawNEONVector(first, elementBits int, quad bool, elementType, value string) error {
	lanes := 64 / elementBits
	totalBits := 64
	if quad {
		lanes *= 2
		totalBits = 128
	}
	bits := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x %s> %s to i%d\n", bits, lanes, elementType, value, totalBits)
	if !quad {
		return c.storeFReg(armRawVFPBackingReg(first, 64), "%"+bits)
	}
	low := c.newTmp()
	highWide := c.newTmp()
	high := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i128 %%%s to i64\n", low, bits)
	fmt.Fprintf(c.b, "  %%%s = lshr i128 %%%s, 64\n", highWide, bits)
	fmt.Fprintf(c.b, "  %%%s = trunc i128 %%%s to i64\n", high, highWide)
	if err := c.storeFReg(armRawVFPBackingReg(first, 64), "%"+low); err != nil {
		return err
	}
	return c.storeFReg(armRawVFPBackingReg(first+1, 64), "%"+high)
}
