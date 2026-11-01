package plan9asm

import "fmt"

// loadFMOVQFrame reconstructs the 16 contiguous bytes addressed by off(FP)
// from the scalar LLVM fields used to model Go parameters and results.
func (c *arm64Ctx) loadFMOVQFrame(off int64) (string, error) {
	packed, err := c.loadFPFrameBits(off, 16)
	if err != nil {
		return "", err
	}
	vector := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast i128 %s to <16 x i8>\n", vector, packed)
	return "%" + vector, nil
}

// storeFMOVQFrame splits a vector into the scalar LLVM frame slots that cover
// the 16 contiguous bytes addressed by off(FP).
func (c *arm64Ctx) storeFMOVQFrame(off int64, value string) error {
	packed := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to i128\n", packed, value)
	return c.storeFPFrameBits(off, 16, "%"+packed)
}
