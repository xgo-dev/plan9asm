package plan9asm

import "fmt"

// This shares exact-width load emission, not source, backing or ABI authority.
func (c *amd64Ctx) evalSizedNativeGPSource(source Operand, typ LLVMType, addressBits int) (string, error) {
	wordBits := 64
	if c.goarch == "386" {
		wordBits = 32
	}
	if source.Kind != OpMem && source.Kind != OpSym {
		return c.evalIntSized(source, typ)
	}
	if addressBits != 0 && addressBits != wordBits && addressBits != wordBits/2 {
		return "", fmt.Errorf("invalid GP read address size %d for %s", addressBits, c.goarch)
	}
	ptr, ptrType, _, err := c.packedVectorMemoryPointer(source)
	if err != nil {
		return "", err
	}
	if source.Kind == OpMem && addressBits != 0 && addressBits != wordBits {
		// Wrap only the effective offset, before the FS/GS hardware base.
		address, wrapped := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ptrtoint %s %s to i%d\n", address, ptrType, ptr, addressBits)
		fmt.Fprintf(c.b, "  %%%s = inttoptr i%d %%%s to %s\n", wrapped, addressBits, address, ptrType)
		ptr = "%" + wrapped
	}
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load volatile %s, %s %s, align 1\n", value, typ, ptrType, ptr)
	return "%" + value, nil
}
