package plan9asm

import "fmt"

// Go ABI0 bool fields occupy a whole canonical byte. LLVM's i1 describes the
// logical argument, not byte-addressable storage: writing i1 alone does not
// establish the other seven bits for subsequent assembly byte loads.
func x86FPStorageType(typ LLVMType) LLVMType {
	if typ == I1 {
		return I8
	}
	return typ
}

func (c *amd64Ctx) storeFPStorage(typ LLVMType, value, pointer, alignment, metadata string) {
	if typ == I1 {
		byteValue := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i1 %s to i8\n", byteValue, value)
		value = "%" + byteValue
	}
	fmt.Fprintf(c.b, "  store %s %s, ptr %s%s%s\n", x86FPStorageType(typ), value, pointer, alignment, metadata)
}

func (c *amd64Ctx) loadFPStorage(typ LLVMType, pointer, alignment string) string {
	loaded := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load %s, ptr %s%s\n", loaded, x86FPStorageType(typ), pointer, alignment)
	if typ == I1 {
		logical := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i8 %%%s to i1\n", logical, loaded)
		return "%" + logical
	}
	return "%" + loaded
}
