package plan9asm

import (
	"fmt"
	"strings"
)

var x86CacheLineWritebackOps = map[string]struct{}{
	"CLFLUSH":    {},
	"CLFLUSHOPT": {},
	"CLWB":       {},
}

// lowerCacheLineWriteback covers Go 1.27's complete x86 yclflush operand
// table. All three instructions accept exactly one Ym memory operand on both
// 386 and amd64. Preserve the architectural cache operation as inline
// assembly: replacing it with an ordinary load would lose ordering and
// persistence semantics.
func (c *amd64Ctx) lowerCacheLineWriteback(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	if _, ok := x86CacheLineWritebackOps[baseOp]; !ok {
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("%s %s does not accept instruction suffixes: %q", c.goarch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 1 || !isAMD64MemoryOperand(ins.Args[0]) {
		return true, false, fmt.Errorf("%s %s expects one Go 1.27 Ym memory operand: %q", c.goarch, baseOp, ins.Raw)
	}

	ptr, ptrType, err := c.x86DescriptorMemoryPointer(ins.Args[0])
	if err != nil {
		return true, false, err
	}
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(%s elementtype(i8) %s)\n",
		strings.ToLower(baseOp)+" $0", "*m,~{memory},~{dirflag},~{fpsr},~{flags}", ptrType, ptr)
	return true, false, nil
}
