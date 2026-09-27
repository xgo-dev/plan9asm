package plan9asm

import (
	"fmt"
	"strings"
)

type amd64ExplicitMaskMoveSpec struct {
	laneBits int
}

// amd64ExplicitMaskMoveSpecs is Go 1.27's complete _yvmaskmovpd grammar.
// Floating and integer spellings have identical bitwise lane-mask semantics;
// only the lane width differs.
var amd64ExplicitMaskMoveSpecs = map[Op]amd64ExplicitMaskMoveSpec{
	"VMASKMOVPS": {laneBits: 32},
	"VMASKMOVPD": {laneBits: 64},
	"VPMASKMOVD": {laneBits: 32},
	"VPMASKMOVQ": {laneBits: 64},
}

func (c *amd64Ctx) lowerExplicitMaskMove(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	spec, recognized := amd64ExplicitMaskMoveSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("%s %s has no suffixed forms in Go 1.27: %q", c.goarch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 3 {
		return true, false, fmt.Errorf("%s %s expects memory/data, mask, destination/memory: %q", c.goarch, baseOp, ins.Raw)
	}
	load := isAMD64MemoryOperand(ins.Args[0])
	store := isAMD64MemoryOperand(ins.Args[2])
	if load == store {
		return true, false, fmt.Errorf("%s %s requires memory only as its first (load) or last (store) operand: %q", c.goarch, baseOp, ins.Raw)
	}
	maskArg := ins.Args[1]
	if maskArg.Kind != OpReg {
		return true, false, fmt.Errorf("%s %s mask must be an X or Y register: %q", c.goarch, baseOp, ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(maskArg.Reg)
	if byteWidth != 16 && byteWidth != 32 || !amd64VEXVectorRegister(maskArg, byteWidth) {
		return true, false, fmt.Errorf("%s %s mask must be an in-range X or Y register: %q", c.goarch, baseOp, ins.Raw)
	}
	registerArg := ins.Args[2]
	memoryArg := ins.Args[0]
	if store {
		registerArg = ins.Args[0]
		memoryArg = ins.Args[2]
	}
	if !amd64VEXVectorRegister(registerArg, byteWidth) {
		return true, false, fmt.Errorf("%s %s data register must match the mask width: %q", c.goarch, baseOp, ins.Raw)
	}

	lanes := byteWidth * 8 / spec.laneBits
	mask, err := c.loadPackedCompareLanes(maskArg, byteWidth, spec.laneBits, false)
	if err != nil {
		return true, false, err
	}
	predicate := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt <%d x i%d> %s, zeroinitializer\n", predicate, lanes, spec.laneBits, mask)
	pointer, pointerType, intrinsicSuffix, err := c.packedVectorMemoryPointer(memoryArg)
	if err != nil {
		return true, false, err
	}
	intrinsicType := fmt.Sprintf("v%di%d", lanes, spec.laneBits)
	vectorType := fmt.Sprintf("<%d x i%d>", lanes, spec.laneBits)
	if load {
		loaded := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.masked.load.%s%s(%s align 1 %s, <%d x i1> %%%s, %s zeroinitializer)\n",
			loaded, vectorType, intrinsicType, intrinsicSuffix, pointerType, pointer, lanes, predicate, vectorType)
		bytesValue := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <%d x i8>\n", bytesValue, vectorType, loaded, byteWidth)
		return true, false, c.storeVectorBytes(registerArg.Reg, byteWidth, "%"+bytesValue)
	}
	data, err := c.loadPackedCompareLanes(registerArg, byteWidth, spec.laneBits, false)
	if err != nil {
		return true, false, err
	}
	fmt.Fprintf(c.b, "  call void @llvm.masked.store.%s%s(%s %s, %s align 1 %s, <%d x i1> %%%s)\n",
		intrinsicType, intrinsicSuffix, vectorType, data, pointerType, pointer, lanes, predicate)
	return true, false, nil
}
