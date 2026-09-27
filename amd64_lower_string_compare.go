package plan9asm

import (
	"fmt"
	"strings"
)

type amd64PackedStringCompareSpec struct {
	explicitLength bool
	maskResult     bool
	vector         bool
}

// amd64PackedStringCompareSpecs models Go 1.27's complete SSE4.2 packed-string
// grammar as three independent axes: explicit/implicit lengths, index/mask
// result, and legacy/VEX encoding. Every spelling shares the same imm8 and
// X/m128 operand grammar and the same five architectural flag results.
var amd64PackedStringCompareSpecs = map[Op]amd64PackedStringCompareSpec{
	"PCMPESTRI":  {explicitLength: true},
	"PCMPESTRM":  {explicitLength: true, maskResult: true},
	"PCMPISTRI":  {},
	"PCMPISTRM":  {maskResult: true},
	"VPCMPESTRI": {explicitLength: true, vector: true},
	"VPCMPESTRM": {explicitLength: true, maskResult: true, vector: true},
	"VPCMPISTRI": {vector: true},
	"VPCMPISTRM": {maskResult: true, vector: true},
}

func (c *amd64Ctx) lowerPackedStringCompare(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	spec, recognized := amd64PackedStringCompareSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("%s %s has no suffixed form in Go 1.27: %q", c.goarch, baseOp, ins.Raw)
	}
	minimumImmediate := int64(0)
	if spec.vector {
		// _yvaeskeygenassist has both Yu8 and Yi8 rows, while the legacy
		// yxshuf table has only Yu8.
		minimumImmediate = -128
	}
	if len(ins.Args) != 3 || ins.Args[0].Kind != OpImm || ins.Args[0].Imm < minimumImmediate || ins.Args[0].Imm > 255 {
		return true, false, fmt.Errorf("%s %s immediate is outside its Go 1.27 byte domain, or operands are not imm8, X/m128, X: %q", c.goarch, baseOp, ins.Raw)
	}

	source, destination := ins.Args[1], ins.Args[2]
	if destination.Kind != OpReg || !c.packedStringCompareRegister(spec, destination) {
		return true, false, fmt.Errorf("%s %s destination is outside its Go 1.27 X register class: %q", c.goarch, baseOp, ins.Raw)
	}
	if source.Kind == OpReg {
		if !c.packedStringCompareRegister(spec, source) {
			return true, false, fmt.Errorf("%s %s source is outside its Go 1.27 X register class: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(source) {
		return true, false, fmt.Errorf("%s %s source must be X or m128: %q", c.goarch, baseOp, ins.Raw)
	}
	if !spec.vector && source.Kind == OpMem && !x86MemoryRegistersValidForArch(source.Mem, c.goarch) {
		return true, false, fmt.Errorf("%s %s memory source uses a register outside the legacy address class: %q", c.goarch, baseOp, ins.Raw)
	}

	left, err := c.loadX(destination.Reg)
	if err != nil {
		return true, false, err
	}
	right, err := c.loadPackedCompareBytes(source, 16)
	if err != nil {
		return true, false, err
	}
	lengthLeft, lengthRight := "", ""
	if spec.explicitLength {
		lengthLeft, err = c.evalIntSized(Operand{Kind: OpReg, Reg: AX}, I32)
		if err != nil {
			return true, false, err
		}
		lengthRight, err = c.evalIntSized(Operand{Kind: OpReg, Reg: DX}, I32)
		if err != nil {
			return true, false, err
		}
	}
	imm := uint8(ins.Args[0].Imm)
	stem := "pcmpi"
	if spec.explicitLength {
		stem = "pcmpe"
	}

	if spec.maskResult {
		result := c.emitPackedStringCompareIntrinsic(stem+"strm128", "<16 x i8>", left, right, lengthLeft, lengthRight, imm)
		if err := c.storeX(Reg("X0"), result); err != nil {
			return true, false, err
		}
	} else {
		result := c.emitPackedStringCompareIntrinsic(stem+"stri128", "i32", left, right, lengthLeft, lengthRight, imm)
		extended := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", extended, result)
		if err := c.storeReg(CX, "%"+extended); err != nil {
			return true, false, err
		}
	}

	carry := c.emitPackedStringCompareFlag(stem+"stric128", left, right, lengthLeft, lengthRight, imm)
	overflow := c.emitPackedStringCompareFlag(stem+"strio128", left, right, lengthLeft, lengthRight, imm)
	sign := c.emitPackedStringCompareFlag(stem+"stris128", left, right, lengthLeft, lengthRight, imm)
	zero := c.emitPackedStringCompareFlag(stem+"striz128", left, right, lengthLeft, lengthRight, imm)
	signedLess := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor i1 %s, %s\n", signedLess, sign, overflow)
	fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", carry, c.flagsCFSlot)
	fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", zero, c.flagsZSlot)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", signedLess, c.flagsSltSlot)
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsPFSlot)
	fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", overflow, c.flagsOFSlot)
	return true, false, nil
}

func (c *amd64Ctx) packedStringCompareRegister(spec amd64PackedStringCompareSpec, operand Operand) bool {
	if spec.vector {
		return amd64VEXVectorRegister(operand, 16)
	}
	return operand.Kind == OpReg && c.isGoLegacyXReg(operand.Reg)
}

func (c *amd64Ctx) emitPackedStringCompareIntrinsic(name, resultType, left, right, lengthLeft, lengthRight string, imm uint8) string {
	result := c.newTmp()
	if lengthLeft == "" {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.x86.sse42.%s(<16 x i8> %s, <16 x i8> %s, i8 %d)\n",
			result, resultType, name, left, right, imm)
	} else {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.x86.sse42.%s(<16 x i8> %s, i32 %s, <16 x i8> %s, i32 %s, i8 %d)\n",
			result, resultType, name, left, lengthLeft, right, lengthRight, imm)
	}
	return "%" + result
}

func (c *amd64Ctx) emitPackedStringCompareFlag(name, left, right, lengthLeft, lengthRight string, imm uint8) string {
	result := c.emitPackedStringCompareIntrinsic(name, "i32", left, right, lengthLeft, lengthRight, imm)
	flag := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i32 %s to i1\n", flag, result)
	return "%" + flag
}
