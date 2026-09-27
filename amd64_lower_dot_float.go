package plan9asm

import (
	"fmt"
	"strings"
)

type amd64PackedFloatingDotForm uint8

const (
	// amd64PackedFloatingDotLegacy is Go's yxshuf table: imm8, X/m128, X.
	amd64PackedFloatingDotLegacy amd64PackedFloatingDotForm = iota
	// amd64PackedFloatingDotVEX128 is Go's _yvdppd table: imm8, X/m128,
	// X, X. The Go 386 frontend cannot represent the four operands.
	amd64PackedFloatingDotVEX128
	// amd64PackedFloatingDotVEX128Or256 is Go's _yvblendpd table, adding
	// the corresponding Y/m256, Y, Y row.
	amd64PackedFloatingDotVEX128Or256
)

type amd64PackedFloatingDotSpec struct {
	form     amd64PackedFloatingDotForm
	laneBits int
}

// amd64PackedFloatingDotSpecs is the complete Go 1.27 grammar for the SSE4.1
// and AVX floating dot-product family. The form class captures operand count,
// legal vector widths, and the 386 frontend restriction; laneBits selects the
// hardware intrinsic and immediate-bit interpretation.
var amd64PackedFloatingDotSpecs = map[Op]amd64PackedFloatingDotSpec{
	"DPPD":  {form: amd64PackedFloatingDotLegacy, laneBits: 64},
	"DPPS":  {form: amd64PackedFloatingDotLegacy, laneBits: 32},
	"VDPPD": {form: amd64PackedFloatingDotVEX128, laneBits: 64},
	"VDPPS": {form: amd64PackedFloatingDotVEX128Or256, laneBits: 32},
}

func (c *amd64Ctx) lowerPackedFloatingDot(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	spec, recognized := amd64PackedFloatingDotSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("%s %s has no suffixed form in Go 1.27: %q", c.goarch, baseOp, ins.Raw)
	}
	if len(ins.Args) == 0 || ins.Args[0].Kind != OpImm || ins.Args[0].Imm < 0 || ins.Args[0].Imm > 255 {
		return true, false, fmt.Errorf("%s %s expects a Yu8 immediate: %q", c.goarch, baseOp, ins.Raw)
	}

	if spec.form == amd64PackedFloatingDotLegacy {
		return c.lowerLegacyPackedFloatingDot(baseOp, spec, ins)
	}
	return c.lowerVEXPackedFloatingDot(baseOp, spec, ins)
}

func (c *amd64Ctx) lowerLegacyPackedFloatingDot(baseOp string, spec amd64PackedFloatingDotSpec, ins Instr) (bool, bool, error) {
	if len(ins.Args) != 3 || !c.isGoVEXVectorRegister(ins.Args[2], 16, false) {
		return true, false, fmt.Errorf("%s %s expects imm8, X/m128, X: %q", c.goarch, baseOp, ins.Raw)
	}
	if !c.isGoVEXVectorRegister(ins.Args[1], 16, true) {
		return true, false, fmt.Errorf("%s %s source must be X/m128: %q", c.goarch, baseOp, ins.Raw)
	}
	if ins.Args[1].Kind == OpMem && !x86MemoryRegistersValidForArch(ins.Args[1].Mem, c.goarch) {
		return true, false, fmt.Errorf("%s %s source uses an out-of-range address register: %q", c.goarch, baseOp, ins.Raw)
	}
	first, err := c.loadPackedFloatingDotOperand(ins.Args[1], 16, spec.laneBits)
	if err != nil {
		return true, false, err
	}
	second, err := c.loadPackedFloatingDotOperand(ins.Args[2], 16, spec.laneBits)
	if err != nil {
		return true, false, err
	}
	result := c.emitPackedFloatingDot(spec, 16, first, second, uint8(ins.Args[0].Imm))
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <16 x i8>\n", out, amd64FMA3LLVMType(128/spec.laneBits, spec.laneBits), result)
	return true, false, c.storeX(ins.Args[2].Reg, "%"+out)
}

func (c *amd64Ctx) lowerVEXPackedFloatingDot(baseOp string, spec amd64PackedFloatingDotSpec, ins Instr) (bool, bool, error) {
	if c.goarch == "386" {
		return true, false, fmt.Errorf("386 %s exceeds the Go assembler frontend's three-operand limit: %q", baseOp, ins.Raw)
	}
	if len(ins.Args) != 4 || ins.Args[3].Kind != OpReg {
		return true, false, fmt.Errorf("amd64 %s expects imm8, source1, source2, destination: %q", baseOp, ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(ins.Args[3].Reg)
	if byteWidth != 16 && (spec.form != amd64PackedFloatingDotVEX128Or256 || byteWidth != 32) {
		return true, false, fmt.Errorf("amd64 %s destination width is absent from its Go 1.27 table: %q", baseOp, ins.Raw)
	}
	if !c.isGoVEXVectorRegister(ins.Args[3], byteWidth, false) || !c.isGoVEXVectorRegister(ins.Args[2], byteWidth, false) {
		return true, false, fmt.Errorf("amd64 %s second source and destination must be matching VEX registers: %q", baseOp, ins.Raw)
	}
	if !c.isGoVEXVectorRegister(ins.Args[1], byteWidth, true) {
		return true, false, fmt.Errorf("amd64 %s first source must be a matching VEX register or memory: %q", baseOp, ins.Raw)
	}
	if ins.Args[1].Kind == OpMem && !x86MemoryRegistersValidForArch(ins.Args[1].Mem, c.goarch) {
		return true, false, fmt.Errorf("amd64 %s source uses an out-of-range address register: %q", baseOp, ins.Raw)
	}
	first, err := c.loadPackedFloatingDotOperand(ins.Args[1], byteWidth, spec.laneBits)
	if err != nil {
		return true, false, err
	}
	second, err := c.loadPackedFloatingDotOperand(ins.Args[2], byteWidth, spec.laneBits)
	if err != nil {
		return true, false, err
	}
	result := c.emitPackedFloatingDot(spec, byteWidth, first, second, uint8(ins.Args[0].Imm))
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <%d x i8>\n", out, amd64FMA3LLVMType(byteWidth*8/spec.laneBits, spec.laneBits), result, byteWidth)
	return true, false, c.storeVectorBytes(ins.Args[3].Reg, byteWidth, "%"+out)
}

func (c *amd64Ctx) loadPackedFloatingDotOperand(operand Operand, byteWidth, laneBits int) (string, error) {
	bytesValue, err := c.loadPackedCompareBytes(operand, byteWidth)
	if err != nil {
		return "", err
	}
	lanes := byteWidth * 8 / laneBits
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to %s\n", result, byteWidth, bytesValue, amd64FMA3LLVMType(lanes, laneBits))
	return "%" + result, nil
}

func (c *amd64Ctx) emitPackedFloatingDot(spec amd64PackedFloatingDotSpec, byteWidth int, first, second string, immediate uint8) string {
	lanes := byteWidth * 8 / spec.laneBits
	typeName := amd64FMA3LLVMType(lanes, spec.laneBits)
	intrinsic := "llvm.x86.sse41.dpps"
	if spec.laneBits == 64 {
		intrinsic = "llvm.x86.sse41.dppd"
	} else if byteWidth == 32 {
		intrinsic = "llvm.x86.avx.dp.ps.256"
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @%s(%s %s, %s %s, i8 %d)\n", result, typeName, intrinsic, typeName, second, typeName, first, immediate)
	return "%" + result
}
