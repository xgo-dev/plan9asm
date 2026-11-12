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
// X/m128 operand grammar and the same six architectural flag results.
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
	spec, recognized, err := amd64PackedStringCompareProperties(op, ins, c.goarch)
	if !recognized || err != nil {
		return recognized, false, err
	}
	source, destination := ins.Args[1], ins.Args[2]
	left, err := c.loadX(destination.Reg)
	if err != nil {
		return true, false, err
	}
	right, err := c.loadPackedStringCompareBytes(source)
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

	output, width, zeroUpper := spec.resultEffect()
	if spec.maskResult {
		result := c.emitPackedStringCompareIntrinsic(stem+"strm128", "<16 x i8>", left, right, lengthLeft, lengthRight, imm)
		if zeroUpper {
			err = c.storePackedMoveOperand(Operand{Kind: OpReg, Reg: output}, width, result)
		} else {
			// The widest shared bank keeps legacy writes limited to low X0.
			err = c.storeX(output, result)
		}
		if err != nil {
			return true, false, err
		}
	} else {
		result := c.emitPackedStringCompareIntrinsic(stem+"stri128", "i32", left, right, lengthLeft, lengthRight, imm)
		extended := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", extended, result)
		if err := c.storeReg(output, "%"+extended); err != nil {
			return true, false, err
		}
	}

	carry := c.emitPackedStringCompareFlag(stem+"stric128", left, right, lengthLeft, lengthRight, imm)
	overflow := c.emitPackedStringCompareFlag(stem+"strio128", left, right, lengthLeft, lengthRight, imm)
	sign := c.emitPackedStringCompareFlag(stem+"stris128", left, right, lengthLeft, lengthRight, imm)
	zero := c.emitPackedStringCompareFlag(stem+"striz128", left, right, lengthLeft, lengthRight, imm)
	fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", carry, c.flagsCFSlot)
	fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", zero, c.flagsZSlot)
	// This slot stores architectural SF. Signed conditions apply SF XOR OF
	// when observing it; precomputing that condition would corrupt PUSHF/LAHF.
	fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", sign, c.flagsSltSlot)
	c.clearX86StatusFlags(x86StatusPF | x86StatusAF)
	fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", overflow, c.flagsOFSlot)
	return true, false, nil
}

// Intel's packed-string exception row permits unaligned m128, but neither
// explicit lengths nor dead results suppress its full observable memory read.
// Logical FP is its existing separate field role; all native addresses use an
// unaligned volatile tuple, without dereferenceability or extent assumptions.
func (c *amd64Ctx) loadPackedStringCompareBytes(source Operand) (string, error) {
	if source.Kind == OpReg || source.Kind == OpFP {
		return c.loadPackedCompareBytes(source, 16)
	}
	pointer, pointerType, _, err := c.packedVectorMemoryPointer(source)
	if err != nil {
		return "", err
	}
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load volatile <16 x i8>, %s %s, align 1\n", value, pointerType, pointer)
	return "%" + value, nil
}

// This descriptor is syntax and architectural effects, not caller definedness
// or address permission. Unregistered source-stack consumers remain Context.
func (spec amd64PackedStringCompareSpec) resultEffect() (Reg, int, bool) {
	if spec.maskResult {
		return "X0", 16, spec.vector
	}
	return CX, 4, false
}

func amd64PackedStringCompareProperties(op Op, ins Instr, goarch string) (amd64PackedStringCompareSpec, bool, error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	spec, recognized := amd64PackedStringCompareSpecs[Op(baseOp)]
	if !recognized {
		return spec, false, nil
	}
	if rawOp != baseOp || goarch != "amd64" && goarch != "386" {
		return spec, true, fmt.Errorf("%s %s has no suffixed or non-x86 form in Go: %q", goarch, baseOp, ins.Raw)
	}
	if ins.Op != "" && strings.ToUpper(string(ins.Op)) != rawOp {
		return spec, true, fmt.Errorf("packed-string dispatch/source opcode mismatch: %s/%s", op, ins.Op)
	}
	minimumImmediate := int64(0)
	if spec.vector {
		// _yvaeskeygenassist has both Yu8 and Yi8 rows, while the legacy
		// yxshuf table has only Yu8.
		minimumImmediate = -128
	}
	if len(ins.Args) != 3 || ins.Args[0].Kind != OpImm || ins.Args[0].ImmIsFloat || ins.Args[0].ImmRaw != "" ||
		ins.Args[0].Imm < minimumImmediate || ins.Args[0].Imm > 255 {
		return spec, true, fmt.Errorf("%s %s immediate is outside its Go byte domain, or operands are not imm8, X/m128, X: %q", goarch, baseOp, ins.Raw)
	}

	source, destination := ins.Args[1], ins.Args[2]
	if destination.Kind != OpReg || !amd64PackedStringCompareRegister(spec, destination, goarch) {
		return spec, true, fmt.Errorf("%s %s destination is outside its Go X register class: %q", goarch, baseOp, ins.Raw)
	}
	if source.Kind == OpReg {
		if !amd64PackedStringCompareRegister(spec, source, goarch) {
			return spec, true, fmt.Errorf("%s %s source is outside its Go X register class: %q", goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(source) {
		return spec, true, fmt.Errorf("%s %s source must be X or m128: %q", goarch, baseOp, ins.Raw)
	}
	if !spec.vector && source.Kind == OpMem && !x86MemoryRegistersValidForArch(source.Mem, goarch) {
		return spec, true, fmt.Errorf("%s %s memory source uses a register outside the legacy address class: %q", goarch, baseOp, ins.Raw)
	}
	ins.Op = op
	return spec, true, x86Mode32VectorRegisterContext(ins, goarch)
}

func amd64PackedStringCompareRegister(spec amd64PackedStringCompareSpec, operand Operand, goarch string) bool {
	if spec.vector {
		return amd64VEXVectorRegister(operand, 16)
	}
	index, valid := amd64ParseXReg(operand.Reg)
	limit := 16
	if goarch == "386" {
		limit = 8
	}
	return operand.Kind == OpReg && valid && index < limit
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
