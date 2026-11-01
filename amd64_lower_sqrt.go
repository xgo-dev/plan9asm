package plan9asm

import (
	"fmt"
	"strings"
)

func (c *amd64Ctx) lowerSqrt(op Op, ins Instr) (bool, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	if _, known := x86SqrtSpecFor(Op(base)); !known {
		return false, false, nil
	}
	if ins.Op != "" && !strings.EqualFold(string(op), string(ins.Op)) {
		return true, false, fmt.Errorf("sqrt dispatch/source opcode mismatch: %s/%s", op, ins.Op)
	}
	ins.Op = op
	f, _, err := x86SqrtProperties(ins, c.goarch)
	if err != nil {
		return true, false, err
	}
	if f.bits == 16 && !x86ScalarFloatIntegerNativeTarget(c.goarch, c.targetTriple) {
		return false, false, nil // Retain the existing cross-target numerical model.
	}
	if f.bits == 16 && f.scalar {
		return true, false, c.emitNativeFP16ThreeOperand(ins, x86NativeFP16ThreeOperand{
			byteWidth: 16, lanes: 1, memoryBytes: f.memoryBytes, second: f.second,
			destination: f.destination, mask: f.mask,
			controls: amd64FMA3Suffix{zeroing: f.zeroing, rounding: f.rounding},
		})
	}
	if f.scalar {
		return true, false, c.lowerScalarSqrt(ins, f)
	}
	if ins.Args[0].Kind == OpFP || ins.x86AddressBits != 0 || f.memory >= 0 &&
		ins.Args[0].Kind == OpMem && !x86OrdinaryNativeMemoryOperand(ins.Args[0], c.goarch) {
		return true, false, fmt.Errorf("%w: %s packed source lacks its original native memory binding", ErrProbeNeedsContext, op)
	}
	carrierBits := f.bits
	if carrierBits == 16 {
		carrierBits = 32 // Register bit carrier, not an arithmetic precision change.
	}
	return true, false, c.emitNativePackedConversion(ins, x86NativePackedConversion{
		byteWidth: f.byteWidth, sourceBytes: f.byteWidth, memoryBytes: f.memoryBytes,
		outputBits: carrierBits, destination: f.destination, mask: f.mask, lanes: f.byteWidth * 8 / f.bits,
		legacy: f.legacy, evex: x86SqrtNativeEVEX(ins, f), broadcast: f.broadcast, zeroing: f.zeroing,
		rounding: f.rounding, mnemonic: strings.ToLower(base),
	})
}

// Retain the actual scalar opcode even for dead results: default rounding,
// DAZ/FTZ, exceptions and explicit ER+SAE are not pure llvm.sqrt semantics.
// Masked source reads use the existing exact-width conditional load; the
// native mask separately suppresses inactive arithmetic and its exceptions.
func (c *amd64Ctx) lowerScalarSqrt(ins Instr, f x86FloatBinaryForm) error {
	mask := ""
	var err error
	if f.mask >= 0 {
		mask, err = c.loadK(ins.Args[f.mask].Reg)
		if err != nil {
			return err
		}
	}
	source, err := c.loadFloatBinaryScalar(ins.Args[0], f.bits, mask)
	if err != nil {
		return err
	}
	typ := amd64FloatingVectorType(128/f.bits, f.bits)
	load := func(index int) (string, error) {
		bytes, err := c.loadX(ins.Args[index].Reg)
		if err != nil {
			return "", err
		}
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to %s\n", value, bytes, typ)
		return "%" + value, nil
	}
	old := "zeroinitializer"
	if f.legacy || mask != "" && !f.zeroing {
		old, err = load(f.destination)
		if err != nil {
			return err
		}
	}
	registerClass := "x"
	if x86SqrtNativeEVEX(ins, f) {
		registerClass = "v"
	}
	constraints := "=" + registerClass + ",0," + registerClass
	args := fmt.Sprintf("%s %s, %s %s", typ, old, amd64FMA3LLVMType(1, f.bits), source)
	operands, maskIndex := "$2, $0", 3
	if !f.legacy {
		upper, err := load(f.second)
		if err != nil {
			return err
		}
		constraints += "," + registerClass
		args += ", " + typ + " " + upper
		operands, maskIndex = "$2, $3, $0", 4
	}
	mnemonic, _, _ := strings.Cut(strings.ToLower(string(ins.Op)), ".")
	if x86SqrtNativeEVEX(ins, f) {
		mnemonic = "{evex} " + mnemonic
	}
	assembly := mnemonic + " "
	if f.rounding != "" {
		assembly += "{" + strings.ToLower(strings.TrimSuffix(f.rounding, "_SAE")) + "-sae}, "
	}
	assembly += operands
	if mask != "" {
		assembly = fmt.Sprintf("kmovw ${%d:k}, %%k1; ", maskIndex) + assembly + " {%k1}"
		if f.zeroing {
			assembly += " {z}"
		}
		constraints += ",r,~{k1}"
		args += ", i32 " + c.approximateMathMask32(mask)
	}
	result, bytes := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q(%s)\n", result, typ, assembly, constraints+",~{memory},~{fpsr}", args)
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", bytes, typ, result)
	if f.legacy {
		return c.storeLegacyXViews(ins.Args[f.destination].Reg, "%"+bytes)
	}
	return c.storePackedMoveOperand(ins.Args[f.destination], 16, "%"+bytes)
}
