package plan9asm

import (
	"fmt"
	"strings"
)

type x86FP16BinaryForm struct {
	x86FloatBinaryForm
	spec amd64BinaryFloatingSpec
	sae  bool
}

// The twelve raw MAP5 binary members share the existing floating operand
// grammar. MIN/MAX allow SAE, not arithmetic's embedded rounding modes.
func x86FP16BinaryProperties(ins Instr, arch string) (x86FP16BinaryForm, bool, error) {
	base, suffix, dotted := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	spec, known := amd64BinaryFloatingSpecs[Op(base)]
	if !known || !spec.rawOnly || spec.mode == amd64BinaryFloatingSqrt {
		return x86FP16BinaryForm{}, false, nil
	}
	controls, valid := parseAMD64BinaryFloatingSuffix(suffix)
	f := x86FP16BinaryForm{spec: spec, sae: controls.sae}
	fail := func() (x86FP16BinaryForm, bool, error) {
		return f, true, fmt.Errorf("%s %s has invalid raw FP16 binary operands or controls: %q", arch, ins.Op, ins.Raw)
	}
	if !ins.x86Encoded || !valid || dotted && suffix == "" ||
		spec.sae && controls.rounding != "" || !spec.sae && controls.sae {
		return fail()
	}
	shape := ins
	if controls.sae {
		shape.Op = Op(base)
		if controls.zeroing {
			shape.Op += ".Z"
		}
	}
	var err error
	f.x86FloatBinaryForm, err = x86FloatBinaryOperandProperties(shape, arch, 16, false, spec.scalar, false, "FP16 binary")
	if err != nil {
		return f, true, err
	}
	if controls.sae && (ins.Args[0].Kind != OpReg || !spec.scalar && f.byteWidth != 64) {
		return fail()
	}
	if ins.Args[0].Kind == OpMem {
		memory := ins.Args[0].Mem
		if err := x86SymbolIndexedMemoryError(memory, arch); err != nil {
			return f, true, err
		}
		if memory.OffRaw != "" || memory.IndexExt != "" {
			return fail()
		}
	}
	return f, true, x86Mode32VectorRegisterContext(ins, arch)
}

func (c *amd64Ctx) lowerFP16Binary(op Op, ins Instr) (bool, bool, error) {
	local := ins
	local.Op = op
	f, known, err := x86FP16BinaryProperties(local, c.goarch)
	if !known {
		return false, false, nil
	}
	if ins.Op != "" && !strings.EqualFold(string(op), string(ins.Op)) {
		return true, false, fmt.Errorf("FP16 binary dispatch/source opcode mismatch: %s/%s", op, ins.Op)
	}
	if err != nil {
		return true, false, err
	}
	ins = local
	controls := amd64FMA3Suffix{broadcast: f.broadcast, zeroing: f.zeroing, rounding: f.rounding}
	if x86ScalarFloatIntegerNativeTarget(c.goarch, c.targetTriple) {
		lanes := f.byteWidth / 2
		if f.scalar {
			lanes = 1
		}
		return true, false, c.emitNativeFP16ThreeOperand(ins, x86NativeFP16ThreeOperand{
			byteWidth: f.byteWidth, lanes: lanes, memoryBytes: f.memoryBytes,
			second: f.second, destination: f.destination, mask: f.mask,
			controls: controls, sae: f.sae,
		})
	}
	// Keep cross-target numerical values separate from original x86 effects.
	mask := ""
	if f.mask >= 0 {
		mask, err = c.loadK(ins.Args[f.mask].Reg)
		if err != nil {
			return true, false, err
		}
	}
	properties := amd64BinaryFloatingSuffix{
		broadcast: f.broadcast, zeroing: f.zeroing, rounding: f.rounding, sae: f.sae,
	}
	if f.scalar {
		return c.lowerScalarBinaryFloating(f.spec, properties, ins, ins.Args[f.destination], mask)
	}
	return c.lowerPackedBinaryFloating(f.spec, properties, ins, ins.Args[f.destination], f.byteWidth, mask)
}
