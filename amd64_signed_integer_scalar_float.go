package plan9asm

import (
	"fmt"
	"strings"
)

type x86SignedIntegerFloatSpec struct {
	sourceBits, resultBits int
	legacy, rounding       bool
}

// Go's complete yxcvlf/yxcvqf and signed _yvcvtsi2sdl family. The
// unsigned, packed, and float-to-integer families have separate contracts.
var x86SignedIntegerFloatSpecs = map[Op]x86SignedIntegerFloatSpec{
	"CVTSL2SS": {32, 32, true, false}, "CVTSL2SD": {32, 64, true, false},
	"CVTSQ2SS": {64, 32, true, false}, "CVTSQ2SD": {64, 64, true, false},
	"VCVTSI2SSL": {32, 32, false, true}, "VCVTSI2SDL": {32, 64, false, false},
	"VCVTSI2SSQ": {64, 32, false, true}, "VCVTSI2SDQ": {64, 64, false, true},
}

type x86SignedIntegerFloatForm struct {
	spec                                   x86SignedIntegerFloatSpec
	sourceBits, upper, destination, memory int
	rounding                               string
}

func x86SignedIntegerFloatProperties(ins Instr, goarch string) (x86SignedIntegerFloatForm, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	spec, recognized := x86SignedIntegerFloatSpecs[Op(base)]
	if !recognized {
		return x86SignedIntegerFloatForm{}, false, nil
	}
	return x86IntegerScalarFloatOperandProperties(ins, goarch, spec)
}

// The signed and unsigned families share operand axes, not arithmetic,
// native generation or source/caller permissions.
func x86IntegerScalarFloatOperandProperties(ins Instr, goarch string, spec x86SignedIntegerFloatSpec) (x86SignedIntegerFloatForm, bool, error) {
	_, suffix, dotted := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	f := x86SignedIntegerFloatForm{spec: spec, sourceBits: spec.sourceBits, upper: 1, destination: len(ins.Args) - 1, memory: -1}
	fail := func() (x86SignedIntegerFloatForm, bool, error) {
		return f, true, fmt.Errorf("%s %s operands/suffix outside Go integer-to-scalar-float grammar: %q", goarch, ins.Op, ins.Raw)
	}
	if goarch != "amd64" && goarch != "386" {
		return fail()
	}
	if spec.legacy {
		if dotted || len(ins.Args) != 2 || goarch == "386" && spec.sourceBits == 64 {
			return fail()
		}
		f.upper = f.destination
	} else {
		if len(ins.Args) != 3 || dotted && suffix == "" {
			return fail()
		}
		if suffix != "" {
			if !spec.rounding || ins.Args[0].Kind != OpReg {
				return fail()
			}
			switch suffix {
			case "RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE":
				f.rounding = suffix
			default:
				return fail()
			}
		}
		// Intel's VEX.W1/EVEX.W1 is ignored outside 64-bit mode.
		if goarch == "386" {
			f.sourceBits = 32
		}
	}
	for _, index := range []int{f.upper, f.destination} {
		arg := ins.Args[index]
		n, valid := amd64ParseXReg(arg.Reg)
		if arg.Kind != OpReg || !valid || spec.legacy && n >= 16 {
			return fail()
		}
		if goarch == "386" && n >= 8 {
			return f, true, fmt.Errorf("%w: %s mode32 cannot address physical X%d even when Go emits its named VEX/EVEX form", ErrProbeNeedsContext, ins.Op, n)
		}
	}
	source := ins.Args[0]
	if source.Kind == OpReg {
		if !(&amd64Ctx{goarch: goarch}).isGoYrlRegister(source) {
			return fail()
		}
	} else if isAMD64MemoryOperand(source) {
		if source.Kind == OpSym {
			text := strings.TrimSpace(source.Sym)
			_, absolute := parseInt(text)
			if strings.HasPrefix(text, "$") || !strings.HasSuffix(text, "(SB)") && absolute != nil {
				return fail()
			}
		}
		if source.Kind == OpMem {
			m := source.Mem
			if m.Off != int64(int32(m.Off)) && (goarch != "386" || m.Off != int64(uint32(m.Off))) ||
				!x86MemoryRegistersValidForArch(m, goarch) || m.Index != "" &&
				(m.Index == SP || m.Scale != 1 && m.Scale != 2 && m.Scale != 4 && m.Scale != 8) {
				return fail()
			}
		}
		f.memory = 0
	} else {
		return fail()
	}
	return f, true, nil
}

func (c *amd64Ctx) lowerSignedIntegerScalarFloat(op Op, ins Instr) (bool, bool, error) {
	if ins.Op == "" {
		ins.Op = op
	} else if !strings.EqualFold(string(ins.Op), string(op)) {
		base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
		if _, known := x86SignedIntegerFloatSpecs[Op(base)]; known {
			return true, false, fmt.Errorf("signed scalar conversion helper opcode %s conflicts with instruction %s", op, ins.Op)
		}
		return false, false, nil
	}
	f, known, err := x86SignedIntegerFloatProperties(ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	if ins.Args[0].Kind == OpFP {
		if err := c.validateFPVectorSpan(ins.Args[0].FPOffset, f.sourceBits/8); err != nil {
			return true, false, fmt.Errorf("%w: signed conversion FP source: %v", ErrProbeNeedsContext, err)
		}
	}
	integer, err := c.loadSignedIntegerFloatSource(ins.Args[0], f.sourceBits)
	if err != nil {
		return true, false, err
	}
	typ := amd64IntegerTypeForBits(f.sourceBits)
	floatType := "float"
	if f.spec.resultBits == 64 {
		floatType = "double"
	}
	var low string
	if f.rounding == "" {
		converted, bits := c.newTmp(), c.newTmp()
		if c.goarch == "386" {
			// LLVM 22's default i386 constrained conversion uses x87 and its
			// control word, not the source instruction's MXCSR. Use a private
			// scalar SSE result; the virtual upper lanes are handled below.
			// W1 is ignored in mode32, so even nominal Q forms consume i32.
			mnemonic := "cvtsi2ssl"
			if f.spec.resultBits == 64 {
				mnemonic = "cvtsi2sdl"
			}
			fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, \"=x,r\"(i32 %s)\n", converted, floatType, mnemonic+" $1, $0", integer)
		} else {
			// Unlike plain sitofp, this cannot fold constant inputs using
			// default rounding or discard the real MXCSR precision exception.
			// LDMXCSR/STMXCSR operate on that same hardware state, not a shadow.
			fmt.Fprintf(c.b, "  %%%s = call %s @llvm.experimental.constrained.sitofp.f%d.i%d(%s %s, metadata !\"round.dynamic\", metadata !\"fpexcept.strict\")\n", converted, floatType, f.spec.resultBits, f.sourceBits, typ, integer)
		}
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to i%d\n", bits, floatType, converted, f.spec.resultBits)
		low = "%" + bits
	} else {
		// Widen the integer work representation to contain double's 53-bit
		// significand even for mode32 WIG forms. No floating operation is
		// introduced: embedded SAE must not change ambient sticky flags.
		if f.sourceBits == 32 {
			wide := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = sext i32 %s to i64\n", wide, integer)
			integer = "%" + wide
		}
		low = c.emitRoundedScalarIntegerToFloatBits(integer, amd64ScalarIntegerFloatSpec{sourceBits: 64, resultBits: f.spec.resultBits}, f.rounding)
	}
	baseBytes, err := c.loadX(ins.Args[f.upper].Reg)
	if err != nil {
		return true, false, err
	}
	base := c.bitcastVectorBytesToIntegerLanes(16, 128/f.spec.resultBits, f.spec.resultBits, baseBytes)
	if f.spec.legacy {
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast i%d %s to %s\n", value, f.spec.resultBits, low, floatType)
		return true, false, c.storeLegacyScalarMoveRegister(ins.Args[f.destination].Reg, "%"+value, f.spec.resultBits, true)
	}
	return true, false, c.storeScalarMoveRegister(ins.Args[f.destination].Reg, f.spec.resultBits, low, base, "", false)
}

func (c *amd64Ctx) loadSignedIntegerFloatSource(arg Operand, bits int) (string, error) {
	if arg.Kind == OpReg {
		return c.evalIntSized(arg, amd64IntegerTypeForBits(bits))
	}
	if arg.Kind == OpFP {
		bytes, err := c.loadFPVectorBytes(arg.FPOffset, bits/8)
		if err != nil {
			return "", err
		}
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to i%d\n", value, bits/8, bytes, bits)
		return "%" + value, nil
	}
	pointer, pointerType, _, err := c.packedVectorMemoryPointer(arg)
	if err != nil {
		return "", err
	}
	value := c.newTmp()
	// Preserve the original native access/fault even if all result bytes
	// are subsequently overwritten; there is no suppressing mask form.
	fmt.Fprintf(c.b, "  %%%s = load volatile i%d, %s %s, align 1\n", value, bits, pointerType, pointer)
	return "%" + value, nil
}
