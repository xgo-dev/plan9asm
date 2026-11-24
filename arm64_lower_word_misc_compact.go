package plan9asm

import (
	"fmt"
)

// --- arm64_lower_word_fsqrt.go ---
type arm64RawFSQRT struct {
	arrangement arm64VectorArrangement
	source      int
	destination int
}

func decodeARM64RawFSQRT(word uint32) (arm64RawFSQRT, bool) {
	const registers = uint32(31 | 31<<5)
	if key := word &^ registers; key == 0x2ef9f800 || key == 0x6ef9f800 {
		lanes := 4
		if word&(1<<30) != 0 {
			lanes = 8
		}
		return arm64RawFSQRT{
			arrangement: arm64VectorArrangement{elementBits: 16, lanes: lanes},
			source:      int(word>>5) & 31,
			destination: int(word) & 31,
		}, true
	}
	if word&0xbfbffc00 != 0x2ea1f800 { // Ignore Q, size, Rn, and Rd.
		return arm64RawFSQRT{}, false
	}
	elementBits := 32
	if word&(1<<22) != 0 {
		elementBits = 64
	}
	vectorBits := 64
	if word&(1<<30) != 0 {
		vectorBits = 128
	}
	if elementBits == 64 && vectorBits == 64 {
		return arm64RawFSQRT{}, false
	}
	return arm64RawFSQRT{
		arrangement: arm64VectorArrangement{elementBits: elementBits, lanes: vectorBits / elementBits},
		source:      int(word>>5) & 31,
		destination: int(word) & 31,
	}, true
}

func (c *arm64Ctx) lowerRawFSQRT(form arm64RawFSQRT) error {
	if form.arrangement.elementBits == 16 {
		source, err := c.loadARM64VectorFloat(Reg(fmt.Sprintf("V%d", form.source)), form.arrangement)
		if err != nil {
			return err
		}
		result := c.newTmp()
		vectorType := fmt.Sprintf("<%d x half>", form.arrangement.lanes)
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.sqrt.v%df16(%s %s)\n", result, vectorType, form.arrangement.lanes, vectorType, source)
		return c.storeARM64VectorFloat(Reg(fmt.Sprintf("V%d", form.destination)), form.arrangement, "%"+result)
	}
	arrangement := arm64VectorArrangementName(form.arrangement)
	ins := Instr{
		Op:  "VFSQRT",
		Raw: "decoded ARM64 WORD as VFSQRT",
		Args: []Operand{
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("V%d.%s", form.source, arrangement))},
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("V%d.%s", form.destination, arrangement))},
		},
	}
	ok, _, err := c.lowerARM64VectorFloatUnary("VFSQRT", ins)
	if !ok && err == nil {
		return fmt.Errorf("arm64 raw VFSQRT decoder reached no semantic lowerer")
	}
	return err
}

// --- arm64_lower_word_mixed_saturating_add.go ---
func (c *arm64Ctx) lowerARM64PortableMixedSaturatingAdd(form arm64SaturatingArithmeticForm, sourceReg, destinationReg Reg) error {
	arrangement := form.arrangement
	bits := arrangement.elementBits
	if arrangement.lanes == 1 {
		source, err := c.arm64VDUPExtractLane(sourceReg, bits, 0)
		if err != nil {
			return err
		}
		destination, err := c.arm64VDUPExtractLane(destinationReg, bits, 0)
		if err != nil {
			return err
		}
		// LLVM 22 cannot select the overloaded scalar i8/i16 intrinsic. Place
		// the active lane in a zeroed vector instead. Other lanes cannot set
		// saturation state, and only the active result lane is written back.
		lanes := 64 / bits
		if bits == 64 {
			lanes = 2
		}
		typeName := fmt.Sprintf("<%d x i%d>", lanes, bits)
		sourceVector := c.newTmp()
		destinationVector := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement %s zeroinitializer, i%d %s, i32 0\n",
			sourceVector, typeName, bits, source)
		fmt.Fprintf(c.b, "  %%%s = insertelement %s zeroinitializer, i%d %s, i32 0\n",
			destinationVector, typeName, bits, destination)
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.neon.%s.v%di%d(%s %%%s, %s %%%s)\n",
			result, typeName, form.op.mnemonic, lanes, bits,
			typeName, destinationVector, typeName, sourceVector)
		low := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %%%s, i32 0\n", low, typeName, result)
		return c.storeARM64ScalarToVReg(destinationReg, bits, "%"+low)
	}

	source, err := c.loadARM64VectorInteger(sourceReg, arrangement)
	if err != nil {
		return err
	}
	destination, err := c.loadARM64VectorInteger(destinationReg, arrangement)
	if err != nil {
		return err
	}
	typeName := fmt.Sprintf("<%d x i%d>", arrangement.lanes, bits)
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.neon.%s.v%di%d(%s %s, %s %s)\n",
		result, typeName, form.op.mnemonic, arrangement.lanes, bits,
		typeName, destination, typeName, source)
	return c.storeARM64VectorInteger(destinationReg, arrangement, "%"+result)
}

// --- arm64_lower_word_sshr.go ---
type arm64RawSSHR struct {
	scalar      bool
	arrangement arm64VectorArrangement
	shift       int
	source      int
	destination int
}

func decodeARM64RawSSHR(word uint32) (arm64RawSSHR, bool) {
	form := arm64RawSSHR{}
	switch {
	case word&0xff80fc00 == 0x5f000400:
		form.scalar = true
	case word&0xbf80fc00 == 0x0f000400:
	default:
		return arm64RawSSHR{}, false
	}
	encodedImmediate := int(word>>16) & 0x7f
	bits := 0
	switch {
	case encodedImmediate >= 64:
		bits = 64
	case encodedImmediate >= 32:
		bits = 32
	case encodedImmediate >= 16:
		bits = 16
	case encodedImmediate >= 8:
		bits = 8
	default:
		return arm64RawSSHR{}, false
	}
	shift := 2*bits - encodedImmediate
	if shift < 1 || shift > bits || form.scalar && bits != 64 {
		return arm64RawSSHR{}, false
	}
	vectorBits := 64
	if form.scalar {
		form.arrangement = arm64VectorArrangement{elementBits: 64, lanes: 1}
	} else {
		if word&(1<<30) != 0 {
			vectorBits = 128
		}
		if bits == 64 && vectorBits != 128 {
			return arm64RawSSHR{}, false
		}
		form.arrangement = arm64VectorArrangement{elementBits: bits, lanes: vectorBits / bits}
	}
	form.shift = shift
	form.source = int(word>>5) & 31
	form.destination = int(word & 31)
	return form, true
}

func (c *arm64Ctx) lowerRawSSHR(form arm64RawSSHR) error {
	source, err := c.loadRawARM64VectorOperand(form.source, form.arrangement, 0, form.scalar)
	if err != nil {
		return err
	}
	vectorType := fmt.Sprintf("<%d x i%d>", form.arrangement.lanes, form.arrangement.elementBits)
	result := c.newTmp()
	shift := form.shift
	if shift == form.arrangement.elementBits {
		// LLVM shifts by the element width are poison. AArch64 SSHR by the
		// element width instead replicates the sign bit, which is equivalent to
		// an arithmetic shift by width-1.
		shift--
	}
	fmt.Fprintf(c.b, "  %%%s = ashr %s %s, %s\n", result, vectorType, source, arm64VectorIntegerSplat(form.arrangement, int64(shift)))
	return c.storeRawARM64VectorResult(form.destination, form.arrangement, "%"+result, form.scalar)
}

// --- arm64_lower_word_system_register.go ---
type arm64RawSystemRegister struct {
	read     bool
	encoding uint16
	reg      int
}

// decodeARM64RawSystemRegister covers the complete MRS/MSR (register) encoding
// fields: both directions, every 15-bit architectural system-register value,
// and every Xt value (including XZR).
func decodeARM64RawSystemRegister(word uint32) (arm64RawSystemRegister, bool) {
	fixed := word & 0xfff00000
	if fixed != 0xd5300000 && fixed != 0xd5100000 {
		return arm64RawSystemRegister{}, false
	}
	return arm64RawSystemRegister{
		read:     fixed == 0xd5300000,
		encoding: uint16((word >> 5) & 0x7fff),
		reg:      int(word & 31),
	}, true
}

func arm64EncodedSystemRegisterName(encoding uint16) string {
	op0 := 2 + int((encoding>>14)&1)
	op1 := int((encoding >> 11) & 7)
	crn := int((encoding >> 7) & 15)
	crm := int((encoding >> 3) & 15)
	op2 := int(encoding & 7)
	return fmt.Sprintf("S%d_%d_C%d_C%d_%d", op0, op1, crn, crm, op2)
}

func (c *arm64Ctx) lowerRawSystemRegister(form arm64RawSystemRegister) error {
	if control, matched := arm64RawFPControl(form); matched {
		return c.lowerARM64FPControl(control)
	}
	if form.encoding == arm64NZCVEncoding {
		reg := ZR
		if form.reg != 31 {
			reg = Reg(fmt.Sprintf("R%d", form.reg))
		}
		return c.lowerARM64NZCV(arm64NZCVForm{read: form.read, reg: reg})
	}
	sysreg := arm64EncodedSystemRegisterName(form.encoding)
	if form.read {
		dst := ZR
		if form.reg != 31 {
			dst = Reg(fmt.Sprintf("R%d", form.reg))
		}
		value := c.emitARM64SystemRegisterRead(sysreg, form.encoding, true, dst)
		if form.reg == 31 {
			return nil
		}
		return c.storeReg(Reg(fmt.Sprintf("R%d", form.reg)), value)
	}
	value := "0"
	if form.reg != 31 {
		var err error
		value, err = c.loadReg(Reg(fmt.Sprintf("R%d", form.reg)))
		if err != nil {
			return err
		}
	}
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(i64 %s)\n", "msr "+sysreg+", $0", "r,~{memory}", value)
	return nil
}
