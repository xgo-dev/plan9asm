package plan9asm

import "fmt"

// ARM's USQADD and SUQADD use a two-register, destructive form. Retaining the
// encoded element size matters for scalar WORD instructions: x/arch's Plan 9
// spelling prints every scalar size as two bare V registers.
type arm64RawMixedSaturatingAdd struct {
	intrinsic   string
	scalar      bool
	elementBits int
	lanes       int
	source      int
	destination int
}

func decodeARM64RawMixedSaturatingAdd(word uint32) (arm64RawMixedSaturatingAdd, bool) {
	base := word &^ uint32(0x00c003ff) // Element size and both V registers.
	form := arm64RawMixedSaturatingAdd{}
	switch base {
	case 0x0e203800, 0x4e203800:
		form.intrinsic = "suqadd"
	case 0x2e203800, 0x6e203800:
		form.intrinsic = "usqadd"
	case 0x5e203800:
		form.intrinsic = "suqadd"
		form.scalar = true
	case 0x7e203800:
		form.intrinsic = "usqadd"
		form.scalar = true
	default:
		return arm64RawMixedSaturatingAdd{}, false
	}
	form.elementBits = 8 << ((word >> 22) & 3)
	if !form.scalar {
		vectorBits := 64
		if word&(1<<30) != 0 {
			vectorBits = 128
		}
		if form.elementBits >= vectorBits {
			return arm64RawMixedSaturatingAdd{}, false
		}
		form.lanes = vectorBits / form.elementBits
	}
	form.source = int(word>>5) & 31
	form.destination = int(word) & 31
	return form, true
}

func (c *arm64Ctx) lowerRawMixedSaturatingAdd(form arm64RawMixedSaturatingAdd) error {
	sourceRegister := Reg(fmt.Sprintf("V%d", form.source))
	destinationRegister := Reg(fmt.Sprintf("V%d", form.destination))
	if form.scalar {
		source, err := c.loadARM64RawScalarVectorElement(sourceRegister, form.elementBits)
		if err != nil {
			return err
		}
		destination, err := c.loadARM64RawScalarVectorElement(destinationRegister, form.elementBits)
		if err != nil {
			return err
		}
		// LLVM 22 cannot select the overloaded scalar i8/i16 intrinsic. Place
		// the active lane in a zeroed vector instead. Other lanes cannot set
		// saturation state, and only the active result lane is written back.
		lanes := 64 / form.elementBits
		if form.elementBits == 64 {
			lanes = 2
		}
		typeName := fmt.Sprintf("<%d x i%d>", lanes, form.elementBits)
		sourceVector := c.newTmp()
		destinationVector := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement %s zeroinitializer, i%d %s, i32 0\n",
			sourceVector, typeName, form.elementBits, source)
		fmt.Fprintf(c.b, "  %%%s = insertelement %s zeroinitializer, i%d %s, i32 0\n",
			destinationVector, typeName, form.elementBits, destination)
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.neon.%s.v%di%d(%s %%%s, %s %%%s)\n",
			result, typeName, form.intrinsic, lanes, form.elementBits,
			typeName, destinationVector, typeName, sourceVector)
		low := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %%%s, i32 0\n", low, typeName, result)
		return c.storeARM64ScalarToVReg(destinationRegister, form.elementBits, "%"+low)
	}

	arrangement := arm64VectorArrangement{elementBits: form.elementBits, lanes: form.lanes}
	source, err := c.loadARM64VectorInteger(sourceRegister, arrangement)
	if err != nil {
		return err
	}
	destination, err := c.loadARM64VectorInteger(destinationRegister, arrangement)
	if err != nil {
		return err
	}
	typeName := fmt.Sprintf("<%d x i%d>", form.lanes, form.elementBits)
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.neon.%s.v%di%d(%s %s, %s %s)\n",
		result, typeName, form.intrinsic, form.lanes, form.elementBits,
		typeName, destination, typeName, source)
	return c.storeARM64VectorInteger(destinationRegister, arrangement, "%"+result)
}

func (c *arm64Ctx) loadARM64RawScalarVectorElement(reg Reg, bits int) (string, error) {
	bytes, err := c.loadVReg(reg)
	if err != nil {
		return "", err
	}
	vectorType := fmt.Sprintf("<%d x i%d>", 128/bits, bits)
	values := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to %s\n", values, bytes, vectorType)
	low := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractelement %s %%%s, i32 0\n", low, vectorType, values)
	return "%" + low, nil
}
