package plan9asm

import (
	"fmt"
	"strings"
)

type amd64ScalarFloatToIntSpec struct {
	inputBits  int
	outputBits int
	truncating bool
	unsigned   bool
	vector     bool
}

var amd64ScalarFloatToIntSpecs = map[Op]amd64ScalarFloatToIntSpec{
	"CVTSS2SL":  {inputBits: 32, outputBits: 32},
	"CVTSS2SQ":  {inputBits: 32, outputBits: 64},
	"CVTSD2SL":  {inputBits: 64, outputBits: 32},
	"CVTSD2SQ":  {inputBits: 64, outputBits: 64},
	"CVTTSS2SL": {inputBits: 32, outputBits: 32, truncating: true},
	"CVTTSS2SQ": {inputBits: 32, outputBits: 64, truncating: true},
	"CVTTSD2SL": {inputBits: 64, outputBits: 32, truncating: true},
	"CVTTSD2SQ": {inputBits: 64, outputBits: 64, truncating: true},

	"VCVTSS2SI":   {inputBits: 32, outputBits: 32, vector: true},
	"VCVTSS2SIQ":  {inputBits: 32, outputBits: 64, vector: true},
	"VCVTSD2SI":   {inputBits: 64, outputBits: 32, vector: true},
	"VCVTSD2SIQ":  {inputBits: 64, outputBits: 64, vector: true},
	"VCVTTSS2SI":  {inputBits: 32, outputBits: 32, truncating: true, vector: true},
	"VCVTTSS2SIQ": {inputBits: 32, outputBits: 64, truncating: true, vector: true},
	"VCVTTSD2SI":  {inputBits: 64, outputBits: 32, truncating: true, vector: true},
	"VCVTTSD2SIQ": {inputBits: 64, outputBits: 64, truncating: true, vector: true},

	"VCVTSS2USIL":  {inputBits: 32, outputBits: 32, unsigned: true, vector: true},
	"VCVTSS2USIQ":  {inputBits: 32, outputBits: 64, unsigned: true, vector: true},
	"VCVTSD2USIL":  {inputBits: 64, outputBits: 32, unsigned: true, vector: true},
	"VCVTSD2USIQ":  {inputBits: 64, outputBits: 64, unsigned: true, vector: true},
	"VCVTTSS2USIL": {inputBits: 32, outputBits: 32, truncating: true, unsigned: true, vector: true},
	"VCVTTSS2USIQ": {inputBits: 32, outputBits: 64, truncating: true, unsigned: true, vector: true},
	"VCVTTSD2USIL": {inputBits: 64, outputBits: 32, truncating: true, unsigned: true, vector: true},
	"VCVTTSD2USIQ": {inputBits: 64, outputBits: 64, truncating: true, unsigned: true, vector: true},
}

// lowerScalarFloatToInteger implements Go 1.27's complete signed legacy/VEX/
// EVEX scalar float-to-integer family and its EVEX unsigned counterparts.
func (c *amd64Ctx) lowerScalarFloatToInteger(rawOp Op, ins Instr) (ok bool, terminated bool, err error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(rawOp)), ".")
	if _, known := amd64ScalarFloatToIntSpecs[Op(base)]; !known {
		return false, false, nil
	}
	if ins.Op != "" && !strings.EqualFold(string(rawOp), string(ins.Op)) {
		return true, false, fmt.Errorf("scalar conversion dispatch/source mismatch: %s/%s", rawOp, ins.Op)
	}
	ins.Op = rawOp
	f, known, err := x86ScalarFloatIntegerProperties(ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	if !x86ScalarFloatIntegerNativeTarget(c.goarch, c.targetTriple) {
		return true, false, fmt.Errorf("%w: scalar conversion lacks native MXCSR target", ErrProbeNeedsContext)
	}
	if ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride {
		return true, false, fmt.Errorf("%w: scalar conversion needs its original native address size", ErrProbeNeedsContext)
	}
	return true, false, c.emitNativeScalarFloatInteger(ins, f)
}

func (c *amd64Ctx) evalScalarFloatForInteger(source Operand, bits int) (string, error) {
	if bits == 32 {
		return c.evalF32(source)
	}
	return c.evalF64(source)
}

func amd64FloatingTypeForBits(bits int) LLVMType {
	if bits == 32 {
		return LLVMType("float")
	}
	return LLVMType("double")
}
