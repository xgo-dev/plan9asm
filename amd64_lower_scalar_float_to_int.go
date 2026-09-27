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
	raw := strings.ToUpper(string(rawOp))
	parts := strings.Split(raw, ".")
	baseOp := Op(parts[0])
	spec, recognized := amd64ScalarFloatToIntSpecs[baseOp]
	if !recognized {
		return false, false, nil
	}
	if len(parts) > 2 {
		return true, false, fmt.Errorf("amd64 %s has multiple suffixes outside Go 1.27's scalar conversion table: %q", baseOp, ins.Raw)
	}
	suffix := ""
	if len(parts) == 2 {
		suffix = parts[1]
	}
	if !spec.vector && suffix != "" {
		return true, false, fmt.Errorf("amd64 legacy %s does not accept instruction suffixes: %q", baseOp, ins.Raw)
	}
	if spec.vector {
		if spec.truncating {
			if suffix != "" && suffix != "SAE" {
				return true, false, fmt.Errorf("amd64 %s accepts only .SAE: %q", baseOp, ins.Raw)
			}
		} else {
			switch suffix {
			case "", "RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE":
			default:
				return true, false, fmt.Errorf("amd64 %s has invalid rounding suffix: %q", baseOp, ins.Raw)
			}
		}
	}
	if len(ins.Args) != 2 {
		return true, false, fmt.Errorf("amd64 %s expects scalar-X/memory source and GP destination: %q", baseOp, ins.Raw)
	}
	source, destination := ins.Args[0], ins.Args[1]
	if destination.Kind != OpReg || !isX86YrlRegisterForArch(destination.Reg, c.goarch) {
		return true, false, fmt.Errorf("amd64 %s destination is outside Go 1.27's Yrl GP class: %q", baseOp, ins.Raw)
	}
	if c.goarch == "386" && spec.outputBits == 64 {
		return true, false, fmt.Errorf("386 %s cannot encode a 64-bit GP destination: %q", baseOp, ins.Raw)
	}
	if !spec.vector {
		if !c.isGoVEXVectorRegister(source, 16, true) {
			return true, false, fmt.Errorf("amd64 %s source is outside Go 1.27's legacy X/memory class: %q", baseOp, ins.Raw)
		}
	} else {
		if source.Kind == OpReg {
			if !c.isGoEVEXVectorRegister(source, 16) {
				return true, false, fmt.Errorf("amd64 %s source is outside Go 1.27's X register class: %q", baseOp, ins.Raw)
			}
		} else if !isAMD64MemoryOperand(source) {
			return true, false, fmt.Errorf("amd64 %s source must be X or memory: %q", baseOp, ins.Raw)
		}
	}
	if suffix != "" && source.Kind != OpReg {
		return true, false, fmt.Errorf("amd64 %s embedded rounding/SAE requires a register source: %q", baseOp, ins.Raw)
	}
	value, err := c.evalScalarFloatForInteger(source, spec.inputBits)
	if err != nil {
		return true, false, err
	}
	value = c.roundScalarFloatForInteger(value, spec.inputBits, spec.truncating, suffix)
	outputType := amd64IntegerTypeForBits(spec.outputBits)
	converted := c.newTmp()
	operation := "fptosi"
	if spec.unsigned {
		operation = "fptoui"
	}
	fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", converted, operation, amd64FloatingTypeForBits(spec.inputBits), value, outputType)
	return true, false, c.storeRegSized(destination.Reg, outputType, "%"+converted)
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

func (c *amd64Ctx) roundScalarFloatForInteger(value string, bits int, truncating bool, suffix string) string {
	intrinsic := "rint"
	if truncating || suffix == "RZ_SAE" || suffix == "SAE" {
		intrinsic = "trunc"
	} else {
		switch suffix {
		case "RN_SAE":
			intrinsic = "roundeven"
		case "RD_SAE":
			intrinsic = "floor"
		case "RU_SAE":
			intrinsic = "ceil"
		}
	}
	return c.emitScalarFloatRound(value, bits, intrinsic)
}
