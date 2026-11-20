package plan9asm

import (
	"fmt"
	"strings"
)

type amd64HalfConversionSuffix struct {
	sae     bool
	zeroing bool
}

type amd64HalfConversionSpec struct {
	inputBits, outputBits int
	rawOnly               bool
	scalar                bool
}

var amd64HalfConversionSpecs = map[string]amd64HalfConversionSpec{
	"VCVTPH2PS":  {inputBits: 16, outputBits: 32},
	"VCVTPS2PH":  {inputBits: 32, outputBits: 16},
	"VCVTPH2PSX": {inputBits: 16, outputBits: 32, rawOnly: true},
	"VCVTPS2PHX": {inputBits: 32, outputBits: 16, rawOnly: true},
	"VCVTSH2SS":  {inputBits: 16, outputBits: 32, rawOnly: true, scalar: true},
	"VCVTSS2SH":  {inputBits: 32, outputBits: 16, rawOnly: true, scalar: true},
	"VCVTSH2SD":  {inputBits: 16, outputBits: 64, rawOnly: true, scalar: true},
	"VCVTSD2SH":  {inputBits: 64, outputBits: 16, rawOnly: true, scalar: true},
}

func parseAMD64HalfConversionSuffix(rawOp, baseOp string) (amd64HalfConversionSuffix, error) {
	var result amd64HalfConversionSuffix
	if rawOp == baseOp {
		return result, nil
	}
	suffixes := strings.Split(strings.TrimPrefix(rawOp, baseOp+"."), ".")
	for index, suffix := range suffixes {
		switch suffix {
		case "SAE":
			if result.sae || index != 0 {
				return result, fmt.Errorf("amd64 %s has invalid or duplicate .SAE suffix", baseOp)
			}
			result.sae = true
		case "Z":
			if result.zeroing || index != len(suffixes)-1 {
				return result, fmt.Errorf("amd64 %s has invalid or duplicate .Z suffix", baseOp)
			}
			result.zeroing = true
		default:
			return result, fmt.Errorf("amd64 %s has unsupported suffix .%s", baseOp, suffix)
		}
	}
	return result, nil
}

// lowerPackedHalfConversion implements every Go 1.27 _yvcvtph2ps and
// _yvcvtps2ph row, including VEX signed immediates, EVEX masks, zeroing, SAE,
// exact-width memory accesses, and the distinct X/Y/Z narrowing widths.
func (c *amd64Ctx) lowerPackedHalfConversion(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	spec, supported := amd64HalfConversionSpecs[baseOp]
	if !supported {
		return false, false, nil
	}
	if spec.rawOnly {
		if !strings.EqualFold(string(op), string(ins.Op)) {
			return true, false, fmt.Errorf("raw FP16 conversion opcode identity mismatch: %s versus %s", op, ins.Op)
		}
		return c.lowerRawFP16Conversion(ins)
	}
	return c.lowerNamedHalfConversion(op, ins)
}

func amd64HalfConversionHighRegister(operand Operand) bool {
	if operand.Kind != OpReg {
		return false
	}
	width := amd64VectorByteWidth(operand.Reg)
	index, ok := amd64VectorRegisterIndex(operand.Reg, width)
	return ok && index >= 16
}

func (c *amd64Ctx) storePackedHalfResult(destination Operand, registerBytes, outputBytes int, value string) error {
	if destination.Kind != OpReg {
		return c.storeVectorBytesOperand(destination, outputBytes, value)
	}
	if outputBytes == registerBytes {
		return c.storePackedMoveOperand(destination, registerBytes, value)
	}
	widened := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i8> %s, <%d x i8> zeroinitializer, <%d x i32> <", widened, outputBytes, value, outputBytes, registerBytes)
	for lane := 0; lane < registerBytes; lane++ {
		if lane > 0 {
			c.b.WriteString(", ")
		}
		fmt.Fprintf(c.b, "i32 %d", lane)
	}
	c.b.WriteString(">\n")
	return c.storePackedMoveOperand(destination, registerBytes, "%"+widened)
}
