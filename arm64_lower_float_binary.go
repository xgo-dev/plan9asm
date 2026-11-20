package plan9asm

import (
	"fmt"
	"strings"
)

func arm64ScalarFloatBinaryKind(op Op) (kind string, bits int, ok bool) {
	bits = 32
	if strings.HasSuffix(string(op), "D") {
		bits = 64
	}
	switch op {
	case "FMAXS", "FMAXD":
		return "maximum", bits, true
	case "FMINS", "FMIND":
		return "minimum", bits, true
	case "FMAXNMS", "FMAXNMD":
		return "maxnum", bits, true
	case "FMINNMS", "FMINNMD":
		return "minnum", bits, true
	default:
		return "", 0, false
	}
}

func (c *arm64Ctx) loadARM64ScalarFloatReg(reg Reg, bits int) (string, error) {
	encoded, err := c.loadRegisterWidth(reg, bits)
	if err != nil {
		return "", err
	}
	switch bits {
	case 64:
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast i64 %s to double\n", value, encoded)
		return "%" + value, nil
	case 32:
		narrow := c.newTmp()
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", narrow, encoded)
		fmt.Fprintf(c.b, "  %%%s = bitcast i32 %%%s to float\n", value, narrow)
		return "%" + value, nil
	case 16:
		narrow := c.newTmp()
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i16\n", narrow, encoded)
		fmt.Fprintf(c.b, "  %%%s = bitcast i16 %%%s to half\n", value, narrow)
		return "%" + value, nil
	default:
		return "", fmt.Errorf("arm64 unsupported scalar float width %d", bits)
	}
}

func (c *arm64Ctx) storeARM64ScalarFloatReg(reg Reg, bits int, value string) error {
	switch bits {
	case 64:
		encoded := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast double %s to i64\n", encoded, value)
		return c.storeReg(reg, "%"+encoded)
	case 32:
		encoded := c.newTmp()
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast float %s to i32\n", encoded, value)
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", wide, encoded)
		return c.storeReg(reg, "%"+wide)
	case 16:
		encoded := c.newTmp()
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast half %s to i16\n", encoded, value)
		fmt.Fprintf(c.b, "  %%%s = zext i16 %%%s to i64\n", wide, encoded)
		return c.storeReg(reg, "%"+wide)
	default:
		return fmt.Errorf("arm64 unsupported scalar float width %d", bits)
	}
}

func (c *arm64Ctx) lowerARM64ScalarFloatBinary(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if form, known, err := parseARM64ScalarBinary(op, ins); known {
		if err != nil {
			return true, false, err
		}
		return true, false, c.lowerARM64ScalarBinary(form)
	}
	if form, matched, err := parseARM64ScalarMinMax(op, ins); matched {
		if err != nil {
			return true, false, err
		}
		return true, false, c.lowerARM64ScalarMinMax(form)
	}
	kind, bits, handled := arm64ScalarFloatBinaryKind(op)
	if !handled {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || (len(ins.Args) != 2 && len(ins.Args) != 3) {
		return true, false, fmt.Errorf("arm64 %s expects Fsrc,Fdst or Fsrc1,Fsrc2,Fdst and no suffix: %q", op, ins.Raw)
	}
	for _, arg := range ins.Args {
		if arg.Kind != OpReg || !isARM64FReg(arg.Reg) {
			return true, false, fmt.Errorf("arm64 %s accepts only F registers: %q", op, ins.Raw)
		}
	}
	rhs, err := c.loadARM64ScalarFloatReg(ins.Args[0].Reg, bits)
	if err != nil {
		return true, false, err
	}
	lhs, err := c.loadARM64ScalarFloatReg(ins.Args[1].Reg, bits)
	if err != nil {
		return true, false, err
	}
	dst := ins.Args[len(ins.Args)-1].Reg
	return true, false, c.lowerARM64ScalarFloatBinaryValues(kind, bits, lhs, rhs, dst)
}

func (c *arm64Ctx) lowerARM64ScalarFloatBinaryValues(
	kind string,
	bits int,
	lhs string,
	rhs string,
	destination Reg,
) error {
	floatType, suffix, ok := arm64ScalarFloatType(bits)
	if !ok {
		return fmt.Errorf("arm64 unsupported scalar float width %d", bits)
	}
	result := c.newTmp()
	switch kind {
	case "fabd", "fmulx":
		family := "neon"
		if kind == "fabd" {
			family = "sisd"
		}
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.%s.%s.%s(%s %s, %s %s)\n",
			result, floatType, family, kind, suffix, floatType, lhs, floatType, rhs)
	default:
		return fmt.Errorf("arm64 scalar binary kind %q requires its typed native form", kind)
	}
	return c.storeARM64ScalarFloatReg(destination, bits, "%"+result)
}
