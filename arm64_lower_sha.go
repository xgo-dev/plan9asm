package plan9asm

import (
	"fmt"
	"strings"
)

var (
	arm64SHA32Arrangement = arm64VectorArrangement{elementBits: 32, lanes: 4}
	arm64SHA64Arrangement = arm64VectorArrangement{elementBits: 64, lanes: 2}
)

func (c *arm64Ctx) lowerARM64SHA(op Op, ins Instr) (ok bool, terminated bool, err error) {
	switch op {
	case "SHA1C", "SHA1P", "SHA1M":
		if err := validateARM64SHAHashForm(op, ins, arm64SHA32Arrangement); err != nil {
			return true, false, err
		}
		schedule, err := c.loadARM64VectorInteger(ins.Args[0].Reg, arm64SHA32Arrangement)
		if err != nil {
			return true, false, err
		}
		hashVector, err := c.loadARM64VectorInteger(ins.Args[1].Reg, arm64SHA32Arrangement)
		if err != nil {
			return true, false, err
		}
		hash := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <4 x i32> %s, i32 0\n", hash, hashVector)
		destination, err := c.loadARM64VectorInteger(ins.Args[2].Reg, arm64SHA32Arrangement)
		if err != nil {
			return true, false, err
		}
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call <4 x i32> @llvm.aarch64.crypto.%s(<4 x i32> %s, i32 %%%s, <4 x i32> %s)\n", result, strings.ToLower(string(op)), destination, hash, schedule)
		return true, false, c.storeARM64VectorInteger(ins.Args[2].Reg, arm64SHA32Arrangement, "%"+result)

	case "SHA1H":
		if err := validateARM64SHABareRegisters(op, ins, 2); err != nil {
			return true, false, err
		}
		sourceVector, err := c.loadARM64VectorInteger(ins.Args[0].Reg, arm64SHA32Arrangement)
		if err != nil {
			return true, false, err
		}
		source := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <4 x i32> %s, i32 0\n", source, sourceVector)
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.aarch64.crypto.sha1h(i32 %%%s)\n", result, source)
		return true, false, c.storeARM64SHA1Scalar(ins.Args[1].Reg, "%"+result)

	case "SHA1SU0", "SHA256SU1":
		if err := validateARM64SHAArrangedRegisters(op, ins, 3, arm64SHA32Arrangement); err != nil {
			return true, false, err
		}
		return true, false, c.lowerARM64SHAVector3(op, ins, arm64SHA32Arrangement)

	case "SHA1SU1", "SHA256SU0":
		if err := validateARM64SHAArrangedRegisters(op, ins, 2, arm64SHA32Arrangement); err != nil {
			return true, false, err
		}
		return true, false, c.lowerARM64SHAVector2(op, ins, arm64SHA32Arrangement)

	case "SHA256H", "SHA256H2":
		if err := validateARM64SHAHashForm(op, ins, arm64SHA32Arrangement); err != nil {
			return true, false, err
		}
		return true, false, c.lowerARM64SHAVector3(op, ins, arm64SHA32Arrangement)

	case "SHA512H", "SHA512H2":
		if err := validateARM64SHAHashForm(op, ins, arm64SHA64Arrangement); err != nil {
			return true, false, err
		}
		return true, false, c.lowerARM64SHAVector3(op, ins, arm64SHA64Arrangement)

	case "SHA512SU0":
		if err := validateARM64SHAArrangedRegisters(op, ins, 2, arm64SHA64Arrangement); err != nil {
			return true, false, err
		}
		return true, false, c.lowerARM64SHAVector2(op, ins, arm64SHA64Arrangement)

	case "SHA512SU1":
		if err := validateARM64SHAArrangedRegisters(op, ins, 3, arm64SHA64Arrangement); err != nil {
			return true, false, err
		}
		return true, false, c.lowerARM64SHAVector3(op, ins, arm64SHA64Arrangement)
	}
	return false, false, nil
}

func validateARM64SHAHashForm(op Op, ins Instr, arrangement arm64VectorArrangement) error {
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return fmt.Errorf("arm64 %s expects an optional-arrangement source and two bare V registers with no suffix: %q", op, ins.Raw)
	}
	if !arm64SHARegisterMatches(ins.Args[0], arrangement, true) || !arm64SHARegisterMatches(ins.Args[1], arrangement, false) || !arm64SHARegisterMatches(ins.Args[2], arrangement, false) {
		return fmt.Errorf("arm64 %s operands do not match Go's assembler table: %q", op, ins.Raw)
	}
	return nil
}

func validateARM64SHABareRegisters(op Op, ins Instr, count int) error {
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != count {
		return fmt.Errorf("arm64 %s expects %d bare V registers with no suffix: %q", op, count, ins.Raw)
	}
	for _, arg := range ins.Args {
		if !arm64SHARegisterMatches(arg, arm64VectorArrangement{}, false) {
			return fmt.Errorf("arm64 %s expects only bare V registers: %q", op, ins.Raw)
		}
	}
	return nil
}

func validateARM64SHAArrangedRegisters(op Op, ins Instr, count int, arrangement arm64VectorArrangement) error {
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != count {
		return fmt.Errorf("arm64 %s expects %d same-arrangement V registers with no suffix: %q", op, count, ins.Raw)
	}
	for _, arg := range ins.Args {
		if !arm64SHARegisterMatches(arg, arrangement, true) || !strings.Contains(string(arg.Reg), ".") {
			return fmt.Errorf("arm64 %s operands do not match Go's assembler table: %q", op, ins.Raw)
		}
	}
	return nil
}

func arm64SHARegisterMatches(arg Operand, arrangement arm64VectorArrangement, allowArrangement bool) bool {
	if arg.Kind != OpReg {
		return false
	}
	if _, ok := arm64ParseVReg(arg.Reg); !ok {
		return false
	}
	hasArrangement := strings.Contains(string(arg.Reg), ".")
	if !hasArrangement {
		return true
	}
	if !allowArrangement {
		return false
	}
	got, ok := parseARM64VectorArrangement(arg.Reg)
	return ok && got == arrangement
}

func (c *arm64Ctx) lowerARM64SHAVector2(op Op, ins Instr, arrangement arm64VectorArrangement) error {
	source, err := c.loadARM64VectorInteger(ins.Args[0].Reg, arrangement)
	if err != nil {
		return err
	}
	destination, err := c.loadARM64VectorInteger(ins.Args[1].Reg, arrangement)
	if err != nil {
		return err
	}
	result := c.newTmp()
	vectorType := fmt.Sprintf("<%d x i%d>", arrangement.lanes, arrangement.elementBits)
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.crypto.%s(%s %s, %s %s)\n", result, vectorType, strings.ToLower(string(op)), vectorType, destination, vectorType, source)
	return c.storeARM64VectorInteger(ins.Args[1].Reg, arrangement, "%"+result)
}

func (c *arm64Ctx) lowerARM64SHAVector3(op Op, ins Instr, arrangement arm64VectorArrangement) error {
	first, err := c.loadARM64VectorInteger(ins.Args[0].Reg, arrangement)
	if err != nil {
		return err
	}
	second, err := c.loadARM64VectorInteger(ins.Args[1].Reg, arrangement)
	if err != nil {
		return err
	}
	destination, err := c.loadARM64VectorInteger(ins.Args[2].Reg, arrangement)
	if err != nil {
		return err
	}
	result := c.newTmp()
	vectorType := fmt.Sprintf("<%d x i%d>", arrangement.lanes, arrangement.elementBits)
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.crypto.%s(%s %s, %s %s, %s %s)\n", result, vectorType, strings.ToLower(string(op)), vectorType, destination, vectorType, second, vectorType, first)
	return c.storeARM64VectorInteger(ins.Args[2].Reg, arrangement, "%"+result)
}

func (c *arm64Ctx) storeARM64SHA1Scalar(reg Reg, value string) error {
	vector := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <4 x i32> zeroinitializer, i32 %s, i32 0\n", vector, value)
	return c.storeARM64VectorInteger(reg, arm64SHA32Arrangement, "%"+vector)
}
