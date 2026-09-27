package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) lowerARM64SHA3(op Op, ins Instr) (ok bool, terminated bool, err error) {
	switch op {
	case "VEOR3", "VBCAX":
		if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 4 {
			return true, false, fmt.Errorf("arm64 %s expects four V.B16 operands with no suffix: %q", op, ins.Raw)
		}
		for _, arg := range ins.Args {
			if arg.Kind != OpReg || string(arg.Reg) != strings.Split(string(arg.Reg), ".")[0]+".B16" {
				return true, false, fmt.Errorf("arm64 %s expects four V.B16 operands: %q", op, ins.Raw)
			}
			arrangement, valid := parseARM64VectorArrangement(arg.Reg)
			if !valid || arrangement.elementBits != 8 || arrangement.lanes != 16 {
				return true, false, fmt.Errorf("arm64 %s expects four V.B16 operands: %q", op, ins.Raw)
			}
		}
		a, err := c.loadVReg(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		m, err := c.loadVReg(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		n, err := c.loadVReg(ins.Args[2].Reg)
		if err != nil {
			return true, false, err
		}
		var result string
		if op == "VEOR3" {
			first := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor <16 x i8> %s, %s\n", first, a, m)
			second := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor <16 x i8> %%%s, %s\n", second, first, n)
			result = "%" + second
		} else {
			// BCAX Vd, Vn, Vm, Va computes Vn XOR (Vm AND NOT Va).
			complement := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor <16 x i8> %s, %s\n", complement, a, arm64VectorI8Splat(-1))
			cleared := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and <16 x i8> %s, %%%s\n", cleared, m, complement)
			combined := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor <16 x i8> %s, %%%s\n", combined, n, cleared)
			result = "%" + combined
		}
		return true, false, c.storeVReg(ins.Args[3].Reg, result)

	case "VRAX1":
		if err := validateARM64SHA3D2Registers(op, ins, 3); err != nil {
			return true, false, err
		}
		m, err := c.loadARM64VectorInteger(ins.Args[0].Reg, arm64VectorArrangement{elementBits: 64, lanes: 2})
		if err != nil {
			return true, false, err
		}
		n, err := c.loadARM64VectorInteger(ins.Args[1].Reg, arm64VectorArrangement{elementBits: 64, lanes: 2})
		if err != nil {
			return true, false, err
		}
		left := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shl <2 x i64> %s, <i64 1, i64 1>\n", left, m)
		right := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr <2 x i64> %s, <i64 63, i64 63>\n", right, m)
		rotated := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or <2 x i64> %%%s, %%%s\n", rotated, left, right)
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor <2 x i64> %s, %%%s\n", result, n, rotated)
		return true, false, c.storeARM64VectorInteger(ins.Args[2].Reg, arm64VectorArrangement{elementBits: 64, lanes: 2}, "%"+result)

	case "VXAR":
		if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 4 || ins.Args[0].Kind != OpImm {
			return true, false, fmt.Errorf("arm64 VXAR expects $0..$63 and three V.D2 operands with no suffix: %q", ins.Raw)
		}
		if ins.Args[0].Imm < 0 || ins.Args[0].Imm > 63 {
			return true, false, fmt.Errorf("arm64 VXAR immediate is outside 0..63: %q", ins.Raw)
		}
		registerInstruction := ins
		registerInstruction.Args = ins.Args[1:]
		if err := validateARM64SHA3D2Registers(op, registerInstruction, 3); err != nil {
			return true, false, err
		}
		m, err := c.loadARM64VectorInteger(ins.Args[1].Reg, arm64VectorArrangement{elementBits: 64, lanes: 2})
		if err != nil {
			return true, false, err
		}
		n, err := c.loadARM64VectorInteger(ins.Args[2].Reg, arm64VectorArrangement{elementBits: 64, lanes: 2})
		if err != nil {
			return true, false, err
		}
		xored := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor <2 x i64> %s, %s\n", xored, m, n)
		result := "%" + xored
		if ins.Args[0].Imm != 0 {
			shift := ins.Args[0].Imm
			right := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = lshr <2 x i64> %%%s, <i64 %d, i64 %d>\n", right, xored, shift, shift)
			left := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shl <2 x i64> %%%s, <i64 %d, i64 %d>\n", left, xored, 64-shift, 64-shift)
			rotated := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = or <2 x i64> %%%s, %%%s\n", rotated, right, left)
			result = "%" + rotated
		}
		return true, false, c.storeARM64VectorInteger(ins.Args[3].Reg, arm64VectorArrangement{elementBits: 64, lanes: 2}, result)
	}
	return false, false, nil
}

func validateARM64SHA3D2Registers(op Op, ins Instr, count int) error {
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != count {
		return fmt.Errorf("arm64 %s expects %d V.D2 operands with no suffix: %q", op, count, ins.Raw)
	}
	for _, arg := range ins.Args {
		if arg.Kind != OpReg {
			return fmt.Errorf("arm64 %s expects only V.D2 operands: %q", op, ins.Raw)
		}
		arrangement, valid := parseARM64VectorArrangement(arg.Reg)
		if !valid || arrangement.elementBits != 64 || arrangement.lanes != 2 {
			return fmt.Errorf("arm64 %s expects only V.D2 operands: %q", op, ins.Raw)
		}
	}
	return nil
}

func arm64VectorI8Splat(value int) string {
	values := make([]string, 16)
	for i := range values {
		values[i] = fmt.Sprintf("i8 %d", value)
	}
	return "<" + strings.Join(values, ", ") + ">"
}
