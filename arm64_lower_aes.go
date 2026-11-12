package plan9asm

import (
	"fmt"
	"strings"
)

type arm64RawAES struct {
	op          Op
	source      int
	destination int
}

func decodeARM64RawAES(word uint32) (arm64RawAES, bool) {
	var op Op
	switch word & 0xfffffc00 {
	case 0x4e284800:
		op = "AESE"
	case 0x4e285800:
		op = "AESD"
	case 0x4e286800:
		op = "AESMC"
	case 0x4e287800:
		op = "AESIMC"
	default:
		return arm64RawAES{}, false
	}
	return arm64RawAES{
		op:          op,
		source:      int(word>>5) & 31,
		destination: int(word) & 31,
	}, true
}

func (c *arm64Ctx) lowerRawAES(form arm64RawAES) error {
	reg := func(index int) Operand {
		return Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("V%d.B16", index))}
	}
	ins := Instr{
		Op:   form.op,
		Raw:  "decoded ARM64 WORD as " + string(form.op),
		Args: []Operand{reg(form.source), reg(form.destination)},
	}
	ok, _, err := c.lowerARM64AES(form.op, ins)
	if !ok && err == nil {
		return fmt.Errorf("arm64 raw %s decoder reached no semantic lowerer", form.op)
	}
	return err
}

func (c *arm64Ctx) lowerARM64AES(op Op, ins Instr) (ok bool, terminated bool, err error) {
	switch op {
	case "AESE", "AESD", "AESMC", "AESIMC":
	default:
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 {
		return true, false, fmt.Errorf("arm64 %s expects two bare V registers or two V.B16 registers with no suffix: %q", op, ins.Raw)
	}

	bare := false
	arranged := false
	for _, arg := range ins.Args {
		if arg.Kind != OpReg {
			return true, false, fmt.Errorf("arm64 %s expects two vector registers: %q", op, ins.Raw)
		}
		if _, valid := arm64ParseVReg(arg.Reg); !valid {
			return true, false, fmt.Errorf("arm64 %s expects two vector registers: %q", op, ins.Raw)
		}
		if strings.Contains(string(arg.Reg), ".") {
			arrangement, valid := parseARM64VectorArrangement(arg.Reg)
			if !valid || arrangement != (arm64VectorArrangement{elementBits: 8, lanes: 16}) {
				return true, false, fmt.Errorf("arm64 %s expects V.B16 operands: %q", op, ins.Raw)
			}
			arranged = true
		} else {
			bare = true
		}
	}
	if bare && arranged {
		return true, false, fmt.Errorf("arm64 %s cannot mix bare and arranged vector registers: %q", op, ins.Raw)
	}

	source, err := c.loadVReg(ins.Args[0].Reg)
	if err != nil {
		return true, false, err
	}
	var result string
	if op == "AESE" || op == "AESD" {
		destination, err := c.loadVReg(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call <16 x i8> @llvm.aarch64.crypto.%s(<16 x i8> %s, <16 x i8> %s)\n", value, strings.ToLower(string(op)), destination, source)
		result = "%" + value
	} else {
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call <16 x i8> @llvm.aarch64.crypto.%s(<16 x i8> %s)\n", value, strings.ToLower(string(op)), source)
		result = "%" + value
	}
	return true, false, c.storeVReg(ins.Args[1].Reg, result)
}
