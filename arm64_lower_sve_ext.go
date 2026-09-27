package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) lowerARM64SVEEXT(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZEXT" && op != "ZEXTQ" {
		return false, false, nil
	}
	if op == "ZEXTQ" {
		return c.lowerARM64SVEEXTQ(ins)
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) < 3 || len(ins.Args) > 4 ||
		ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" || ins.Args[0].Imm < 0 || ins.Args[0].Imm > 255 {
		return true, false, fmt.Errorf("arm64 ZEXT expects an unsigned 8-bit immediate and one Go 1.27 vector form: %q", ins.Raw)
	}
	immediate := ins.Args[0].Imm
	var first, second, destination int
	if len(ins.Args) == 4 {
		var firstOK, secondOK, destinationOK bool
		second, secondOK = arm64ParseSVEByteReg(ins.Args[1])
		first, firstOK = arm64ParseSVEByteReg(ins.Args[2])
		destination, destinationOK = arm64ParseSVEByteReg(ins.Args[3])
		if !firstOK || !secondOK || !destinationOK || first != destination {
			return true, false, fmt.Errorf("arm64 ZEXT destructive form requires $imm, Zm.B, Zdn.B, Zdn.B: %q", ins.Raw)
		}
	} else {
		if ins.Args[1].Kind != OpRegList || len(ins.Args[1].RegList) != 2 {
			return true, false, fmt.Errorf("arm64 ZEXT list form requires exactly two consecutive byte vectors: %q", ins.Raw)
		}
		var firstOK, secondOK, destinationOK bool
		first, firstOK = arm64ParseSVEByteReg(Operand{Kind: OpReg, Reg: ins.Args[1].RegList[0]})
		second, secondOK = arm64ParseSVEByteReg(Operand{Kind: OpReg, Reg: ins.Args[1].RegList[1]})
		destination, destinationOK = arm64ParseSVEByteReg(ins.Args[2])
		if !firstOK || !secondOK || !destinationOK || first == 31 || second != first+1 {
			return true, false, fmt.Errorf("arm64 ZEXT list form requires [Zn.B, Z(n+1).B], Zd.B: %q", ins.Raw)
		}
	}
	firstValue, err := c.loadZReg(first)
	if err != nil {
		return true, false, err
	}
	secondValue, err := c.loadZReg(second)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call <vscale x 16 x i8> @llvm.aarch64.sve.ext.nxv16i8(<vscale x 16 x i8> %s, <vscale x 16 x i8> %s, i32 %d)\n",
		result, firstValue, secondValue, immediate)
	return true, false, c.storeZReg(destination, "%"+result)
}

func (c *arm64Ctx) lowerARM64SVEEXTQ(ins Instr) (ok bool, terminated bool, err error) {
	if strings.ToUpper(string(ins.Op)) != "ZEXTQ" || len(ins.Args) != 4 ||
		ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" || ins.Args[0].Imm < 0 || ins.Args[0].Imm > 15 {
		return true, false, fmt.Errorf("arm64 ZEXTQ expects $imm4, Zm.B, Zdn.B, Zdn.B without a suffix: %q", ins.Raw)
	}
	second, secondOK := arm64ParseSVEByteReg(ins.Args[1])
	first, firstOK := arm64ParseSVEByteReg(ins.Args[2])
	destination, destinationOK := arm64ParseSVEByteReg(ins.Args[3])
	if !firstOK || !secondOK || !destinationOK || first != destination {
		return true, false, fmt.Errorf("arm64 ZEXTQ requires matching destructive byte-vector operands: %q", ins.Raw)
	}
	firstValue, err := c.loadZReg(first)
	if err != nil {
		return true, false, err
	}
	secondValue, err := c.loadZReg(second)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call <vscale x 16 x i8> @llvm.aarch64.sve.extq.nxv16i8(<vscale x 16 x i8> %s, <vscale x 16 x i8> %s, i32 %d)\n",
		result, firstValue, secondValue, ins.Args[0].Imm)
	return true, false, c.storeZReg(destination, "%"+result)
}

func arm64ParseSVEByteReg(operand Operand) (int, bool) {
	index, bits, ok := arm64ParseSVEZElementReg(operand)
	return index, ok && bits == 8
}
