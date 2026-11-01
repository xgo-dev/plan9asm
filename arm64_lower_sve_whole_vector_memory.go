package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
)

var arm64SVEWholeVectorMemoryOps = map[Op]bool{
	"ZLDR": true,
	"ZSTR": false,
}

func (c *arm64Ctx) lowerARM64SVEWholeVectorMemory(op Op, ins Instr) (ok bool, terminated bool, err error) {
	load, ok := arm64SVEWholeVectorMemoryOps[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 {
		return true, false, fmt.Errorf("arm64 %s expects its two-operand Go 1.27 form: %q", op, ins.Raw)
	}
	memoryOperand := 0
	vectorOperand := 1
	if !load {
		vectorOperand, memoryOperand = memoryOperand, vectorOperand
	}
	vector, vectorOK := arm64ParseSVEBareZReg(ins.Args[vectorOperand])
	if !vectorOK || ins.Args[memoryOperand].Kind != OpMem {
		return true, false, fmt.Errorf("arm64 %s requires a MUL VL address and bare Z0..Z31: %q", op, ins.Raw)
	}
	address, err := c.arm64SVEVLAddress(ins.Args[memoryOperand].Mem, -256, 255, 16)
	if err != nil {
		return true, false, fmt.Errorf("arm64 %s: %w: %q", op, err, ins.Raw)
	}
	pointer := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pointer, address)
	if load {
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load <vscale x 16 x i8>, ptr %%%s, align 1\n", value, pointer)
		return true, false, c.storeZReg(vector, "%"+value)
	}
	value, err := c.loadZReg(vector)
	if err != nil {
		return true, false, err
	}
	fmt.Fprintf(c.b, "  store <vscale x 16 x i8> %s, ptr %%%s, align 1\n", value, pointer)
	return true, false, nil
}

func arm64ParseSVEBareZReg(operand Operand) (int, bool) {
	if operand.Kind != OpReg {
		return 0, false
	}
	name := strings.ToUpper(strings.TrimSpace(string(operand.Reg)))
	if strings.Contains(name, ".") || !strings.HasPrefix(name, "Z") {
		return 0, false
	}
	index, err := strconv.Atoi(strings.TrimPrefix(name, "Z"))
	return index, err == nil && index >= 0 && index <= 31
}
