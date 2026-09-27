package plan9asm

import (
	"fmt"
	"strings"
)

var arm64SVEPredicateMemoryOps = map[Op]int{
	"PLDR":  0,
	"PSTR":  0,
	"PPRFB": 8,
	"PPRFH": 16,
	"PPRFW": 32,
	"PPRFD": 64,
}

func (c *arm64Ctx) lowerARM64SVEPredicateMemory(op Op, ins Instr) (ok bool, terminated bool, err error) {
	elementBits, ok := arm64SVEPredicateMemoryOps[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) {
		return true, false, fmt.Errorf("arm64 %s does not accept an instruction suffix: %q", op, ins.Raw)
	}
	if op == "PLDR" || op == "PSTR" {
		return c.lowerARM64SVEPredicateLoadStore(op, ins)
	}
	return c.lowerARM64SVEPredicatePrefetch(op, elementBits, ins)
}

func (c *arm64Ctx) lowerARM64SVEPredicateLoadStore(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if len(ins.Args) != 2 {
		return true, false, fmt.Errorf("arm64 %s expects its two-operand Go 1.27 form: %q", op, ins.Raw)
	}
	memoryOperand := 0
	predicateOperand := 1
	if op == "PSTR" {
		predicateOperand, memoryOperand = memoryOperand, predicateOperand
	}
	if ins.Args[memoryOperand].Kind != OpMem {
		return true, false, fmt.Errorf("arm64 %s requires a MUL VL memory operand: %q", op, ins.Raw)
	}
	predicate, predicateOK := arm64ParseSVEPredicateBare(ins.Args[predicateOperand], 15)
	if !predicateOK {
		return true, false, fmt.Errorf("arm64 %s predicate must be P0..P15 without an arrangement: %q", op, ins.Raw)
	}
	address, err := c.arm64SVEVLAddress(ins.Args[memoryOperand].Mem, -256, 255, 2)
	if err != nil {
		return true, false, fmt.Errorf("arm64 %s: %w: %q", op, err, ins.Raw)
	}
	pointer := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pointer, address)
	if op == "PLDR" {
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load <vscale x 16 x i1>, ptr %%%s, align 1\n", value, pointer)
		return true, false, c.storePReg(predicate, "%"+value)
	}
	value, err := c.loadPReg(predicate)
	if err != nil {
		return true, false, err
	}
	fmt.Fprintf(c.b, "  store <vscale x 16 x i1> %s, ptr %%%s, align 1\n", value, pointer)
	return true, false, nil
}

func (c *arm64Ctx) lowerARM64SVEPredicatePrefetch(op Op, elementBits int, ins Instr) (ok bool, terminated bool, err error) {
	if len(ins.Args) != 3 || ins.Args[0].Kind != OpMem {
		return true, false, fmt.Errorf("arm64 %s expects memory, Pg, prfop: %q", op, ins.Raw)
	}
	predicate, predicateOK := arm64ParseSVEPredicateBare(ins.Args[1], 7)
	hint, hintOK := arm64SVEPrefetchHint(ins.Args[2])
	if !predicateOK || !hintOK {
		return true, false, fmt.Errorf("arm64 %s requires P0..P7 and an SVE data prefetch operation: %q", op, ins.Raw)
	}
	memory := ins.Args[0].Mem
	var address string
	if memory.Index != "" {
		address, err = c.arm64SVERegisterOffsetAddress(memory, int64(elementBits/8))
	} else {
		address, err = c.arm64SVEVLAddress(memory, -32, 31, 16)
	}
	if err != nil {
		return true, false, fmt.Errorf("arm64 %s: %w: %q", op, err, ins.Raw)
	}
	predicateValue, predicateType, err := c.loadPRegElements(predicate, elementBits)
	if err != nil {
		return true, false, err
	}
	pointer := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pointer, address)
	lanes := 128 / elementBits
	fmt.Fprintf(c.b, "  call void @llvm.aarch64.sve.prf.nxv%di1(%s %s, ptr %%%s, i32 %d)\n", lanes, predicateType, predicateValue, pointer, hint)
	return true, false, nil
}

func (c *arm64Ctx) arm64SVEVLAddress(memory MemRef, minimum, maximum, bytesPerVScale int64) (string, error) {
	if memory.Sym != "" || memory.Segment != "" || memory.Index != "" || memory.Off != 0 {
		return "", fmt.Errorf("address is not a scalar base plus MUL VL immediate")
	}
	baseReg, ok := arm64SVEPhysicalMemoryBase(memory.Base)
	if !ok {
		return "", fmt.Errorf("address base must be R0..R30, RSP, or ZR")
	}
	multiplier := int64(0)
	if memory.OffRaw != "" {
		var parsed bool
		multiplier, parsed = parseVectorLengthScaleExpr(memory.OffRaw)
		if !parsed {
			return "", fmt.Errorf("address displacement must be VL*imm")
		}
	}
	if multiplier < minimum || multiplier > maximum {
		return "", fmt.Errorf("MUL VL immediate %d is outside [%d,%d]", multiplier, minimum, maximum)
	}
	base, err := c.loadReg(baseReg)
	if err != nil {
		return "", err
	}
	if multiplier == 0 {
		return base, nil
	}
	vscale := c.newTmp()
	offset := c.newTmp()
	address := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call i64 @llvm.vscale.i64()\n", vscale)
	fmt.Fprintf(c.b, "  %%%s = mul i64 %%%s, %d\n", offset, vscale, multiplier*bytesPerVScale)
	fmt.Fprintf(c.b, "  %%%s = add i64 %s, %%%s\n", address, base, offset)
	return "%" + address, nil
}

func (c *arm64Ctx) arm64SVERegisterOffsetAddress(memory MemRef, expectedScale int64) (string, error) {
	if memory.Sym != "" || memory.Segment != "" || memory.Off != 0 || memory.OffRaw != "" || memory.IndexExt != "" || memory.Scale != expectedScale {
		return "", fmt.Errorf("register-offset address requires its exact LSL element scale")
	}
	baseReg := memory.Base
	indexReg := memory.Index
	// PPRFB's unshifted Go syntax is (Xm)(Xn|RSP); the generic Plan 9
	// memory parser records the first parenthesis as Base, so restore the
	// architectural base/index order here. Shifted H/W/D forms are normalized
	// by parseMem into the architectural order.
	if expectedScale == 1 {
		baseReg, indexReg = indexReg, baseReg
	}
	baseReg, baseOK := arm64SVEPhysicalMemoryBase(baseReg)
	if !baseOK || !isARM64GeneralOrZeroReg(indexReg) || indexReg == ZR {
		return "", fmt.Errorf("register-offset address requires R0..R30 index and scalar base")
	}
	base, err := c.loadReg(baseReg)
	if err != nil {
		return "", err
	}
	index, err := c.loadReg(indexReg)
	if err != nil {
		return "", err
	}
	scaled := index
	if expectedScale != 1 {
		shifted := c.newTmp()
		shift := map[int64]int64{2: 1, 4: 2, 8: 3, 16: 4}[expectedScale]
		fmt.Fprintf(c.b, "  %%%s = shl i64 %s, %d\n", shifted, index, shift)
		scaled = "%" + shifted
	}
	address := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add i64 %s, %s\n", address, base, scaled)
	return "%" + address, nil
}

func arm64SVEPhysicalMemoryBase(register Reg) (Reg, bool) {
	if register == Reg("RSP") || register == ZR {
		return SP, true
	}
	if isARM64GeneralOrZeroReg(register) && register != ZR {
		return register, true
	}
	return "", false
}

func arm64SVEPrefetchHint(operand Operand) (int, bool) {
	if operand.Kind != OpIdent {
		return 0, false
	}
	encoded, ok := arm64PrefetchOperations[arm64PrefetchOperation(strings.ToUpper(strings.TrimSpace(operand.Ident)))]
	if !ok || encoded >= 8 && encoded <= 13 {
		return 0, false
	}
	if encoded >= 16 {
		encoded -= 8
	}
	return int(encoded), true
}
