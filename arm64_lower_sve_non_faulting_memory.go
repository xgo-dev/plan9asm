package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVENonFaultingMemorySpec struct {
	memoryBits int
	signed     bool
}

// arm64SVENonFaultingMemorySpecs covers all 16 Go 1.27 LDNF1 encoder forms:
// natural-width and widening unsigned loads plus the widening signed forms.
var arm64SVENonFaultingMemorySpecs = map[Op]arm64SVENonFaultingMemorySpec{
	"ZLDNF1B":  {memoryBits: 8},
	"ZLDNF1H":  {memoryBits: 16},
	"ZLDNF1W":  {memoryBits: 32},
	"ZLDNF1D":  {memoryBits: 64},
	"ZLDNF1SB": {memoryBits: 8, signed: true},
	"ZLDNF1SH": {memoryBits: 16, signed: true},
	"ZLDNF1SW": {memoryBits: 32, signed: true},
}

func (c *arm64Ctx) lowerARM64SVENonFaultingMemory(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVENonFaultingMemorySpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 || ins.Args[0].Kind != OpMem || ins.Args[2].Kind != OpRegList {
		return true, false, fmt.Errorf("arm64 %s expects memory, predicate, vector-list operands: %q", op, ins.Raw)
	}
	predicate, predicateOK := arm64ParseSVEPredicateMode(ins.Args[1], "Z", 7)
	vectors, elementBits, vectorsOK := arm64ParseSVEConsecutiveVectorList(ins.Args[2])
	if !predicateOK || !vectorsOK || len(vectors) != 1 || elementBits < spec.memoryBits || spec.signed && elementBits == spec.memoryBits {
		return true, false, fmt.Errorf("arm64 %s has predicate or destination widths outside its Go 1.27 table: %q", op, ins.Raw)
	}
	address, err := c.arm64SVEVLAddress(ins.Args[0].Mem, -8, 7, int64(16*spec.memoryBits/elementBits))
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
	loadedType := fmt.Sprintf("<vscale x %d x i%d>", lanes, spec.memoryBits)
	loaded := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.ldnf1.nxv%di%d(%s %s, ptr %%%s)\n",
		loaded, loadedType, lanes, spec.memoryBits, predicateType, predicateValue, pointer)
	value := "%" + loaded
	if spec.memoryBits < elementBits {
		vectorType, _, err := arm64SVEVectorType(elementBits)
		if err != nil {
			return true, false, err
		}
		extended := c.newTmp()
		extension := "zext"
		if spec.signed {
			extension = "sext"
		}
		fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", extended, extension, loadedType, value, vectorType)
		value = "%" + extended
	}
	return true, false, c.storeZRegElements(vectors[0], elementBits, value)
}
