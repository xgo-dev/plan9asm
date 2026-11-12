package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVEStructuredMemorySpec struct {
	load        bool
	vectorCount int
	memoryBits  int
	q           bool
}

// arm64SVEStructuredMemorySpecs covers every Go 1.27 LD2/3/4 and ST2/3/4
// structured SVE spelling, including the SVE2.1 Q-granule forms.
var arm64SVEStructuredMemorySpecs = map[Op]arm64SVEStructuredMemorySpec{
	"ZLD2B": {load: true, vectorCount: 2, memoryBits: 8},
	"ZLD2H": {load: true, vectorCount: 2, memoryBits: 16},
	"ZLD2W": {load: true, vectorCount: 2, memoryBits: 32},
	"ZLD2D": {load: true, vectorCount: 2, memoryBits: 64},
	"ZLD2Q": {load: true, vectorCount: 2, memoryBits: 128, q: true},
	"ZLD3B": {load: true, vectorCount: 3, memoryBits: 8},
	"ZLD3H": {load: true, vectorCount: 3, memoryBits: 16},
	"ZLD3W": {load: true, vectorCount: 3, memoryBits: 32},
	"ZLD3D": {load: true, vectorCount: 3, memoryBits: 64},
	"ZLD3Q": {load: true, vectorCount: 3, memoryBits: 128, q: true},
	"ZLD4B": {load: true, vectorCount: 4, memoryBits: 8},
	"ZLD4H": {load: true, vectorCount: 4, memoryBits: 16},
	"ZLD4W": {load: true, vectorCount: 4, memoryBits: 32},
	"ZLD4D": {load: true, vectorCount: 4, memoryBits: 64},
	"ZLD4Q": {load: true, vectorCount: 4, memoryBits: 128, q: true},
	"ZST2B": {vectorCount: 2, memoryBits: 8},
	"ZST2H": {vectorCount: 2, memoryBits: 16},
	"ZST2W": {vectorCount: 2, memoryBits: 32},
	"ZST2D": {vectorCount: 2, memoryBits: 64},
	"ZST2Q": {vectorCount: 2, memoryBits: 128, q: true},
	"ZST3B": {vectorCount: 3, memoryBits: 8},
	"ZST3H": {vectorCount: 3, memoryBits: 16},
	"ZST3W": {vectorCount: 3, memoryBits: 32},
	"ZST3D": {vectorCount: 3, memoryBits: 64},
	"ZST3Q": {vectorCount: 3, memoryBits: 128, q: true},
	"ZST4B": {vectorCount: 4, memoryBits: 8},
	"ZST4H": {vectorCount: 4, memoryBits: 16},
	"ZST4W": {vectorCount: 4, memoryBits: 32},
	"ZST4D": {vectorCount: 4, memoryBits: 64},
	"ZST4Q": {vectorCount: 4, memoryBits: 128, q: true},
}

func (c *arm64Ctx) lowerARM64SVEStructuredMemory(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVEStructuredMemorySpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects its three-operand Go 1.27 form: %q", op, ins.Raw)
	}
	if spec.load {
		return c.lowerARM64SVEStructuredLoad(op, spec, ins)
	}
	return c.lowerARM64SVEStructuredStore(op, spec, ins)
}

func (c *arm64Ctx) lowerARM64SVEStructuredLoad(op Op, spec arm64SVEStructuredMemorySpec, ins Instr) (ok bool, terminated bool, err error) {
	if ins.Args[0].Kind != OpMem || ins.Args[2].Kind != OpRegList {
		return true, false, fmt.Errorf("arm64 %s requires memory, Pn.Z, and vector-list operands: %q", op, ins.Raw)
	}
	predicate, predicateOK := arm64ParseSVEPredicateMode(ins.Args[1], "Z", 7)
	vectors, elementBits, vectorsOK := arm64ParseSVEStructuredVectorList(ins.Args[2], spec.vectorCount)
	if !predicateOK || !vectorsOK || elementBits != spec.memoryBits {
		return true, false, fmt.Errorf("arm64 %s requires P0..P7.Z and %d consecutive natural-width destination vectors: %q", op, spec.vectorCount, ins.Raw)
	}
	address, err := c.arm64SVEStructuredAddress(ins.Args[0].Mem, spec)
	if err != nil {
		return true, false, fmt.Errorf("arm64 %s: %w: %q", op, err, ins.Raw)
	}
	valueBits := spec.memoryBits
	if spec.q {
		valueBits = 64
	}
	predicateValue, predicateType, err := c.loadPRegElements(predicate, valueBits)
	if err != nil {
		return true, false, err
	}
	vectorType, _, err := arm64SVEVectorType(valueBits)
	if err != nil {
		return true, false, err
	}
	pointer := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pointer, address)
	aggregateType := arm64SVEAggregateType(vectorType, spec.vectorCount)
	result := c.newTmp()
	q := ""
	if spec.q {
		q = "q"
	}
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.ld%d%s.sret.nxv%di%d(%s %s, ptr %%%s)\n",
		result, aggregateType, spec.vectorCount, q, 128/valueBits, valueBits, predicateType, predicateValue, pointer)
	for i, vector := range vectors {
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractvalue %s %%%s, %d\n", value, aggregateType, result, i)
		if err := c.storeZRegElements(vector, valueBits, "%"+value); err != nil {
			return true, false, err
		}
	}
	return true, false, nil
}

func (c *arm64Ctx) lowerARM64SVEStructuredStore(op Op, spec arm64SVEStructuredMemorySpec, ins Instr) (ok bool, terminated bool, err error) {
	if ins.Args[0].Kind != OpRegList || ins.Args[2].Kind != OpMem {
		return true, false, fmt.Errorf("arm64 %s requires vector-list, Pn, and memory operands: %q", op, ins.Raw)
	}
	predicate, predicateOK := arm64ParseSVEPredicateBare(ins.Args[1], 7)
	vectors, elementBits, vectorsOK := arm64ParseSVEStructuredVectorList(ins.Args[0], spec.vectorCount)
	if !predicateOK || !vectorsOK || elementBits != spec.memoryBits {
		return true, false, fmt.Errorf("arm64 %s requires %d consecutive natural-width source vectors and P0..P7: %q", op, spec.vectorCount, ins.Raw)
	}
	address, err := c.arm64SVEStructuredAddress(ins.Args[2].Mem, spec)
	if err != nil {
		return true, false, fmt.Errorf("arm64 %s: %w: %q", op, err, ins.Raw)
	}
	valueBits := spec.memoryBits
	if spec.q {
		valueBits = 64
	}
	predicateValue, predicateType, err := c.loadPRegElements(predicate, valueBits)
	if err != nil {
		return true, false, err
	}
	vectorType, _, err := arm64SVEVectorType(valueBits)
	if err != nil {
		return true, false, err
	}
	values := make([]string, len(vectors))
	for i, vector := range vectors {
		value, _, err := c.loadZRegElements(vector, valueBits)
		if err != nil {
			return true, false, err
		}
		values[i] = fmt.Sprintf("%s %s", vectorType, value)
	}
	pointer := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pointer, address)
	q := ""
	if spec.q {
		q = "q"
	}
	fmt.Fprintf(c.b, "  call void @llvm.aarch64.sve.st%d%s.nxv%di%d(%s, %s %s, ptr %%%s)\n",
		spec.vectorCount, q, 128/valueBits, valueBits, strings.Join(values, ", "), predicateType, predicateValue, pointer)
	return true, false, nil
}

func (c *arm64Ctx) arm64SVEStructuredAddress(memory MemRef, spec arm64SVEStructuredMemorySpec) (string, error) {
	if memory.Index != "" {
		return c.arm64SVERegisterOffsetAddress(memory, int64(spec.memoryBits/8))
	}
	return c.arm64SVENonTemporalContiguousAddress(memory, spec.memoryBits, spec.vectorCount)
}

func arm64ParseSVEStructuredVectorList(operand Operand, count int) (vectors []int, elementBits int, ok bool) {
	if operand.Kind != OpRegList || len(operand.RegList) != count {
		return nil, 0, false
	}
	vectors = make([]int, len(operand.RegList))
	for i, register := range operand.RegList {
		vector, bits, valid := arm64ParseSVEOrdinaryZReg(register)
		if !valid || i > 0 && (bits != elementBits || vector != (vectors[i-1]+1)%32) {
			return nil, 0, false
		}
		vectors[i] = vector
		elementBits = bits
	}
	return vectors, elementBits, true
}
