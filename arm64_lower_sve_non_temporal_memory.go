package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVENonTemporalMemorySpec struct {
	load       bool
	memoryBits int
	signed     bool
}

// arm64SVENonTemporalMemorySpecs covers every Go 1.27 LDNT1/STNT1 spelling:
// the ordinary B/H/W/D operations and the sign-extending gather loads.
var arm64SVENonTemporalMemorySpecs = map[Op]arm64SVENonTemporalMemorySpec{
	"ZLDNT1B":  {load: true, memoryBits: 8},
	"ZLDNT1H":  {load: true, memoryBits: 16},
	"ZLDNT1W":  {load: true, memoryBits: 32},
	"ZLDNT1D":  {load: true, memoryBits: 64},
	"ZLDNT1SB": {load: true, memoryBits: 8, signed: true},
	"ZLDNT1SH": {load: true, memoryBits: 16, signed: true},
	"ZLDNT1SW": {load: true, memoryBits: 32, signed: true},
	"ZSTNT1B":  {memoryBits: 8},
	"ZSTNT1H":  {memoryBits: 16},
	"ZSTNT1W":  {memoryBits: 32},
	"ZSTNT1D":  {memoryBits: 64},
}

func arm64SVENonTemporalMemoryNeedsSVE2P1(ins Instr) bool {
	if len(ins.Args) != 3 || ins.Args[1].Kind != OpReg {
		return false
	}
	return strings.HasPrefix(strings.ToUpper(strings.TrimSpace(string(ins.Args[1].Reg))), "PN")
}

func (c *arm64Ctx) lowerARM64SVENonTemporalMemory(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVENonTemporalMemorySpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects its three-operand Go 1.27 form: %q", op, ins.Raw)
	}
	if spec.load {
		return c.lowerARM64SVENonTemporalLoad(op, spec, ins)
	}
	return c.lowerARM64SVENonTemporalStore(op, spec, ins)
}

func (c *arm64Ctx) lowerARM64SVENonTemporalLoad(op Op, spec arm64SVENonTemporalMemorySpec, ins Instr) (ok bool, terminated bool, err error) {
	if ins.Args[0].Kind != OpMem || ins.Args[2].Kind != OpRegList {
		return true, false, fmt.Errorf("arm64 %s requires memory, predicate, vector-list operands: %q", op, ins.Raw)
	}
	vectors, elementBits, vectorsOK := arm64ParseSVEConsecutiveVectorList(ins.Args[2])
	if !vectorsOK {
		return true, false, fmt.Errorf("arm64 %s requires a consecutive, uniformly arranged Z register list: %q", op, ins.Raw)
	}
	if predicate, predicateOK := arm64ParseSVEPredicateMode(ins.Args[1], "Z", 7); predicateOK {
		if len(vectors) != 1 {
			return true, false, fmt.Errorf("arm64 %s ordinary predicate form requires one destination vector: %q", op, ins.Raw)
		}
		return c.lowerARM64SVENonTemporalSingleLoad(op, spec, ins.Args[0].Mem, predicate, vectors[0], elementBits, ins)
	}
	predicate, predicateOK := arm64ParseSVENonTemporalPN(ins.Args[1], true)
	if !predicateOK || spec.signed || (len(vectors) != 2 && len(vectors) != 4) || elementBits != spec.memoryBits {
		return true, false, fmt.Errorf("arm64 %s PN/Z form requires PN8..PN15.Z and two or four same-width destination vectors: %q", op, ins.Raw)
	}
	address, err := c.arm64SVENonTemporalContiguousAddress(ins.Args[0].Mem, spec.memoryBits, len(vectors))
	if err != nil {
		return true, false, fmt.Errorf("arm64 %s: %w: %q", op, err, ins.Raw)
	}
	pointer := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pointer, address)
	counter, err := c.loadPNReg(predicate)
	if err != nil {
		return true, false, err
	}
	vectorType, _, err := arm64SVEVectorType(elementBits)
	if err != nil {
		return true, false, err
	}
	aggregateType := arm64SVEAggregateType(vectorType, len(vectors))
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.ldnt1.pn.x%d.nxv%di%d(target(\"aarch64.svcount\") %s, ptr %%%s)\n",
		result, aggregateType, len(vectors), 128/elementBits, elementBits, counter, pointer)
	for i, vector := range vectors {
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractvalue %s %%%s, %d\n", value, aggregateType, result, i)
		if err := c.storeZRegElements(vector, elementBits, "%"+value); err != nil {
			return true, false, err
		}
	}
	return true, false, nil
}

func (c *arm64Ctx) lowerARM64SVENonTemporalSingleLoad(op Op, spec arm64SVENonTemporalMemorySpec, memory MemRef, predicate, destination, elementBits int, ins Instr) (ok bool, terminated bool, err error) {
	predicateValue, predicateType, err := c.loadPRegElements(predicate, elementBits)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / elementBits
	if vectorBase, vectorBaseBits, vectorBaseOK := arm64ParseSVEZElementReg(Operand{Kind: OpReg, Reg: memory.Index}); vectorBaseOK {
		if vectorBaseBits != elementBits || elementBits < spec.memoryBits || (elementBits != 32 && elementBits != 64) || !arm64SVENonTemporalVectorBaseAddressOK(memory) {
			return true, false, fmt.Errorf("arm64 %s vector-base form has widths or address operands outside its Go 1.27 table: %q", op, ins.Raw)
		}
		bases, baseType, err := c.loadZRegElements(vectorBase, vectorBaseBits)
		if err != nil {
			return true, false, err
		}
		offset, err := c.loadReg(memory.Base)
		if err != nil {
			return true, false, err
		}
		loadedType := fmt.Sprintf("<vscale x %d x i%d>", lanes, spec.memoryBits)
		loaded := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.ldnt1.gather.scalar.offset.nxv%di%d.nxv%di%d(%s %s, %s %s, i64 %s)\n",
			loaded, loadedType, lanes, spec.memoryBits, lanes, elementBits, predicateType, predicateValue, baseType, bases, offset)
		value := "%" + loaded
		if spec.memoryBits < elementBits {
			extended := c.newTmp()
			extension := "zext"
			if spec.signed {
				extension = "sext"
			}
			vectorType, _, _ := arm64SVEVectorType(elementBits)
			fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", extended, extension, loadedType, value, vectorType)
			value = "%" + extended
		}
		return true, false, c.storeZRegElements(destination, elementBits, value)
	}
	if spec.signed || elementBits != spec.memoryBits {
		return true, false, fmt.Errorf("arm64 %s contiguous form requires its natural %d-bit arrangement: %q", op, spec.memoryBits, ins.Raw)
	}
	address, err := c.arm64SVENonTemporalContiguousAddress(memory, spec.memoryBits, 1)
	if err != nil {
		return true, false, fmt.Errorf("arm64 %s: %w: %q", op, err, ins.Raw)
	}
	pointer := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pointer, address)
	vectorType, _, _ := arm64SVEVectorType(elementBits)
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.ldnt1.nxv%di%d(%s %s, ptr %%%s)\n",
		result, vectorType, lanes, elementBits, predicateType, predicateValue, pointer)
	return true, false, c.storeZRegElements(destination, elementBits, "%"+result)
}

func (c *arm64Ctx) lowerARM64SVENonTemporalStore(op Op, spec arm64SVENonTemporalMemorySpec, ins Instr) (ok bool, terminated bool, err error) {
	if ins.Args[0].Kind != OpRegList || ins.Args[2].Kind != OpMem {
		return true, false, fmt.Errorf("arm64 %s requires vector-list, predicate, memory operands: %q", op, ins.Raw)
	}
	vectors, elementBits, vectorsOK := arm64ParseSVEConsecutiveVectorList(ins.Args[0])
	if !vectorsOK {
		return true, false, fmt.Errorf("arm64 %s requires a consecutive, uniformly arranged Z register list: %q", op, ins.Raw)
	}
	if predicate, predicateOK := arm64ParseSVEPredicateBare(ins.Args[1], 7); predicateOK {
		if len(vectors) != 1 {
			return true, false, fmt.Errorf("arm64 %s ordinary predicate form requires one source vector: %q", op, ins.Raw)
		}
		return c.lowerARM64SVENonTemporalSingleStore(op, spec, ins.Args[2].Mem, predicate, vectors[0], elementBits, ins)
	}
	predicate, predicateOK := arm64ParseSVENonTemporalPN(ins.Args[1], false)
	if !predicateOK || (len(vectors) != 2 && len(vectors) != 4) || elementBits != spec.memoryBits {
		return true, false, fmt.Errorf("arm64 %s PN form requires PN8..PN15 and two or four same-width source vectors: %q", op, ins.Raw)
	}
	address, err := c.arm64SVENonTemporalContiguousAddress(ins.Args[2].Mem, spec.memoryBits, len(vectors))
	if err != nil {
		return true, false, fmt.Errorf("arm64 %s: %w: %q", op, err, ins.Raw)
	}
	pointer := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pointer, address)
	counter, err := c.loadPNReg(predicate)
	if err != nil {
		return true, false, err
	}
	vectorType, _, err := arm64SVEVectorType(elementBits)
	if err != nil {
		return true, false, err
	}
	values := make([]string, 0, len(vectors))
	for _, vector := range vectors {
		value, _, err := c.loadZRegElements(vector, elementBits)
		if err != nil {
			return true, false, err
		}
		values = append(values, fmt.Sprintf("%s %s", vectorType, value))
	}
	fmt.Fprintf(c.b, "  call void @llvm.aarch64.sve.stnt1.pn.x%d.nxv%di%d(%s, target(\"aarch64.svcount\") %s, ptr %%%s)\n",
		len(vectors), 128/elementBits, elementBits, strings.Join(values, ", "), counter, pointer)
	return true, false, nil
}

func (c *arm64Ctx) lowerARM64SVENonTemporalSingleStore(op Op, spec arm64SVENonTemporalMemorySpec, memory MemRef, predicate, source, elementBits int, ins Instr) (ok bool, terminated bool, err error) {
	if elementBits < spec.memoryBits {
		return true, false, fmt.Errorf("arm64 %s source arrangement is narrower than its memory element: %q", op, ins.Raw)
	}
	value, vectorType, err := c.loadZRegElements(source, elementBits)
	if err != nil {
		return true, false, err
	}
	predicateValue, predicateType, err := c.loadPRegElements(predicate, elementBits)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / elementBits
	if vectorBase, vectorBaseBits, vectorBaseOK := arm64ParseSVEZElementReg(Operand{Kind: OpReg, Reg: memory.Index}); vectorBaseOK {
		if vectorBaseBits != elementBits || (elementBits != 32 && elementBits != 64) || !arm64SVENonTemporalVectorBaseAddressOK(memory) {
			return true, false, fmt.Errorf("arm64 %s vector-base form has widths or address operands outside its Go 1.27 table: %q", op, ins.Raw)
		}
		bases, baseType, err := c.loadZRegElements(vectorBase, vectorBaseBits)
		if err != nil {
			return true, false, err
		}
		offset, err := c.loadReg(memory.Base)
		if err != nil {
			return true, false, err
		}
		storedType := vectorType
		stored := value
		if spec.memoryBits < elementBits {
			storedType = fmt.Sprintf("<vscale x %d x i%d>", lanes, spec.memoryBits)
			truncated := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc %s %s to %s\n", truncated, vectorType, value, storedType)
			stored = "%" + truncated
		}
		fmt.Fprintf(c.b, "  call void @llvm.aarch64.sve.stnt1.scatter.scalar.offset.nxv%di%d.nxv%di%d(%s %s, %s %s, %s %s, i64 %s)\n",
			lanes, spec.memoryBits, lanes, elementBits, storedType, stored, predicateType, predicateValue, baseType, bases, offset)
		return true, false, nil
	}
	if elementBits != spec.memoryBits {
		return true, false, fmt.Errorf("arm64 %s contiguous form requires its natural %d-bit arrangement: %q", op, spec.memoryBits, ins.Raw)
	}
	address, err := c.arm64SVENonTemporalContiguousAddress(memory, spec.memoryBits, 1)
	if err != nil {
		return true, false, fmt.Errorf("arm64 %s: %w: %q", op, err, ins.Raw)
	}
	pointer := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pointer, address)
	fmt.Fprintf(c.b, "  call void @llvm.aarch64.sve.stnt1.nxv%di%d(%s %s, %s %s, ptr %%%s)\n",
		lanes, elementBits, vectorType, value, predicateType, predicateValue, pointer)
	return true, false, nil
}

func arm64ParseSVEConsecutiveVectorList(operand Operand) (vectors []int, elementBits int, ok bool) {
	if operand.Kind != OpRegList || len(operand.RegList) == 0 {
		return nil, 0, false
	}
	vectors = make([]int, len(operand.RegList))
	for i, register := range operand.RegList {
		vector, bits, valid := arm64ParseSVEZElementReg(Operand{Kind: OpReg, Reg: register})
		if !valid || i > 0 && (bits != elementBits || vector != vectors[i-1]+1) {
			return nil, 0, false
		}
		vectors[i] = vector
		elementBits = bits
	}
	return vectors, elementBits, true
}

func arm64ParseSVENonTemporalPN(operand Operand, zeroing bool) (int, bool) {
	if operand.Kind != OpReg {
		return 0, false
	}
	text := strings.ToUpper(strings.TrimSpace(string(operand.Reg)))
	wantSuffix := ""
	if zeroing {
		wantSuffix = ".Z"
	}
	if !strings.HasSuffix(text, wantSuffix) {
		return 0, false
	}
	name := strings.TrimSuffix(text, wantSuffix)
	if strings.Contains(name, ".") || !strings.HasPrefix(name, "PN") {
		return 0, false
	}
	var index int
	if _, err := fmt.Sscanf(name, "PN%d", &index); err != nil || index < 8 || index > 15 {
		return 0, false
	}
	return index, true
}

func arm64SVENonTemporalVectorBaseAddressOK(memory MemRef) bool {
	return memory.Sym == "" && memory.Segment == "" && memory.Off == 0 && memory.OffRaw == "" && memory.IndexExt == "" && memory.Scale == 1 &&
		isARM64GeneralOrZeroReg(memory.Base) && memory.Base != SP && memory.Base != Reg("RSP")
}

func (c *arm64Ctx) arm64SVENonTemporalContiguousAddress(memory MemRef, elementBits, vectorCount int) (string, error) {
	if memory.Index != "" {
		if _, _, vectorIndex := arm64ParseSVEZElementReg(Operand{Kind: OpReg, Reg: memory.Index}); vectorIndex {
			return "", fmt.Errorf("contiguous form does not accept a scalable-vector base")
		}
		return c.arm64SVERegisterOffsetAddress(memory, int64(elementBits/8))
	}
	minimum, maximum := int64(-8), int64(7)
	if vectorCount == 2 {
		minimum, maximum = -16, 14
	} else if vectorCount == 3 {
		minimum, maximum = -24, 21
	} else if vectorCount == 4 {
		minimum, maximum = -32, 28
	} else if vectorCount != 1 {
		return "", fmt.Errorf("contiguous form requires one, two, three, or four vectors")
	}
	if memory.OffRaw != "" {
		multiplier, parsed := parseVectorLengthScaleExpr(memory.OffRaw)
		if !parsed || multiplier%int64(vectorCount) != 0 {
			return "", fmt.Errorf("MUL VL immediate must be a multiple of %d", vectorCount)
		}
	}
	return c.arm64SVEVLAddress(memory, minimum, maximum, 16)
}

func arm64SVEAggregateType(vectorType string, count int) string {
	values := make([]string, count)
	for i := range values {
		values[i] = vectorType
	}
	return "{ " + strings.Join(values, ", ") + " }"
}
