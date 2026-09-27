package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
)

type arm64SVEOrdinaryMemorySpec struct {
	load       bool
	memoryBits int
	signed     bool
	qOnly      bool
}

// arm64SVEOrdinaryMemorySpecs covers the complete Go 1.27 LD1/ST1 family:
// ordinary and widening loads, truncating stores, Q-granule forms, and the
// SVE2.1 two-/four-vector PN forms.
var arm64SVEOrdinaryMemorySpecs = map[Op]arm64SVEOrdinaryMemorySpec{
	"ZLD1B":  {load: true, memoryBits: 8},
	"ZLD1H":  {load: true, memoryBits: 16},
	"ZLD1W":  {load: true, memoryBits: 32},
	"ZLD1D":  {load: true, memoryBits: 64},
	"ZLD1Q":  {load: true, memoryBits: 128, qOnly: true},
	"ZLD1SB": {load: true, memoryBits: 8, signed: true},
	"ZLD1SH": {load: true, memoryBits: 16, signed: true},
	"ZLD1SW": {load: true, memoryBits: 32, signed: true},
	"ZST1B":  {memoryBits: 8},
	"ZST1H":  {memoryBits: 16},
	"ZST1W":  {memoryBits: 32},
	"ZST1D":  {memoryBits: 64},
	"ZST1Q":  {memoryBits: 128, qOnly: true},
}

func arm64SVEOrdinaryMemoryNeedsSVE2P1(ins Instr) bool {
	for _, operand := range ins.Args {
		if operand.Kind == OpReg && strings.HasPrefix(strings.ToUpper(strings.TrimSpace(string(operand.Reg))), "PN") {
			return true
		}
		if operand.Kind == OpRegList {
			for _, register := range operand.RegList {
				if strings.HasSuffix(strings.ToUpper(strings.TrimSpace(string(register))), ".Q") {
					return true
				}
			}
		}
	}
	op := Op(strings.ToUpper(string(ins.Op)))
	return op == "ZLD1Q" || op == "ZST1Q"
}

func (c *arm64Ctx) lowerARM64SVEOrdinaryMemory(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVEOrdinaryMemorySpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects its three-operand Go 1.27 form: %q", op, ins.Raw)
	}
	if spec.load {
		return c.lowerARM64SVEOrdinaryLoad(op, spec, ins)
	}
	return c.lowerARM64SVEOrdinaryStore(op, spec, ins)
}

func (c *arm64Ctx) lowerARM64SVEOrdinaryLoad(op Op, spec arm64SVEOrdinaryMemorySpec, ins Instr) (ok bool, terminated bool, err error) {
	if ins.Args[0].Kind != OpMem || ins.Args[2].Kind != OpRegList {
		return true, false, fmt.Errorf("arm64 %s requires memory, predicate, vector-list operands: %q", op, ins.Raw)
	}
	vectors, elementBits, vectorsOK := arm64ParseSVEOrdinaryVectorList(ins.Args[2])
	if !vectorsOK {
		return true, false, fmt.Errorf("arm64 %s requires a consecutive, uniformly arranged Z register list: %q", op, ins.Raw)
	}
	if predicate, predicateOK := arm64ParseSVEPredicateMode(ins.Args[1], "Z", 7); predicateOK {
		if len(vectors) != 1 {
			return true, false, fmt.Errorf("arm64 %s ordinary predicate form requires one destination vector: %q", op, ins.Raw)
		}
		return c.lowerARM64SVEOrdinarySingleLoad(op, spec, ins.Args[0].Mem, predicate, vectors[0], elementBits, ins)
	}
	predicate, predicateOK := arm64ParseSVENonTemporalPN(ins.Args[1], true)
	if !predicateOK || spec.signed || spec.qOnly || (len(vectors) != 2 && len(vectors) != 4) || elementBits != spec.memoryBits {
		return true, false, fmt.Errorf("arm64 %s PN/Z form requires PN8..PN15.Z and two or four natural-width destination vectors: %q", op, ins.Raw)
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
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.ld1.pn.x%d.nxv%di%d(target(\"aarch64.svcount\") %s, ptr %%%s)\n",
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

func (c *arm64Ctx) lowerARM64SVEOrdinarySingleLoad(op Op, spec arm64SVEOrdinaryMemorySpec, memory MemRef, predicate, destination, elementBits int, ins Instr) (ok bool, terminated bool, err error) {
	if spec.qOnly {
		return c.lowerARM64SVEOrdinaryQGatherLoad(op, memory, predicate, destination, elementBits, ins)
	}
	if elementBits == 128 {
		if spec.signed || (spec.memoryBits != 32 && spec.memoryBits != 64) {
			return true, false, fmt.Errorf("arm64 %s Q arrangement is outside its Go 1.27 table: %q", op, ins.Raw)
		}
		return c.lowerARM64SVEOrdinaryQContiguousLoad(op, spec, memory, predicate, destination, ins)
	}
	if elementBits < spec.memoryBits || spec.signed && elementBits == spec.memoryBits {
		return true, false, fmt.Errorf("arm64 %s destination width is outside its Go 1.27 table: %q", op, ins.Raw)
	}
	if _, _, vectorOffset := arm64ParseSVEZElementReg(Operand{Kind: OpReg, Reg: memory.Index}); vectorOffset {
		return c.lowerARM64SVEOrdinaryVectorOffsetLoad(op, spec, memory, predicate, destination, elementBits, ins)
	}
	if _, _, vectorBase := arm64ParseSVEZElementReg(Operand{Kind: OpReg, Reg: memory.Base}); vectorBase {
		return c.lowerARM64SVEOrdinaryVectorBaseLoad(op, spec, memory, predicate, destination, elementBits, ins)
	}
	address, err := c.arm64SVEOrdinaryContiguousAddress(memory, spec.memoryBits, elementBits)
	if err != nil {
		return true, false, fmt.Errorf("arm64 %s: %w: %q", op, err, ins.Raw)
	}
	pointer := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pointer, address)
	predicateValue, predicateType, err := c.loadPRegElements(predicate, elementBits)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / elementBits
	loadedType := fmt.Sprintf("<vscale x %d x i%d>", lanes, spec.memoryBits)
	loaded := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.ld1.nxv%di%d(%s %s, ptr %%%s)\n",
		loaded, loadedType, lanes, spec.memoryBits, predicateType, predicateValue, pointer)
	return c.finishARM64SVEOrdinaryLoad(spec, destination, elementBits, loadedType, "%"+loaded)
}

func (c *arm64Ctx) lowerARM64SVEOrdinaryVectorOffsetLoad(op Op, spec arm64SVEOrdinaryMemorySpec, memory MemRef, predicate, destination, elementBits int, ins Instr) (ok bool, terminated bool, err error) {
	pointer, indexValue, indexType, suffix, err := c.arm64SVEOrdinaryVectorOffset(op, memory, elementBits, spec.memoryBits, ins)
	if err != nil {
		return true, false, err
	}
	predicateValue, predicateType, err := c.loadPRegElements(predicate, elementBits)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / elementBits
	loadedType := fmt.Sprintf("<vscale x %d x i%d>", lanes, spec.memoryBits)
	loaded := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.ld1.gather%s.nxv%di%d(%s %s, ptr %s, %s %s)\n",
		loaded, loadedType, suffix, lanes, spec.memoryBits, predicateType, predicateValue, pointer, indexType, indexValue)
	return c.finishARM64SVEOrdinaryLoad(spec, destination, elementBits, loadedType, "%"+loaded)
}

func (c *arm64Ctx) lowerARM64SVEOrdinaryVectorBaseLoad(op Op, spec arm64SVEOrdinaryMemorySpec, memory MemRef, predicate, destination, elementBits int, ins Instr) (ok bool, terminated bool, err error) {
	baseValue, baseType, err := c.arm64SVEOrdinaryVectorBase(op, memory, elementBits, spec.memoryBits, ins)
	if err != nil {
		return true, false, err
	}
	predicateValue, predicateType, err := c.loadPRegElements(predicate, elementBits)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / elementBits
	loadedType := fmt.Sprintf("<vscale x %d x i%d>", lanes, spec.memoryBits)
	loaded := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.ld1.gather.scalar.offset.nxv%di%d.nxv%di%d(%s %s, %s %s, i64 %d)\n",
		loaded, loadedType, lanes, spec.memoryBits, lanes, elementBits, predicateType, predicateValue, baseType, baseValue, memory.Off)
	return c.finishARM64SVEOrdinaryLoad(spec, destination, elementBits, loadedType, "%"+loaded)
}

func (c *arm64Ctx) finishARM64SVEOrdinaryLoad(spec arm64SVEOrdinaryMemorySpec, destination, elementBits int, loadedType, loaded string) (ok bool, terminated bool, err error) {
	value := loaded
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
	return true, false, c.storeZRegElements(destination, elementBits, value)
}

func (c *arm64Ctx) lowerARM64SVEOrdinaryStore(op Op, spec arm64SVEOrdinaryMemorySpec, ins Instr) (ok bool, terminated bool, err error) {
	if ins.Args[0].Kind != OpRegList || ins.Args[2].Kind != OpMem {
		return true, false, fmt.Errorf("arm64 %s requires vector-list, predicate, memory operands: %q", op, ins.Raw)
	}
	vectors, elementBits, vectorsOK := arm64ParseSVEOrdinaryVectorList(ins.Args[0])
	if !vectorsOK {
		return true, false, fmt.Errorf("arm64 %s requires a consecutive, uniformly arranged Z register list: %q", op, ins.Raw)
	}
	if predicate, predicateOK := arm64ParseSVEPredicateBare(ins.Args[1], 7); predicateOK {
		if len(vectors) != 1 {
			return true, false, fmt.Errorf("arm64 %s ordinary predicate form requires one source vector: %q", op, ins.Raw)
		}
		return c.lowerARM64SVEOrdinarySingleStore(op, spec, ins.Args[2].Mem, predicate, vectors[0], elementBits, ins)
	}
	predicate, predicateOK := arm64ParseSVENonTemporalPN(ins.Args[1], false)
	if !predicateOK || spec.qOnly || (len(vectors) != 2 && len(vectors) != 4) || elementBits != spec.memoryBits {
		return true, false, fmt.Errorf("arm64 %s PN form requires PN8..PN15 and two or four natural-width source vectors: %q", op, ins.Raw)
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
	fmt.Fprintf(c.b, "  call void @llvm.aarch64.sve.st1.pn.x%d.nxv%di%d(%s, target(\"aarch64.svcount\") %s, ptr %%%s)\n",
		len(vectors), 128/elementBits, elementBits, strings.Join(values, ", "), counter, pointer)
	return true, false, nil
}

func (c *arm64Ctx) lowerARM64SVEOrdinarySingleStore(op Op, spec arm64SVEOrdinaryMemorySpec, memory MemRef, predicate, source, elementBits int, ins Instr) (ok bool, terminated bool, err error) {
	if spec.qOnly {
		return c.lowerARM64SVEOrdinaryQScatterStore(op, memory, predicate, source, elementBits, ins)
	}
	if elementBits == 128 {
		if spec.memoryBits != 32 && spec.memoryBits != 64 {
			return true, false, fmt.Errorf("arm64 %s Q arrangement is outside its Go 1.27 table: %q", op, ins.Raw)
		}
		return c.lowerARM64SVEOrdinaryQContiguousStore(op, spec, memory, predicate, source, ins)
	}
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
	storedType, stored := arm64SVETruncateStoreValue(c, value, vectorType, lanes, spec.memoryBits, elementBits)
	if _, _, vectorOffset := arm64ParseSVEZElementReg(Operand{Kind: OpReg, Reg: memory.Index}); vectorOffset {
		pointer, indexValue, indexType, suffix, err := c.arm64SVEOrdinaryVectorOffset(op, memory, elementBits, spec.memoryBits, ins)
		if err != nil {
			return true, false, err
		}
		fmt.Fprintf(c.b, "  call void @llvm.aarch64.sve.st1.scatter%s.nxv%di%d(%s %s, %s %s, ptr %s, %s %s)\n",
			suffix, lanes, spec.memoryBits, storedType, stored, predicateType, predicateValue, pointer, indexType, indexValue)
		return true, false, nil
	}
	if _, _, vectorBase := arm64ParseSVEZElementReg(Operand{Kind: OpReg, Reg: memory.Base}); vectorBase {
		baseValue, baseType, err := c.arm64SVEOrdinaryVectorBase(op, memory, elementBits, spec.memoryBits, ins)
		if err != nil {
			return true, false, err
		}
		fmt.Fprintf(c.b, "  call void @llvm.aarch64.sve.st1.scatter.scalar.offset.nxv%di%d.nxv%di%d(%s %s, %s %s, %s %s, i64 %d)\n",
			lanes, spec.memoryBits, lanes, elementBits, storedType, stored, predicateType, predicateValue, baseType, baseValue, memory.Off)
		return true, false, nil
	}
	address, err := c.arm64SVEOrdinaryContiguousAddress(memory, spec.memoryBits, elementBits)
	if err != nil {
		return true, false, fmt.Errorf("arm64 %s: %w: %q", op, err, ins.Raw)
	}
	pointer := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pointer, address)
	fmt.Fprintf(c.b, "  call void @llvm.aarch64.sve.st1.nxv%di%d(%s %s, %s %s, ptr %%%s)\n",
		lanes, spec.memoryBits, storedType, stored, predicateType, predicateValue, pointer)
	return true, false, nil
}

func arm64SVETruncateStoreValue(c *arm64Ctx, value, vectorType string, lanes, memoryBits, elementBits int) (storedType, stored string) {
	storedType, stored = vectorType, value
	if memoryBits < elementBits {
		storedType = fmt.Sprintf("<vscale x %d x i%d>", lanes, memoryBits)
		truncated := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc %s %s to %s\n", truncated, vectorType, value, storedType)
		stored = "%" + truncated
	}
	return storedType, stored
}

func (c *arm64Ctx) lowerARM64SVEOrdinaryQContiguousLoad(op Op, spec arm64SVEOrdinaryMemorySpec, memory MemRef, predicate, destination int, ins Instr) (ok bool, terminated bool, err error) {
	address, err := c.arm64SVEOrdinaryContiguousAddress(memory, spec.memoryBits, 128)
	if err != nil {
		return true, false, fmt.Errorf("arm64 %s: %w: %q", op, err, ins.Raw)
	}
	pointer := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pointer, address)
	predicateValue, err := c.loadARM64SVEQPredicate(predicate)
	if err != nil {
		return true, false, err
	}
	vectorType, lanes, _ := arm64SVEVectorType(spec.memoryBits)
	intrinsic := map[int]string{32: "ld1uwq", 64: "ld1udq"}[spec.memoryBits]
	loaded := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(<vscale x 1 x i1> %s, ptr %%%s)\n",
		loaded, vectorType, intrinsic, lanes, spec.memoryBits, predicateValue, pointer)
	return true, false, c.storeZRegElements(destination, spec.memoryBits, "%"+loaded)
}

func (c *arm64Ctx) lowerARM64SVEOrdinaryQContiguousStore(op Op, spec arm64SVEOrdinaryMemorySpec, memory MemRef, predicate, source int, ins Instr) (ok bool, terminated bool, err error) {
	address, err := c.arm64SVEOrdinaryContiguousAddress(memory, spec.memoryBits, 128)
	if err != nil {
		return true, false, fmt.Errorf("arm64 %s: %w: %q", op, err, ins.Raw)
	}
	pointer := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pointer, address)
	value, vectorType, err := c.loadZRegElements(source, spec.memoryBits)
	if err != nil {
		return true, false, err
	}
	predicateValue, err := c.loadARM64SVEQPredicate(predicate)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / spec.memoryBits
	intrinsic := map[int]string{32: "st1wq", 64: "st1dq"}[spec.memoryBits]
	fmt.Fprintf(c.b, "  call void @llvm.aarch64.sve.%s.nxv%di%d(%s %s, <vscale x 1 x i1> %s, ptr %%%s)\n",
		intrinsic, lanes, spec.memoryBits, vectorType, value, predicateValue, pointer)
	return true, false, nil
}

func (c *arm64Ctx) lowerARM64SVEOrdinaryQGatherLoad(op Op, memory MemRef, predicate, destination, elementBits int, ins Instr) (ok bool, terminated bool, err error) {
	if elementBits != 128 || memory.Sym != "" || memory.Segment != "" || memory.Off != 0 || memory.OffRaw != "" || memory.IndexExt != "" || memory.Scale != 1 {
		return true, false, fmt.Errorf("arm64 %s requires vector D bases, a scalar register offset, and a Q destination: %q", op, ins.Raw)
	}
	bases, baseBits, baseOK := arm64ParseSVEZElementReg(Operand{Kind: OpReg, Reg: memory.Index})
	if !baseOK || baseBits != 64 || !isARM64GeneralOrZeroReg(memory.Base) || memory.Base == ZR || memory.Base == SP || memory.Base == Reg("RSP") {
		return true, false, fmt.Errorf("arm64 %s requires Zn.D bases and R0..R30 offset: %q", op, ins.Raw)
	}
	offset, err := c.loadReg(memory.Base)
	if err != nil {
		return true, false, err
	}
	return c.emitARM64SVEOrdinaryQGatherLoad(bases, predicate, destination, offset)
}

func (c *arm64Ctx) emitARM64SVEOrdinaryQGatherLoad(bases, predicate, destination int, offset string) (bool, bool, error) {
	baseValue, baseType, err := c.loadZRegElements(bases, 64)
	if err != nil {
		return true, false, err
	}
	predicateValue, err := c.loadARM64SVEQPredicate(predicate)
	if err != nil {
		return true, false, err
	}
	loaded := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.ld1q.gather.scalar.offset.nxv2i64.nxv2i64(<vscale x 1 x i1> %s, %s %s, i64 %s)\n",
		loaded, baseType, predicateValue, baseType, baseValue, offset)
	return true, false, c.storeZRegElements(destination, 64, "%"+loaded)
}

func (c *arm64Ctx) lowerARM64SVEOrdinaryQScatterStore(op Op, memory MemRef, predicate, source, elementBits int, ins Instr) (ok bool, terminated bool, err error) {
	if elementBits != 128 || memory.Sym != "" || memory.Segment != "" || memory.Off != 0 || memory.OffRaw != "" || memory.IndexExt != "" || memory.Scale != 1 {
		return true, false, fmt.Errorf("arm64 %s requires a Q source, vector D bases, and a scalar register offset: %q", op, ins.Raw)
	}
	bases, baseBits, baseOK := arm64ParseSVEZElementReg(Operand{Kind: OpReg, Reg: memory.Index})
	if !baseOK || baseBits != 64 || !isARM64GeneralOrZeroReg(memory.Base) || memory.Base == ZR || memory.Base == SP || memory.Base == Reg("RSP") {
		return true, false, fmt.Errorf("arm64 %s requires Zn.D bases and R0..R30 offset: %q", op, ins.Raw)
	}
	baseValue, baseType, err := c.loadZRegElements(bases, 64)
	if err != nil {
		return true, false, err
	}
	offset, err := c.loadReg(memory.Base)
	if err != nil {
		return true, false, err
	}
	value, vectorType, err := c.loadZRegElements(source, 64)
	if err != nil {
		return true, false, err
	}
	predicateValue, err := c.loadARM64SVEQPredicate(predicate)
	if err != nil {
		return true, false, err
	}
	fmt.Fprintf(c.b, "  call void @llvm.aarch64.sve.st1q.scatter.scalar.offset.nxv2i64.nxv2i64(%s %s, <vscale x 1 x i1> %s, %s %s, i64 %s)\n",
		vectorType, value, predicateValue, baseType, baseValue, offset)
	return true, false, nil
}

func (c *arm64Ctx) loadARM64SVEQPredicate(predicate int) (string, error) {
	value, err := c.loadPReg(predicate)
	if err != nil {
		return "", err
	}
	converted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call <vscale x 1 x i1> @llvm.aarch64.sve.convert.from.svbool.nxv1i1(<vscale x 16 x i1> %s)\n", converted, value)
	return "%" + converted, nil
}

func (c *arm64Ctx) arm64SVEOrdinaryContiguousAddress(memory MemRef, memoryBits, elementBits int) (string, error) {
	if memory.Index != "" {
		if _, _, vectorIndex := arm64ParseSVEZElementReg(Operand{Kind: OpReg, Reg: memory.Index}); vectorIndex {
			return "", fmt.Errorf("contiguous form does not accept a scalable-vector index")
		}
		return c.arm64SVERegisterOffsetAddress(memory, int64(memoryBits/8))
	}
	// MUL VL counts the vector's in-memory footprint, not its register
	// footprint. Widening loads and truncating stores transfer fewer bytes.
	return c.arm64SVEVLAddress(memory, -8, 7, int64(16*memoryBits/elementBits))
}

func (c *arm64Ctx) arm64SVEOrdinaryVectorOffset(op Op, memory MemRef, elementBits, memoryBits int, ins Instr) (pointer, indexValue, indexType, suffix string, err error) {
	if memory.Sym != "" || memory.Segment != "" || memory.Off != 0 || memory.OffRaw != "" {
		return "", "", "", "", fmt.Errorf("arm64 %s vector-offset form does not accept a displacement: %q", op, ins.Raw)
	}
	baseReg, baseOK := arm64SVEPhysicalMemoryBase(memory.Base)
	index, indexBits, indexOK := arm64ParseSVEZElementReg(Operand{Kind: OpReg, Reg: memory.Index})
	byteScale := int64(memoryBits / 8)
	if !baseOK || !indexOK || indexBits != elementBits || (elementBits != 32 && elementBits != 64) || (memory.Scale != 1 && memory.Scale != byteScale) {
		return "", "", "", "", fmt.Errorf("arm64 %s vector offset has widths or scale outside its Go 1.27 table: %q", op, ins.Raw)
	}
	extension := ""
	switch memory.IndexExt {
	case "":
		if indexBits != 64 {
			return "", "", "", "", fmt.Errorf("arm64 %s unextended vector offset requires Zm.D: %q", op, ins.Raw)
		}
	case ExtendUXTW:
		extension = "uxtw"
	case ExtendSXTW:
		extension = "sxtw"
	default:
		return "", "", "", "", fmt.Errorf("arm64 %s vector offset only accepts UXTW or SXTW: %q", op, ins.Raw)
	}
	base, err := c.loadReg(baseReg)
	if err != nil {
		return "", "", "", "", err
	}
	pointerName := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pointerName, base)
	indexValue, indexType, err = c.loadZRegElements(index, indexBits)
	if err != nil {
		return "", "", "", "", err
	}
	if extension != "" && indexBits == 64 {
		narrowType := "<vscale x 2 x i32>"
		narrow := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc %s %s to %s\n", narrow, indexType, indexValue, narrowType)
		extended := c.newTmp()
		opcode := "zext"
		if extension == "sxtw" {
			opcode = "sext"
		}
		fmt.Fprintf(c.b, "  %%%s = %s %s %%%s to %s\n", extended, opcode, narrowType, narrow, indexType)
		indexValue = "%" + extended
		extension = ""
	}
	if extension != "" {
		suffix = "." + extension
	}
	if byteScale > 1 && memory.Scale == byteScale {
		suffix += ".index"
	}
	return "%" + pointerName, indexValue, indexType, suffix, nil
}

func (c *arm64Ctx) arm64SVEOrdinaryVectorBase(op Op, memory MemRef, elementBits, memoryBits int, ins Instr) (baseValue, baseType string, err error) {
	base, baseBits, baseOK := arm64ParseSVEZElementReg(Operand{Kind: OpReg, Reg: memory.Base})
	alignment := int64(memoryBits / 8)
	maximum := int64(31) * alignment
	if !baseOK || baseBits != elementBits || (elementBits != 32 && elementBits != 64) || memory.Index != "" || memory.IndexExt != "" || memory.Sym != "" || memory.Segment != "" || memory.OffRaw != "" || memory.Off < 0 || memory.Off > maximum || memory.Off%alignment != 0 {
		return "", "", fmt.Errorf("arm64 %s vector-base offset must match the data width, be aligned to %d, and be in [0,%d]: %q", op, alignment, maximum, ins.Raw)
	}
	return c.loadZRegElements(base, baseBits)
}

func arm64ParseSVEOrdinaryVectorList(operand Operand) (vectors []int, elementBits int, ok bool) {
	if operand.Kind != OpRegList || len(operand.RegList) == 0 {
		return nil, 0, false
	}
	vectors = make([]int, len(operand.RegList))
	for i, register := range operand.RegList {
		vector, bits, valid := arm64ParseSVEOrdinaryZReg(register)
		if !valid || i > 0 && (bits != elementBits || vector != vectors[i-1]+1) {
			return nil, 0, false
		}
		vectors[i] = vector
		elementBits = bits
	}
	return vectors, elementBits, true
}

func arm64ParseSVEOrdinaryZReg(register Reg) (index, elementBits int, ok bool) {
	if index, elementBits, ok = arm64ParseSVEZElementReg(Operand{Kind: OpReg, Reg: register}); ok {
		return index, elementBits, true
	}
	parts := strings.Split(strings.ToUpper(strings.TrimSpace(string(register))), ".")
	if len(parts) != 2 || parts[1] != "Q" || !strings.HasPrefix(parts[0], "Z") {
		return 0, 0, false
	}
	index, err := strconv.Atoi(strings.TrimPrefix(parts[0], "Z"))
	if err != nil || index < 0 || index > 31 {
		return 0, 0, false
	}
	return index, 128, true
}
