package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVEReplicateMemorySpec struct {
	memoryBits int
	signed     bool
	blockBytes int
}

// arm64SVEReplicateMemorySpecs covers all 32 Go 1.27 replicate-load encoder
// forms: scalar LD1R, sign-extending LD1RS, and block LD1RO/LD1RQ.
var arm64SVEReplicateMemorySpecs = map[Op]arm64SVEReplicateMemorySpec{
	"ZLD1RB":  {memoryBits: 8},
	"ZLD1RH":  {memoryBits: 16},
	"ZLD1RW":  {memoryBits: 32},
	"ZLD1RD":  {memoryBits: 64},
	"ZLD1RSB": {memoryBits: 8, signed: true},
	"ZLD1RSH": {memoryBits: 16, signed: true},
	"ZLD1RSW": {memoryBits: 32, signed: true},
	"ZLD1ROB": {memoryBits: 8, blockBytes: 32},
	"ZLD1ROH": {memoryBits: 16, blockBytes: 32},
	"ZLD1ROW": {memoryBits: 32, blockBytes: 32},
	"ZLD1ROD": {memoryBits: 64, blockBytes: 32},
	"ZLD1RQB": {memoryBits: 8, blockBytes: 16},
	"ZLD1RQH": {memoryBits: 16, blockBytes: 16},
	"ZLD1RQW": {memoryBits: 32, blockBytes: 16},
	"ZLD1RQD": {memoryBits: 64, blockBytes: 16},
}

// decodeARM64RawSVEReplicateScalar covers every scalar immediate-address
// LD1R/LD1RS row in the Go 1.27 ARM64 encoder table. The decoded operands
// use the same typed path as the corresponding Plan 9 mnemonics.
func decodeARM64RawSVEReplicateScalar(word uint32) (Instr, bool) {
	const fields = uint32(0x003f1fff) // imm6, Pg, Xn, Zt
	forms := [...]struct {
		op          Op
		base        uint32
		arrangement string
		memoryBytes int64
	}{
		{"ZLD1RB", 0x84408000, "B", 1},
		{"ZLD1RB", 0x8440a000, "H", 1},
		{"ZLD1RB", 0x8440c000, "S", 1},
		{"ZLD1RB", 0x8440e000, "D", 1},
		{"ZLD1RH", 0x84c0a000, "H", 2},
		{"ZLD1RH", 0x84c0c000, "S", 2},
		{"ZLD1RH", 0x84c0e000, "D", 2},
		{"ZLD1RW", 0x8540c000, "S", 4},
		{"ZLD1RW", 0x8540e000, "D", 4},
		{"ZLD1RD", 0x85c0e000, "D", 8},
		{"ZLD1RSB", 0x85c0a000, "S", 1},
		{"ZLD1RSB", 0x85c0c000, "H", 1},
		{"ZLD1RSB", 0x85c08000, "D", 1},
		{"ZLD1RSH", 0x8540a000, "S", 2},
		{"ZLD1RSH", 0x85408000, "D", 2},
		{"ZLD1RSW", 0x84c08000, "D", 4},
	}
	for _, form := range forms {
		if word&^fields != form.base {
			continue
		}
		baseNumber := int(word>>5) & 31
		base := Reg(fmt.Sprintf("R%d", baseNumber))
		if baseNumber == 31 {
			base = SP
		}
		memory := MemRef{
			Base: base,
			Off:  int64(word>>16&63) * form.memoryBytes,
		}
		predicate := int(word>>10) & 7
		vector := int(word) & 31
		return Instr{
			Op: form.op,
			Args: []Operand{
				{Kind: OpMem, Mem: memory},
				{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d.Z", predicate))},
				{Kind: OpRegList, RegList: []Reg{Reg(fmt.Sprintf("Z%d.%s", vector, form.arrangement))}},
			},
			Raw: fmt.Sprintf("WORD $%#08x", word),
		}, true
	}
	return Instr{}, false
}

// decodeARM64RawSVEReplicateBlock covers all sixteen Go 1.27 LD1RO/LD1RQ
// register-offset and signed-immediate encoding rows. The decoded operands
// are passed through the same typed lowering as the corresponding mnemonics.
func decodeARM64RawSVEReplicateBlock(word uint32) (Instr, bool) {
	const (
		registerBits  = uint32(0x001f1fff)
		immediateBits = uint32(0x000f1fff)
	)
	forms := [...]struct {
		op         Op
		register   uint32
		immediate  uint32
		element    string
		elementB   int64
		blockBytes int64
	}{
		{"ZLD1ROB", 0xa4200000, 0xa4202000, "B", 1, 32},
		{"ZLD1ROH", 0xa4a00000, 0xa4a02000, "H", 2, 32},
		{"ZLD1ROW", 0xa5200000, 0xa5202000, "S", 4, 32},
		{"ZLD1ROD", 0xa5a00000, 0xa5a02000, "D", 8, 32},
		{"ZLD1RQB", 0xa4000000, 0xa4002000, "B", 1, 16},
		{"ZLD1RQH", 0xa4800000, 0xa4802000, "H", 2, 16},
		{"ZLD1RQW", 0xa5000000, 0xa5002000, "S", 4, 16},
		{"ZLD1RQD", 0xa5800000, 0xa5802000, "D", 8, 16},
	}
	for _, form := range forms {
		registerOffset := word&^registerBits == form.register
		immediateOffset := word&^immediateBits == form.immediate
		if !registerOffset && !immediateOffset {
			continue
		}
		baseNumber := int(word>>5) & 31
		base := Reg(fmt.Sprintf("R%d", baseNumber))
		if baseNumber == 31 {
			base = SP
		}
		memory := MemRef{Base: base}
		if registerOffset {
			indexNumber := int(word>>16) & 31
			index := Reg(fmt.Sprintf("R%d", indexNumber))
			if indexNumber == 31 {
				index = ZR
			}
			memory.Index = index
			memory.Scale = form.elementB
			if form.elementB == 1 {
				memory.Base, memory.Index = memory.Index, memory.Base
			}
		} else {
			immediate := int64(word >> 16 & 15)
			if immediate >= 8 {
				immediate -= 16
			}
			memory.Off = immediate * form.blockBytes
		}
		predicate := int(word>>10) & 7
		vector := int(word) & 31
		args := []Operand{
			{Kind: OpMem, Mem: memory},
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d.Z", predicate))},
			{Kind: OpRegList, RegList: []Reg{Reg(fmt.Sprintf("Z%d.%s", vector, form.element))}},
		}
		return Instr{Op: form.op, Args: args, Raw: fmt.Sprintf("WORD $%#08x", word)}, true
	}
	return Instr{}, false
}

func (c *arm64Ctx) lowerARM64SVEReplicateMemory(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVEReplicateMemorySpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 || ins.Args[0].Kind != OpMem || ins.Args[2].Kind != OpRegList {
		return true, false, fmt.Errorf("arm64 %s expects memory, predicate, vector-list operands: %q", op, ins.Raw)
	}
	predicate, predicateOK := arm64ParseSVEPredicateMode(ins.Args[1], "Z", 7)
	vectors, elementBits, vectorsOK := arm64ParseSVEConsecutiveVectorList(ins.Args[2])
	widthOK := elementBits >= spec.memoryBits && (!spec.signed || elementBits > spec.memoryBits)
	if spec.blockBytes != 0 {
		widthOK = elementBits == spec.memoryBits
	}
	if !predicateOK || !vectorsOK || len(vectors) != 1 || !widthOK {
		return true, false, fmt.Errorf("arm64 %s has predicate or destination widths outside its Go 1.27 table: %q", op, ins.Raw)
	}
	if spec.blockBytes != 0 {
		return c.lowerARM64SVEReplicateBlockLoad(op, spec, ins.Args[0].Mem, predicate, vectors[0], elementBits, ins)
	}
	return c.lowerARM64SVEReplicateScalarLoad(op, spec, ins.Args[0].Mem, predicate, vectors[0], elementBits, ins)
}

func (c *arm64Ctx) lowerARM64SVEReplicateScalarLoad(op Op, spec arm64SVEReplicateMemorySpec, memory MemRef, predicate, destination, elementBits int, ins Instr) (ok bool, terminated bool, err error) {
	memoryBytes := int64(spec.memoryBits / 8)
	address, err := c.arm64SVEScalarByteOffsetAddress(memory, 0, 63*memoryBytes, memoryBytes)
	if err != nil {
		return true, false, fmt.Errorf("arm64 %s: %w: %q", op, err, ins.Raw)
	}
	pointer := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pointer, address)
	loaded := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i%d, ptr %%%s\n", loaded, spec.memoryBits, pointer)
	scalar := "%" + loaded
	if spec.memoryBits < elementBits {
		extended := c.newTmp()
		extension := "zext"
		if spec.signed {
			extension = "sext"
		}
		fmt.Fprintf(c.b, "  %%%s = %s i%d %s to i%d\n", extended, extension, spec.memoryBits, scalar, elementBits)
		scalar = "%" + extended
	}
	vectorType, lanes, err := arm64SVEVectorType(elementBits)
	if err != nil {
		return true, false, err
	}
	inserted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement %s poison, i%d %s, i64 0\n", inserted, vectorType, elementBits, scalar)
	splat := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s poison, <vscale x %d x i32> zeroinitializer\n", splat, vectorType, inserted, vectorType, lanes)
	predicateValue, predicateType, err := c.loadPRegElements(predicate, elementBits)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select %s %s, %s %%%s, %s zeroinitializer\n", result, predicateType, predicateValue, vectorType, splat, vectorType)
	return true, false, c.storeZRegElements(destination, elementBits, "%"+result)
}

func (c *arm64Ctx) lowerARM64SVEReplicateBlockLoad(op Op, spec arm64SVEReplicateMemorySpec, memory MemRef, predicate, destination, elementBits int, ins Instr) (ok bool, terminated bool, err error) {
	var address string
	var addressErr error
	if memory.Index != "" {
		address, addressErr = c.arm64SVERegisterOffsetAddress(memory, int64(spec.memoryBits/8))
	} else {
		address, addressErr = c.arm64SVEScalarByteOffsetAddress(memory, -8*int64(spec.blockBytes), 7*int64(spec.blockBytes), int64(spec.blockBytes))
	}
	if addressErr != nil {
		return true, false, fmt.Errorf("arm64 %s: %w: %q", op, addressErr, ins.Raw)
	}
	pointer := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pointer, address)
	predicateValue, predicateType, err := c.loadPRegElements(predicate, elementBits)
	if err != nil {
		return true, false, err
	}
	vectorType, lanes, err := arm64SVEVectorType(elementBits)
	if err != nil {
		return true, false, err
	}
	kind := "rq"
	if spec.blockBytes == 32 {
		kind = "ro"
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.ld1%s.nxv%di%d(%s %s, ptr %%%s)\n",
		result, vectorType, kind, lanes, elementBits, predicateType, predicateValue, pointer)
	return true, false, c.storeZRegElements(destination, elementBits, "%"+result)
}

func (c *arm64Ctx) arm64SVEScalarByteOffsetAddress(memory MemRef, minimum, maximum, alignment int64) (string, error) {
	if memory.Sym != "" || memory.Segment != "" || memory.Index != "" || memory.IndexExt != "" || memory.OffRaw != "" || memory.Off < minimum || memory.Off > maximum || memory.Off%alignment != 0 {
		return "", fmt.Errorf("scalar byte offset must be aligned to %d and in [%d,%d]", alignment, minimum, maximum)
	}
	baseReg, ok := arm64SVEPhysicalMemoryBase(memory.Base)
	if !ok {
		return "", fmt.Errorf("address base must be R0..R30, RSP, or ZR")
	}
	base, err := c.loadReg(baseReg)
	if err != nil {
		return "", err
	}
	if memory.Off == 0 {
		return base, nil
	}
	address := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add i64 %s, %d\n", address, base, memory.Off)
	return "%" + address, nil
}
