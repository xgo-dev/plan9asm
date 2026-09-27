package plan9asm

import (
	"fmt"
	"strings"
)

type amd64PackedIntegerCompareSpec struct {
	laneBits          int
	greater           bool
	mapNumber, opcode int
}

// Every Go _yvpcmpeqb entry: X/Y VEX vector results, X/Y/Z EVEX K
// results, optional K1-7 mask, and memory-only D/Q broadcast. Raw decode
// consumes the same lane and encoding axes as the named lowerer.
var amd64PackedIntegerCompareSpecs = map[Op]amd64PackedIntegerCompareSpec{
	"VPCMPEQB": {8, false, 1, 0x74},
	"VPCMPEQW": {16, false, 1, 0x75},
	"VPCMPEQD": {32, false, 1, 0x76},
	"VPCMPEQQ": {64, false, 2, 0x29},
	"VPCMPGTB": {8, true, 1, 0x64},
	"VPCMPGTW": {16, true, 1, 0x65},
	"VPCMPGTD": {32, true, 1, 0x66},
	"VPCMPGTQ": {64, true, 2, 0x37},
}

// lowerPackedIntegerCompare implements the legacy PCMPGT{B,W,L,Q} family and
// the complete Go 1.27 _yvpcmpeqb operand family shared by VPCMPEQ{B,W,D,Q}
// and VPCMPGT{B,W,D,Q}.
// VEX forms write X/Y vectors. EVEX forms compare X/Y/Z lanes into a K
// register, optionally gated by a non-K0 mask; D/Q memory operands can be
// broadcast for the EVEX forms.
func (c *amd64Ctx) lowerPackedIntegerCompare(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	suffix := ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	laneBits := 0
	legacy := false
	legacyMMX := false
	switch baseOp {
	case "PCMPEQB":
		laneBits, legacy, legacyMMX = 8, true, true
	case "PCMPEQW":
		laneBits, legacy, legacyMMX = 16, true, true
	case "PCMPEQL":
		laneBits, legacy, legacyMMX = 32, true, true
	case "PCMPEQQ":
		laneBits, legacy = 64, true
	case "PCMPGTB":
		laneBits, legacy, legacyMMX = 8, true, true
	case "PCMPGTW":
		laneBits, legacy, legacyMMX = 16, true, true
	case "PCMPGTL":
		laneBits, legacy, legacyMMX = 32, true, true
	case "PCMPGTQ":
		laneBits, legacy = 64, true
	default:
		spec, recognized := amd64PackedIntegerCompareSpecs[Op(baseOp)]
		if !recognized {
			return false, false, nil
		}
		laneBits = spec.laneBits
	}
	if legacy {
		if suffix != "" {
			return true, false, fmt.Errorf("%s %s does not accept instruction suffixes: %q", c.goarch, baseOp, ins.Raw)
		}
		return c.lowerLegacyPackedIntegerCompare(baseOp, laneBits, legacyMMX, ins)
	}
	broadcast := suffix == "BCST"
	if suffix != "" && !broadcast {
		return true, false, fmt.Errorf("amd64 %s accepts only the .BCST suffix supported by its Go 1.27 optab: %q", baseOp, ins.Raw)
	}
	if len(ins.Args) != 3 && len(ins.Args) != 4 {
		return true, false, fmt.Errorf("amd64 %s expects src1, src2, [K mask,] destination: %q", baseOp, ins.Raw)
	}
	if ins.Args[len(ins.Args)-1].Kind != OpReg {
		return true, false, fmt.Errorf("amd64 %s expects a vector or K destination: %q", baseOp, ins.Raw)
	}

	dst := ins.Args[len(ins.Args)-1].Reg
	if isAMD64XReg(dst) || isAMD64YReg(dst) {
		if len(ins.Args) != 3 || broadcast {
			return true, false, fmt.Errorf("amd64 %s vector-result form has no mask or suffix: %q", baseOp, ins.Raw)
		}
		byteWidth := 16
		if isAMD64YReg(dst) {
			byteWidth = 32
		}
		// Go's named VEX classes accept X/Y8-15 even on 386. The raw
		// decoder independently enforces physical 32-bit register limits.
		if !(amd64VEXVectorRegister(ins.Args[0], byteWidth) || isAMD64MemoryOperand(ins.Args[0])) ||
			!amd64VEXVectorRegister(ins.Args[1], byteWidth) ||
			!amd64VEXVectorRegister(ins.Args[2], byteWidth) {
			return true, false, fmt.Errorf("%s %s VEX form requires matching in-range X or Y operands: %q", c.goarch, baseOp, ins.Raw)
		}
		return true, false, c.emitPackedIntegerVectorCompare(baseOp, laneBits, byteWidth, ins.Args[0], ins.Args[1], dst)
	}

	if _, ok := amd64ParseKReg(dst); !ok {
		return true, false, fmt.Errorf("amd64 %s EVEX form expects a K destination: %q", baseOp, ins.Raw)
	}
	byteWidth, ok := amd64PackedCompareWidth(ins.Args[1])
	if !ok || !c.isGoPackedVectorMoveRegister(ins.Args[1], byteWidth) {
		return true, false, fmt.Errorf("amd64 %s EVEX form expects X/Y/Z as its second source: %q", baseOp, ins.Raw)
	}
	if ins.Args[0].Kind == OpReg {
		if !c.isGoPackedVectorMoveRegister(ins.Args[0], byteWidth) {
			return true, false, fmt.Errorf("%s %s EVEX source registers must match and be in range: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(ins.Args[0]) {
		return true, false, fmt.Errorf("%s %s EVEX first source must be a vector register or memory: %q", c.goarch, baseOp, ins.Raw)
	}
	if broadcast {
		if laneBits != 32 && laneBits != 64 {
			return true, false, fmt.Errorf("amd64 %s does not enable EVEX broadcast: %q", baseOp, ins.Raw)
		}
		if !isAMD64MemoryOperand(ins.Args[0]) {
			return true, false, fmt.Errorf("amd64 %s.BCST requires a memory first source: %q", baseOp, ins.Raw)
		}
	}

	var writeMask string
	if len(ins.Args) == 4 {
		if c.goarch == "386" && !ins.x86Encoded {
			return true, false, fmt.Errorf("386 %s write-mask forms exceed the Go assembler frontend's three-operand limit: %q", baseOp, ins.Raw)
		}
		mask := ins.Args[2]
		if mask.Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s masked form expects K1-K7: %q", baseOp, ins.Raw)
		}
		index, ok := amd64ParseKReg(mask.Reg)
		if !ok || index == 0 {
			return true, false, fmt.Errorf("amd64 %s masked form expects K1-K7: %q", baseOp, ins.Raw)
		}
		writeMask, err = c.loadK(mask.Reg)
		if err != nil {
			return true, false, err
		}
	}
	return true, false, c.emitPackedIntegerMaskCompare(baseOp, laneBits, byteWidth, ins.Args[0], ins.Args[1], dst, writeMask, broadcast)
}

func (c *amd64Ctx) lowerLegacyPackedIntegerCompare(baseOp string, laneBits int, allowMMX bool, ins Instr) (bool, bool, error) {
	if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("%s %s expects packed source, packed destination: %q", c.goarch, baseOp, ins.Raw)
	}
	destination := ins.Args[1].Reg
	if _, mmx := amd64ParseMReg(destination); mmx {
		if !allowMMX {
			return true, false, fmt.Errorf("%s %s has no MMX form in Go 1.27's yxm_q4 table: %q", c.goarch, baseOp, ins.Raw)
		}
		if ins.Args[0].Kind == OpReg {
			if _, ok := amd64ParseMReg(ins.Args[0].Reg); !ok {
				return true, false, fmt.Errorf("%s %s MMX form requires an MMX source: %q", c.goarch, baseOp, ins.Raw)
			}
		} else if !isAMD64MemoryOperand(ins.Args[0]) {
			return true, false, fmt.Errorf("%s %s MMX form requires MMX or memory source: %q", c.goarch, baseOp, ins.Raw)
		}
		firstBits, err := c.loadLegacyMMXPackedSource(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		secondBits, err := c.loadReg(destination)
		if err != nil {
			return true, false, err
		}
		lanes := 64 / laneBits
		first := c.bitcastI64ToIntegerLanes(lanes, laneBits, firstBits)
		second := c.bitcastI64ToIntegerLanes(lanes, laneBits, secondBits)
		result := c.emitLegacyPackedIntegerCompare(baseOp, lanes, laneBits, first, second)
		bits := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to i64\n", bits, lanes, laneBits, result)
		return true, false, c.storeReg(destination, "%"+bits)
	}

	if !c.isGoLegacyXReg(destination) {
		return true, false, fmt.Errorf("%s %s destination must be an in-range MMX or X register: %q", c.goarch, baseOp, ins.Raw)
	}
	if ins.Args[0].Kind == OpReg && !c.isGoLegacyXReg(ins.Args[0].Reg) {
		return true, false, fmt.Errorf("%s %s XMM form requires an in-range X source: %q", c.goarch, baseOp, ins.Raw)
	}
	if ins.Args[0].Kind != OpReg && !isAMD64MemoryOperand(ins.Args[0]) {
		return true, false, fmt.Errorf("%s %s XMM form requires X or memory source: %q", c.goarch, baseOp, ins.Raw)
	}
	firstBytes, err := c.loadXVecOperand(ins.Args[0])
	if err != nil {
		return true, false, err
	}
	secondBytes, err := c.loadX(destination)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / laneBits
	first := c.bitcastVectorBytesToIntegerLanes(16, lanes, laneBits, firstBytes)
	second := c.bitcastVectorBytesToIntegerLanes(16, lanes, laneBits, secondBytes)
	result := c.emitLegacyPackedIntegerCompare(baseOp, lanes, laneBits, first, second)
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <16 x i8>\n", out, lanes, laneBits, result)
	return true, false, c.storeX(destination, "%"+out)
}

func (c *amd64Ctx) emitLegacyPackedIntegerCompare(baseOp string, lanes, laneBits int, first, second string) string {
	compared := c.newTmp()
	result := c.newTmp()
	predicate := "eq"
	if strings.HasPrefix(baseOp, "PCMPGT") {
		predicate = "sgt"
	}
	fmt.Fprintf(c.b, "  %%%s = icmp %s <%d x i%d> %s, %s\n", compared, predicate, lanes, laneBits, second, first)
	fmt.Fprintf(c.b, "  %%%s = sext <%d x i1> %%%s to <%d x i%d>\n", result, lanes, compared, lanes, laneBits)
	return "%" + result
}

func (c *amd64Ctx) isGoVEXVectorRegister(arg Operand, byteWidth int, allowMemory bool) bool {
	if allowMemory && isAMD64MemoryOperand(arg) {
		return true
	}
	if !amd64VEXVectorRegister(arg, byteWidth) {
		return false
	}
	if c.goarch == "386" {
		index, _ := amd64VectorRegisterIndex(arg.Reg, byteWidth)
		return index < 8
	}
	return true
}

func amd64PackedCompareWidth(op Operand) (int, bool) {
	if op.Kind != OpReg {
		return 0, false
	}
	switch {
	case isAMD64XReg(op.Reg):
		return 16, true
	case isAMD64YReg(op.Reg):
		return 32, true
	case isAMD64ZReg(op.Reg):
		return 64, true
	default:
		return 0, false
	}
}

func (c *amd64Ctx) loadPackedCompareBytes(op Operand, byteWidth int) (string, error) {
	if op.Kind == OpReg {
		width, ok := amd64PackedCompareWidth(op)
		if !ok || width != byteWidth {
			return "", fmt.Errorf("expected %d-byte vector register, got %s", byteWidth, op.String())
		}
		switch byteWidth {
		case 16:
			return c.loadX(op.Reg)
		case 32:
			return c.loadY(op.Reg)
		case 64:
			return c.loadZ(op.Reg)
		}
	}
	if op.Kind == OpFP {
		chunks := byteWidth / 8
		value := "zeroinitializer"
		for i := 0; i < chunks; i++ {
			word, err := c.evalFPToI64(op.FPOffset + int64(i*8))
			if err != nil {
				return "", err
			}
			inserted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i64> %s, i64 %s, i32 %d\n", inserted, chunks, value, word, i)
			value = "%" + inserted
		}
		bytesValue := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i64> %s to <%d x i8>\n", bytesValue, chunks, value, byteWidth)
		return "%" + bytesValue, nil
	}
	if op.Kind == OpSym {
		// As in Go's x86 assembler, an unprefixed integer denotes an
		// absolute memory address rather than an immediate value.
		if address, parseErr := parseInt(strings.TrimSpace(op.Sym)); parseErr == nil {
			value := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load <%d x i8>, ptr %s, align 1\n", value, byteWidth, c.ptrFromAddrI64(fmt.Sprintf("%d", address)))
			return "%" + value, nil
		}
	}
	if !isAMD64MemoryOperand(op) {
		return "", fmt.Errorf("expected vector register or memory, got %s", op.String())
	}
	switch byteWidth {
	case 16:
		return c.loadXVecOperand(op)
	case 32:
		return c.loadYVecOperand(op)
	case 64:
		return c.loadZVecOperand(op)
	default:
		return "", fmt.Errorf("unsupported packed compare width %d", byteWidth)
	}
}

func (c *amd64Ctx) loadPackedCompareLanes(op Operand, byteWidth, laneBits int, broadcast bool) (string, error) {
	lanes := byteWidth * 8 / laneBits
	if broadcast {
		value, err := c.evalIntSized(op, amd64IntegerTypeForBits(laneBits))
		if err != nil {
			return "", err
		}
		return amd64SplatInteger(c, lanes, laneBits, value), nil
	}
	bytesValue, err := c.loadPackedCompareBytes(op, byteWidth)
	if err != nil {
		return "", err
	}
	lanesValue := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to <%d x i%d>\n", lanesValue, byteWidth, bytesValue, lanes, laneBits)
	return "%" + lanesValue, nil
}

func (c *amd64Ctx) comparePackedIntegerLanes(baseOp string, laneBits, byteWidth int, first, second Operand, broadcast bool, mask string) (string, error) {
	firstValue, err := c.loadMaskedPackedCompareLanes(first, byteWidth, laneBits, broadcast, mask)
	if err != nil {
		return "", err
	}
	secondValue, err := c.loadPackedCompareLanes(second, byteWidth, laneBits, false)
	if err != nil {
		return "", err
	}
	predicate := "eq"
	if amd64PackedIntegerCompareSpecs[Op(baseOp)].greater {
		predicate = "sgt"
	}
	lanes := byteWidth * 8 / laneBits
	compared := c.newTmp()
	// Go/Plan 9 lists the Intel r/m operand first: dst = second cmp first.
	fmt.Fprintf(c.b, "  %%%s = icmp %s <%d x i%d> %s, %s\n", compared, predicate, lanes, laneBits, secondValue, firstValue)
	return "%" + compared, nil
}

func (c *amd64Ctx) emitPackedIntegerVectorCompare(baseOp string, laneBits, byteWidth int, first, second Operand, dst Reg) error {
	compared, err := c.comparePackedIntegerLanes(baseOp, laneBits, byteWidth, first, second, false, "")
	if err != nil {
		return err
	}
	lanes := byteWidth * 8 / laneBits
	allBits := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sext <%d x i1> %s to <%d x i%d>\n", allBits, lanes, compared, lanes, laneBits)
	bytesValue := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %%%s to <%d x i8>\n", bytesValue, lanes, laneBits, allBits, byteWidth)
	return c.storePackedMoveOperand(Operand{Kind: OpReg, Reg: dst}, byteWidth, "%"+bytesValue)
}

func (c *amd64Ctx) emitPackedIntegerMaskCompare(baseOp string, laneBits, byteWidth int, first, second Operand, dst Reg, writeMask string, broadcast bool) error {
	compared, err := c.comparePackedIntegerLanes(baseOp, laneBits, byteWidth, first, second, broadcast, writeMask)
	if err != nil {
		return err
	}
	lanes := byteWidth * 8 / laneBits
	packedType := fmt.Sprintf("i%d", lanes)
	packed := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i1> %s to %s\n", packed, lanes, compared, packedType)
	result := "%" + packed
	if lanes < 64 {
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext %s %s to i64\n", wide, packedType, result)
		result = "%" + wide
	}
	if writeMask != "" {
		masked := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %s, %s\n", masked, result, writeMask)
		result = "%" + masked
	}
	return c.storeK(dst, result)
}

func (c *amd64Ctx) loadMaskedPackedCompareLanes(source Operand, byteWidth, laneBits int, broadcast bool, mask string) (string, error) {
	// FP describes independent checked virtual slots, not one contiguous
	// native allocation. Keep per-slot loads; never form a vector pointer
	// from only the first slot, even when its address happens to be available.
	if source.Kind == OpFP && !broadcast {
		for offset := source.FPOffset; offset < source.FPOffset+int64(byteWidth); offset += 8 {
			_, parameter := c.fpParam(offset)
			_, _, result := c.fpResultAlloca(offset)
			if !parameter && !result {
				return "", fmt.Errorf("%s packed compare uses an undeclared FP vector slot at +%d(FP)", c.goarch, offset)
			}
		}
	}
	if mask == "" || source.Kind == OpReg || source.Kind == OpFP {
		return c.loadPackedCompareLanes(source, byteWidth, laneBits, broadcast)
	}
	lanes := byteWidth * 8 / laneBits
	if broadcast {
		relevant, active := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %s, %d\n", relevant, mask, uint64(1)<<uint(lanes)-1)
		fmt.Fprintf(c.b, "  %%%s = icmp ne i64 %%%s, 0\n", active, relevant)
		value, err := c.loadX86ScalarMemoryIf(source, laneBits, "%"+active)
		if err != nil {
			return "", err
		}
		return amd64SplatInteger(c, lanes, laneBits, value), nil
	}
	pointer, pointerType, suffix, err := c.packedVectorMemoryPointer(source)
	if err != nil {
		return "", err
	}
	if suffix == "" {
		suffix = ".p0"
	}
	predicate := amd64IntegerMaskVector(c, lanes, mask)
	value := c.newTmp()
	vectorType := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.masked.load.v%di%d%s(%s align 1 %s, <%d x i1> %s, %s zeroinitializer)\n", value, vectorType, lanes, laneBits, suffix, pointerType, pointer, lanes, predicate, vectorType)
	return "%" + value, nil
}
