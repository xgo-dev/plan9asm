package plan9asm

import (
	"fmt"
	"strings"
)

// One complete grammar is consumed by lowering and caller byte proofs.
// Interleaving is bitwise, including floating spellings: it never changes MXCSR.
func (c *amd64Ctx) lowerPackedUnpack(op Op, ins Instr) (bool, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	if _, recognized := x86PackedUnpackSpecs[Op(base)]; !recognized {
		return false, false, nil
	}
	if ins.Op != "" && strings.ToUpper(string(ins.Op)) != strings.ToUpper(string(op)) {
		return true, false, fmt.Errorf("packed unpack dispatch/source opcode mismatch: %s/%s", op, ins.Op)
	}
	ins.Op = op
	form, recognized, err := x86PackedUnpackProperties(ins, c.goarch)
	if err != nil || !recognized {
		return recognized, false, err
	}
	if err := x86LegacyMMXReadEmitterContext(ins, c.goarch); err != nil {
		return true, false, err
	}
	first, second, destination := ins.Args[form.first], ins.Args[form.second], ins.Args[form.destination]
	if form.legacy && !form.mmx && form.memory >= 0 {
		virtual := first.Kind == OpFP
		if first.Kind == OpMem && !x86CallerMemoryCertified(ins, form.memory) && !c.fixedLocalMemoryCertified(ins, form.memory) {
			virtual = !x86OrdinaryNativeMemoryOperand(first, c.goarch)
		}
		if virtual {
			return true, false, fmt.Errorf("%w: legacy unpack m128 needs original native storage, not virtual FP/SP/BP alignment", ErrProbeNeedsContext)
		}
	}
	laneBits := form.spec.laneBits
	lanes := form.byteWidth * 8 / laneBits
	if form.memory >= 0 && first.Kind == OpFP {
		if err := c.validateFPVectorSpan(first.FPOffset, form.memoryBytes); err != nil {
			return true, false, err
		}
	}
	if form.mmx {
		firstBits, err := c.loadPackedUnpackMMXSource(first, form.memoryBytes)
		if err != nil {
			return true, false, err
		}
		secondBits, err := c.loadReg(second.Reg)
		if err != nil {
			return true, false, err
		}
		a := c.bitcastI64ToIntegerLanes(lanes, laneBits, firstBits)
		b := c.bitcastI64ToIntegerLanes(lanes, laneBits, secondBits)
		result := c.emitPackedUnpackLanes(form.byteWidth, laneBits, form.spec.high, a, b)
		bits := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to i64\n", bits, lanes, laneBits, result)
		return true, false, c.storeReg(destination.Reg, "%"+bits)
	}
	// Intel SDM Vol.2A Tables 2-44/45 classify these EVEX permutations as
	// E4NF, not E4. A mask (even all zero) is not memory-fault suppression.
	// Do not reuse the logical family's masked-memory reader here.
	b, err := c.loadPackedCompareLanes(second, form.byteWidth, laneBits, false)
	if err != nil {
		return true, false, err
	}
	var result string
	if form.legacy && form.memory >= 0 {
		mnemonic := strings.ToLower(base)
		switch base {
		case "PUNPCKLWL":
			mnemonic = "punpcklwd"
		case "PUNPCKHWL":
			mnemonic = "punpckhwd"
		case "PUNPCKLLQ":
			mnemonic = "punpckldq"
		case "PUNPCKHLQ":
			mnemonic = "punpckhdq"
		}
		result, err = c.emitPackedBinaryNativeMemory(first, laneBits, b, mnemonic)
	} else {
		var a string
		a, err = c.loadPackedUnpackSource(first, form)
		if err == nil {
			result = c.emitPackedUnpackLanes(form.byteWidth, laneBits, form.spec.high, a, b)
		}
	}
	if err != nil {
		return true, false, err
	}
	if form.mask >= 0 {
		mask, err := c.loadK(ins.Args[form.mask].Reg)
		if err != nil {
			return true, false, err
		}
		old, err := c.loadPackedCompareLanes(destination, form.byteWidth, laneBits, false)
		if err != nil {
			return true, false, err
		}
		result = amd64ApplyIntegerLaneMask(c, lanes, laneBits, result, old, mask, form.zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, laneBits, result, form.byteWidth)
	if form.legacy {
		return true, false, c.storeLegacyPackedLogical(destination, "%"+out)
	}
	return true, false, c.storePackedMoveOperand(destination, form.byteWidth, "%"+out)
}

func (c *amd64Ctx) loadPackedUnpackSource(source Operand, form x86PackedUnpackForm) (string, error) {
	if source.Kind == OpReg || source.Kind == OpFP {
		return c.loadPackedCompareLanes(source, form.byteWidth, form.spec.laneBits, form.broadcast)
	}
	pointer, pointerType, _, err := c.packedVectorMemoryPointer(source)
	if err != nil {
		return "", err
	}
	value := c.newTmp()
	bits := form.spec.laneBits
	lanes := form.byteWidth * 8 / bits
	// An E4NF access is mandatory even when every output lane is masked off
	// or observes only part of the source. A plain LLVM load can disappear.
	if form.broadcast {
		fmt.Fprintf(c.b, "  %%%s = load volatile i%d, %s %s, align 1\n", value, bits, pointerType, pointer)
		return amd64SplatInteger(c, lanes, bits, "%"+value), nil
	}
	fmt.Fprintf(c.b, "  %%%s = load volatile <%d x i%d>, %s %s, align 1\n", value, lanes, bits, pointerType, pointer)
	return "%" + value, nil
}

func (c *amd64Ctx) loadPackedUnpackMMXSource(source Operand, memoryBytes int) (string, error) {
	if source.Kind == OpFP {
		bytes, err := c.loadFPVectorBytes(source.FPOffset, memoryBytes)
		if err != nil {
			return "", err
		}
		bits := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to i%d\n", bits, memoryBytes, bytes, 8*memoryBytes)
		if memoryBytes == 8 {
			return "%" + bits, nil
		}
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", wide, bits)
		return "%" + wide, nil
	}
	if memoryBytes == 0 {
		return c.loadLegacyMMXPackedSource(source)
	}
	pointer, pointerType, _, err := c.packedVectorMemoryPointer(source)
	if err != nil {
		return "", err
	}
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load volatile i%d, %s %s, align 1\n", value, 8*memoryBytes, pointerType, pointer)
	if memoryBytes == 8 {
		return "%" + value, nil
	}
	wide := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", wide, value)
	return "%" + wide, nil
}

// emitPackedUnpackLanes interleaves the second (vvvv/old destination) source
// with the first (r/m) source independently within each 128-bit vector lane.
func (c *amd64Ctx) emitPackedUnpackLanes(byteWidth, laneBits int, high bool, first, second string) string {
	lanes := byteWidth * 8 / laneBits
	groupBits := 128
	if byteWidth == 8 {
		groupBits = 64
	}
	groupLanes := groupBits / laneBits
	half := groupLanes / 2
	start := 0
	if high {
		start = half
	}
	mask := make([]string, 0, lanes)
	for group := 0; group < lanes/groupLanes; group++ {
		base := group * groupLanes
		for lane := start; lane < start+half; lane++ {
			index := base + lane
			mask = append(mask, fmt.Sprintf("i32 %d", index), fmt.Sprintf("i32 %d", lanes+index))
		}
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i%d> %s, <%d x i%d> %s, <%d x i32> <%s>\n",
		result, lanes, laneBits, second, lanes, laneBits, first, lanes, strings.Join(mask, ", "))
	return "%" + result
}
