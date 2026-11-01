package plan9asm

import (
	"fmt"
	"strings"
)

type x86SignedPackedFloatSpec struct {
	bits   int
	legacy bool
}

// The complete signed dword-to-floating Go namespace. Scalar signed and
// unsigned packed conversions have different grammars and are not included.
var x86SignedPackedFloatSpecs = map[Op]x86SignedPackedFloatSpec{
	"CVTPL2PS": {bits: 32, legacy: true}, "CVTPL2PD": {bits: 64, legacy: true},
	"VCVTDQ2PS": {bits: 32}, "VCVTDQ2PD": {bits: 64},
}

type x86SignedPackedFloatForm struct {
	spec                          x86SignedPackedFloatSpec
	byteWidth, sourceBytes        int
	inputBytes, memoryBytes       int
	destination, memory, mask     int
	mmx, evex, broadcast, zeroing bool
	rounding                      string
}

// Shape and physical encoding only: this does not grant caller memory access,
// numeric initialization, contiguous FP backing, or an executable host ISA.
func x86SignedPackedFloatProperties(ins Instr, goarch string) (x86SignedPackedFloatForm, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	spec, recognized := x86SignedPackedFloatSpecs[Op(base)]
	if !recognized {
		return x86SignedPackedFloatForm{}, false, nil
	}
	f := x86SignedPackedFloatForm{
		spec: spec, destination: len(ins.Args) - 1, memory: -1, mask: -1,
		mmx: ins.x86MMXSourceConversion,
	}
	fail := func() (x86SignedPackedFloatForm, bool, error) {
		return f, true, fmt.Errorf("%s %s outside Go signed packed dword-to-float grammar: %q", goarch, ins.Op, ins.Raw)
	}
	if goarch != "amd64" && goarch != "386" || len(ins.Args) != 2 && len(ins.Args) != 3 || f.mmx && !spec.legacy {
		return fail()
	}
	suffix, err := parseAMD64PackedDoubleDwordSuffix(strings.ToUpper(string(ins.Op)), base)
	if err != nil || suffix.sae || spec.legacy && (len(ins.Args) != 2 || strings.ToUpper(string(ins.Op)) != base) {
		return fail()
	}
	f.broadcast, f.zeroing, f.rounding = suffix.broadcast, suffix.zeroing, suffix.rounding
	if len(ins.Args) == 3 {
		if !amd64NonzeroKOperand(ins.Args[1]) {
			return fail()
		}
		f.mask = 1
	} else if f.zeroing {
		return fail()
	}
	destination := ins.Args[f.destination]
	f.byteWidth = amd64VectorByteWidth(destination.Reg)
	if destination.Kind != OpReg || !amd64EVEXVectorRegister(destination, f.byteWidth) ||
		spec.legacy && (!amd64VEXVectorRegister(destination, 16) || goarch == "386" && !amd64Mode32VectorOperand(destination)) {
		return fail()
	}
	f.inputBytes = f.byteWidth * 32 / spec.bits
	f.sourceBytes = f.byteWidth
	if spec.bits == 64 {
		f.sourceBytes = 16
		if f.byteWidth == 64 {
			f.sourceBytes = 32
		}
	}
	if f.mmx {
		f.inputBytes, f.sourceBytes = 8, 8
	}
	source := ins.Args[0]
	if source.Kind == OpReg {
		_, mmxRegister := amd64ParseMReg(source.Reg)
		f.mmx = f.mmx || mmxRegister
		// Go's ycover admits these GP spellings to Ymm and emits an
		// MMX opcode, not an integer GP conversion. Never read their GP
		// value as though it were the physical MMX input.
		f.mmx = f.mmx || spec.legacy && isAMD64YrlRegister(source.Reg) &&
			(goarch != "386" || !amd64IsExtendedGPRegister(source.Reg))
		if f.mmx {
			if !spec.legacy {
				return fail()
			}
			f.inputBytes, f.sourceBytes = 8, 8
		} else if !amd64EVEXVectorRegister(source, f.sourceBytes) || spec.legacy &&
			(!amd64VEXVectorRegister(source, 16) || goarch == "386" && !amd64Mode32VectorOperand(source)) {
			return fail()
		}
	} else if isAMD64MemoryOperand(source) {
		if !x86SignedPackedFloatMemoryOperand(source, goarch) {
			return fail()
		}
		f.memory, f.memoryBytes = 0, f.inputBytes
	} else {
		return fail()
	}
	if f.broadcast {
		if spec.legacy || f.memory < 0 {
			return fail()
		}
		f.memoryBytes = 4
	}
	if f.rounding != "" && (spec.bits != 32 || spec.legacy || f.byteWidth != 64 || source.Kind != OpReg) {
		return fail()
	}
	if !spec.legacy {
		f.evex = ins.x86PackedNumericEVEX || f.byteWidth == 64 || f.mask >= 0 || f.broadcast || f.rounding != ""
		for _, operand := range []Operand{source, destination} {
			if operand.Kind == OpReg {
				index, _ := amd64VectorRegisterIndex(operand.Reg, amd64VectorByteWidth(operand.Reg))
				f.evex = f.evex || index >= 16
				if goarch == "386" && index >= 8 {
					return f, true, fmt.Errorf("%w: %s register %s has no physical mode32 binding", ErrProbeNeedsContext, ins.Op, operand.Reg)
				}
			}
		}
	}
	return f, true, nil
}

func amd64Mode32VectorOperand(op Operand) bool {
	index, valid := amd64VectorRegisterIndex(op.Reg, amd64VectorByteWidth(op.Reg))
	return valid && index < 8
}

func x86SignedPackedFloatMemoryOperand(source Operand, goarch string) bool {
	if source.Kind == OpSym {
		symbol := strings.TrimSpace(source.Sym)
		_, absolute := parseInt(symbol)
		return !strings.HasPrefix(symbol, "$") && (strings.HasSuffix(symbol, "(SB)") || absolute == nil)
	}
	if source.Kind != OpMem {
		return source.Kind == OpFP
	}
	displacement := source.Mem.Off
	return (displacement == int64(int32(displacement)) || goarch == "386" && displacement == int64(uint32(displacement))) &&
		x86MemoryRegistersValidForArch(source.Mem, goarch) && (source.Mem.Index == "" || source.Mem.Index != SP &&
		(source.Mem.Scale == 1 || source.Mem.Scale == 2 || source.Mem.Scale == 4 || source.Mem.Scale == 8))
}

func (c *amd64Ctx) lowerSignedPackedIntegerFloat(op Op, ins Instr) (bool, bool, error) {
	f, known, err := x86SignedPackedFloatProperties(ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	if !strings.EqualFold(string(op), string(ins.Op)) {
		return true, false, fmt.Errorf("signed packed conversion opcode identity mismatch: %s versus %s", op, ins.Op)
	}
	if f.mmx {
		// A body whitelist cannot close the caller's physical MMX/x87
		// observations after RET. A private MM0 scratch would alter a
		// different register when the source names M1, and also affects
		// x87 Tag/TOS and pending exceptions. No current producer supplies
		// that complete entry/caller contract; virtual values are not it.
		return true, false, fmt.Errorf("%w: MMX source conversion lacks a complete physical MMX/x87 caller contract", ErrProbeNeedsContext)
	}
	source := ins.Args[0]
	// Neither a collection of typed FP fields nor our virtual stack is the
	// original native backing/alignment/fault contract of packed memory.
	if source.Kind == OpFP {
		if err := c.validateFPVectorSpan(source.FPOffset, f.memoryBytes); err != nil {
			return true, false, err
		}
		return true, false, fmt.Errorf("%w: %s packed FP source lacks original native backing", ErrProbeNeedsContext, ins.Op)
	}
	if ins.x86AddressBits != 0 || source.Kind == OpMem &&
		!x86OrdinaryNativeMemoryOperand(source, c.goarch) && !c.fixedLocalMemoryCertified(ins, f.memory) {
		return true, false, fmt.Errorf("%w: %s packed memory lacks original native address binding", ErrProbeNeedsContext, ins.Op)
	}
	return true, false, c.emitSignedPackedIntegerFloat(ins, f)
}

// One original native packed opcode retains ambient RC/PE/trap ordering,
// active-lane memory fault suppression and ER+SAE. Do not scalarize or emit
// plain sitofp: O2 may fold it and lose both dynamic rounding and precision.
func (c *amd64Ctx) emitSignedPackedIntegerFloat(ins Instr, f x86SignedPackedFloatForm) error {
	mnemonic := strings.ToLower(strings.Split(string(ins.Op), ".")[0])
	if f.spec.legacy {
		mnemonic = "cvtdq2ps"
		if f.spec.bits == 64 {
			mnemonic = "cvtdq2pd"
		}
	}
	return c.emitNativePackedConversion(ins, x86NativePackedConversion{
		byteWidth: f.byteWidth, sourceBytes: f.sourceBytes, memoryBytes: f.memoryBytes,
		outputBits: f.spec.bits, destination: f.destination, mask: f.mask,
		lanes: f.byteWidth * 8 / f.spec.bits,
		mmx:   f.mmx, legacy: f.spec.legacy, evex: f.evex, broadcast: f.broadcast,
		zeroing: f.zeroing, rounding: f.rounding, mnemonic: mnemonic,
	})
}

type x86NativePackedConversion struct {
	byteWidth, sourceBytes, memoryBytes, outputBits int
	destination, mask, lanes                        int
	source                                          int // Explicit family-selected data operand; default zero.
	mmx, legacy, evex, broadcast, zeroing, sae      bool
	rounding, mnemonic                              string
	logicalFPBits                                   int   // Explicit owned-value projection, never native FP backing.
	immediate                                       *byte // Explicit original imm8, not an arithmetic rounding approximation.
}

func (c *amd64Ctx) emitNativePackedConversion(ins Instr, f x86NativePackedConversion) error {
	if f.mmx {
		return fmt.Errorf("%w: no physical MMX/x87 caller contract", ErrProbeNeedsContext)
	}
	typ := amd64FloatingVectorType(f.byteWidth*8/f.outputBits, f.outputBits)
	old := "zeroinitializer"
	if f.mask >= 0 && !f.zeroing {
		value, err := c.loadPackedCompareBytes(ins.Args[f.destination], f.byteWidth)
		if err != nil {
			return err
		}
		old = "%" + c.newTmp()
		fmt.Fprintf(c.b, "  %s = bitcast <%d x i8> %s to %s\n", old, f.byteWidth, value, typ)
	}
	constraint := "x"
	if f.evex {
		constraint = "v"
	}
	inputConstraint, inputType, inputTemplate := constraint, fmt.Sprintf("<%d x float>", f.sourceBytes/4), "$2"
	var input string
	var err error
	source := ins.Args[f.source]
	mnemonic := f.mnemonic
	prefix := ""
	if source.Kind == OpReg {
		bytes, loadErr := c.loadPackedCompareBytes(source, f.sourceBytes)
		if loadErr != nil {
			return loadErr
		}
		input = "%" + c.newTmp()
		fmt.Fprintf(c.b, "  %s = bitcast <%d x i8> %s to %s\n", input, f.sourceBytes, bytes, inputType)
	} else if source.Kind == OpFP && f.logicalFPBits != 0 {
		input, err = c.loadPackedConversionFPValue(source, f.sourceBytes, f.memoryBytes, f.logicalFPBits, f.broadcast)
		if err != nil {
			return err
		}
	} else {
		var pointerType string
		input, pointerType, _, err = c.packedVectorMemoryPointer(source)
		if err != nil {
			return err
		}
		inputType, inputConstraint = fmt.Sprintf("%s elementtype([%d x i8])", pointerType, f.memoryBytes), "*m"
		if pointerType == "ptr addrspace(256)" {
			inputTemplate = "%gs:" + inputTemplate
		} else if pointerType == "ptr addrspace(257)" {
			inputTemplate = "%fs:" + inputTemplate
		}
	}
	if f.evex {
		mnemonic = "{evex} " + mnemonic
	}
	args := fmt.Sprintf("%s %s, %s %s", typ, old, inputType, input)
	constraints := "=" + constraint + ",0," + inputConstraint
	if f.mask >= 0 {
		mask, err := c.loadK(ins.Args[f.mask].Reg)
		if err != nil {
			return err
		}
		maskMove := "kmovw"
		if f.lanes > 16 {
			maskMove = "kmovd"
		}
		prefix += maskMove + " ${3:k}, %k1; "
		constraints += ",r,~{k1}"
		args += ", i32 " + c.approximateMathMask32(mask)
	}
	assembly := prefix + mnemonic + " "
	if f.immediate != nil {
		assembly += fmt.Sprintf("$$%d, ", *f.immediate)
	}
	if f.rounding != "" {
		assembly += "{" + strings.ToLower(strings.TrimSuffix(f.rounding, "_SAE")) + "-sae}, "
	}
	if f.sae {
		assembly += "{sae}, "
	}
	if f.broadcast && source.Kind != OpFP {
		inputTemplate += fmt.Sprintf(" {1to%d}", f.lanes)
	}
	assembly += inputTemplate + ", $0"
	if f.mask >= 0 {
		assembly += " {%k1}"
		if f.zeroing {
			assembly += " {z}"
		}
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q(%s)\n", result, typ, assembly, constraints+",~{memory},~{fpsr}", args)
	bytes := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <%d x i8>\n", bytes, typ, result, f.byteWidth)
	if f.legacy {
		return c.storeLegacyXViews(ins.Args[f.destination].Reg, "%"+bytes)
	}
	return c.storePackedMoveOperand(ins.Args[f.destination], f.byteWidth, "%"+bytes)
}
