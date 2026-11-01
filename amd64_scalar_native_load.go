package plan9asm

import (
	"fmt"
	"reflect"
)

// Register-addressed memory-to-GP rows of Go's ymovb/ymovw/ymovl/ymovq tables.
// Register, immediate, static-symbol, FP/AUTO, MMX/X and system-register rows
// keep their own consumers, including Go's distinct symbol-address roles.
// This is an ordinary native load shape, not a memory-ownership certificate.
type x86ScalarNativeLoadForm struct {
	source      Operand
	destination Reg
	bytes       int64
}

// The decoder binds mode and physical shape separately from source/ABI
// permissions. Only the paired volatile scalar reader consumes this identity.
type x86RawScalarSegmentLoadIdentity struct {
	arch          string
	bytes         int64
	segmentPrefix byte
}

func x86ScalarSegmentLoadRawIdentity(ins Instr, arch string) x86RawScalarSegmentLoadIdentity {
	arch = x86SourceStackScalarArch(arch)
	if arch != "amd64" && arch != "386" {
		return x86RawScalarSegmentLoadIdentity{}
	}
	ins.x86Encoded = true // Physical memory is already normalized by the decoder.
	form, known, err := x86ScalarNativeLoadProperties(ins.Op, ins, arch)
	if !known || err != nil || form.source.Mem.Segment != FS && form.source.Mem.Segment != GS {
		return x86RawScalarSegmentLoadIdentity{}
	}
	return x86RawScalarSegmentLoadIdentity{arch, form.bytes, ins.x86SegmentPrefix}
}

func x86RawScalarSegmentLoadSource(ins Instr, arch string) bool {
	origin := ins.x86SourceRaw
	identity := x86ScalarSegmentLoadRawIdentity(ins, arch)
	return ins.x86Encoded && origin != nil && identity.arch != "" && identity == origin.scalarSegmentLoad &&
		origin.op == ins.Op && reflect.DeepEqual(origin.args, ins.Args) &&
		origin.vectorBytes == ins.x86VectorBytes && origin.addressBits == ins.x86AddressBits &&
		ins.x86AddressBits == 0 && !ins.x86UnboundAddressOverride && ins.x86SegmentPrefix == 0 &&
		ins.x86RawNearReturn == nil && !ins.x86RIPLiteral && ins.x86NumericalRead == nil
}

func x86ScalarNativeLoadProperties(op Op, ins Instr, arch string) (x86ScalarNativeLoadForm, bool, error) {
	form, known, err := x86ScalarRegisterLoadProperties(op, ins, arch)
	if !known || err != nil {
		return form, known, err
	}
	if !x86OrdinaryNativeMemoryOperand(form.source, arch) {
		return x86ScalarNativeLoadForm{}, false, nil
	}
	return form, true, nil
}

// The machine grammar is independent of whether BP denotes an ordinary
// native input, a private frame, or an unavailable physical entry register.
// Each consumer must select that role before calling the common emitter.
func x86ScalarRegisterLoadProperties(op Op, ins Instr, arch string) (x86ScalarNativeLoadForm, bool, error) {
	if form, known, err := x86ScalarMoveAliasProperties(op, ins, arch); known {
		if err != nil {
			return x86ScalarNativeLoadForm{}, true, err
		}
		if form.spec.load {
			return x86ScalarNativeLoadForm{}, false, nil // Existing extension storage consumer.
		}
		op = form.spec.canonical
	}
	local := ins
	local.Op = op
	canonical := x86SourceMoveInstruction(local, arch).Op
	width := x86RawReturnScalarMoveBytes(canonical)
	if width == 0 || len(ins.Args) != 2 || ins.Args[0].Kind != OpMem || ins.Args[1].Kind != OpReg {
		return x86ScalarNativeLoadForm{}, false, nil
	}
	source, destination := ins.Args[0], ins.Args[1].Reg
	if source.Mem.Sym != "" {
		return x86ScalarNativeLoadForm{}, false, nil
	}
	if projected, segment, err := x86NamedSegmentMemorySource(ins, source, arch); segment {
		if err != nil {
			return x86ScalarNativeLoadForm{}, true, err
		}
		source = projected
	}
	validRegister := isX86YrlRegisterForArch(destination, arch)
	if width == 1 {
		validRegister = isGoYmbRegisterForArch(destination, arch)
	}
	if !validRegister {
		return x86ScalarNativeLoadForm{}, false, nil
	}
	if arch == "386" && width == 8 || !x86PackedShiftMemoryValid(source, arch) {
		return x86ScalarNativeLoadForm{}, true, fmt.Errorf("invalid %s native scalar load: %q", arch, ins.Raw)
	}
	if width == 1 && arch != "386" &&
		(x86ExtensionHighRegister(source.Mem.Base) || x86ExtensionHighRegister(source.Mem.Index)) {
		// Go emits the actual REX byte even with AH/CH/DH/BH source
		// spellings. Their ModRM numbers then name SP/BP/SI/DI low bytes.
		switch destination {
		case AH, CH, DH, BH:
			destination = amd64YmbEffectiveRegister(destination, 16)
		}
	}
	return x86ScalarNativeLoadForm{source, destination, width}, true, nil
}

func (c *amd64Ctx) scalarNativeLoadProperties(op Op, ins Instr) (x86ScalarNativeLoadForm, bool, error) {
	if c.fixedLocal != nil {
		if access, valid := c.fixedLocalMemoryAccess(ins, 0); valid && access.nativeInput {
			return x86ScalarRegisterLoadProperties(op, ins, c.goarch)
		}
	}
	return x86ScalarNativeLoadProperties(op, ins, c.goarch)
}

func (c *amd64Ctx) lowerScalarNativeLoad(form x86ScalarNativeLoadForm, ins Instr) error {
	if form.destination != ins.Args[1].Reg && (form.destination == SP || form.destination == BP) {
		return fmt.Errorf("%w: REX byte alias needs its physical SP/BP write contract", ErrProbeNeedsContext)
	}
	if ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride {
		return fmt.Errorf("%w: scalar MOV needs its original native address size", ErrProbeNeedsContext)
	}
	pointer, pointerType, _, err := c.packedVectorMemoryPointer(form.source)
	if err != nil {
		return err
	}
	typ := amd64IntegerTypeForBits(int(form.bytes * 8))
	loaded := c.newTmp()
	// The fault/read remains observable even when the numerical result is
	// discarded. This asserts no pointee extent, alignment or nonaliasing.
	fmt.Fprintf(c.b, "  %%%s = load volatile %s, %s %s, align 1\n", loaded, typ, pointerType, pointer)
	return c.storeRegSized(form.destination, typ, "%"+loaded)
}

func x86LoweredScalarNativeLoad(ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) (bool, bool) {
	form, known, err := x86ScalarNativeLoadProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	if !x86ResultNamedPredicateInstruction(ins) && !x86RawScalarSegmentLoadSource(ins, arch) || ins.x86NumericalRead != nil {
		return false, true // Physical emission does not grant a named numerical continuation.
	}
	if x86LogicalSourceFrameRegister(form.destination, arch) {
		return false, true
	}
	if form.source.Mem.Segment != "" {
		// The hardware segment base is an implicit input of this exact
		// volatile emitter, not an initialized AS0 pointer or GP zero.
		// Any explicit offset base still needs its full numerical value;
		// opaque caller/pointer identities cannot supply those bits.
		for _, register := range []Reg{form.source.Mem.Base, form.source.Mem.Index} {
			if register == "" {
				continue
			}
			word := x86ResultPointerWord(arch)
			index, _, valid := x86ResultGP(register, word, arch)
			if !valid || !state.shapeOnly && state.pointerGP[index] ||
				!x86ResultRead(Operand{Kind: OpReg, Reg: register}, word, state, owned, arch) {
				return false, true
			}
		}
		return x86ResultStore(Operand{Kind: OpReg, Reg: form.destination}, form.bytes, state, owned, resultOffset, arch), true
	}
	if !x86ResultReadWithNativeContinuation(ins, form.source, form.bytes, state, owned, arch, true) {
		return false, true
	}
	return x86ResultStore(Operand{Kind: OpReg, Reg: form.destination}, form.bytes, state, owned, resultOffset, arch), true
}
