package plan9asm

import (
	"bytes"
	"strings"
)

type x86FixedLocalData struct {
	size, alignment int64
	literals        map[int64]x86ShiftLiteral
}

type x86FixedLocalMemoryRole uint8

const (
	x86FixedLocalPrivateMemory x86FixedLocalMemoryRole = iota
	x86FixedLocalLiteralMemory
	x86FixedLocalNativeInput
)

func fixedLocalDataSymbol(symbol string) (string, bool) {
	name := strings.TrimPrefix(symbol, "·")
	if !strings.HasSuffix(name, "<>") || len(name) <= 2 || strings.ContainsAny(name, "·/.") {
		return "", false
	}
	return "·" + name, true
}

// Library callers preserve the private <> spelling; the ordinary CLIs render
// it as $local. Both describe the same source-local LLVM namespace, not the
// original Go object's name/ABI. Never accept an arbitrary caller renaming.
func fixedLocalDataEmissionMatches(symbol, packagePath, emitted string) bool {
	canonical := numericalNativeName(symbol, packagePath)
	return emitted == canonical || emitted == strings.TrimSuffix(canonical, "<>")+"$local"
}

// Called under the original source lock after its whole parsed file has been
// matched. Private literal definitions cannot be replaced by a Go variable,
// linker winner, mutable global, address initializer or caller-supplied extent.
func (source *GoAMD64FrameSource) fixedLocalData(file *File, expanded string, resolve func(string) string) (map[string]x86FixedLocalData, map[string]string, error) {
	if len(file.Data)+len(file.Globl) == 0 {
		return nil, nil, nil
	}
	observed, err := source.fixedLocalDataObservation(source.request.AssemblyFile, expanded)
	if err != nil {
		return nil, nil, err
	}
	if len(observed.Layouts) != len(file.Globl) {
		return nil, nil, goAMD64FrameContext("fixed local DATA lacks its whole original definition inventory")
	}
	data := make(map[string]x86FixedLocalData)
	requests := x86PackedLogicalLiteralRequests(file, "amd64")
	symbols := make(map[string]string)
	// BindFixedLocal has already frozen the resolver outside the source lock.
	// Keep every emitted definition injective, including the complete TEXT set.
	used := make(map[string]bool, len(file.Funcs)+len(file.Globl))
	for _, fn := range file.Funcs {
		name := resolve(fn.Sym)
		if name == "" || used[name] {
			return nil, nil, goAMD64FrameContext("fixed local emitted function identities are empty or collapsed")
		}
		used[name] = true
	}
	var total int64
	for index, global := range file.Globl {
		layout := observed.Layouts[index]
		definition := layout.Definition
		name, private := fixedLocalDataSymbol(global.Sym)
		emitted := resolve(name)
		if _, duplicate := symbols[name]; duplicate {
			return nil, nil, goAMD64FrameContext("fixed local DATA definitions collapse to the same translated identity")
		}
		if !private || !fixedLocalDataEmissionMatches(name, source.selection.ImportPath, emitted) || used[emitted] {
			return nil, nil, goAMD64FrameContext("fixed local DATA resolver changed or collapsed its private emitted identity")
		}
		used[emitted] = true
		total += int64(definition.Size)
		if !layout.Static || layout.ABI != 65535 ||
			layout.Flags != 8 && layout.Flags != 24 || definition.Kind != 3 && definition.Kind != 4 || definition.Flags != 0 ||
			definition.Flags2 != 0 || len(definition.Relocations) != 0 || global.SizeRaw != "" ||
			definition.Size == 0 || definition.Size > 64<<10 || total > 1<<20 || len(definition.Data) > int(definition.Size) {
			return nil, nil, goAMD64FrameContext("fixed local DATA requires bounded private relocation-free readonly storage")
		}
		// Compare the translator's complete initializer with independent actual
		// Go bytes, including sparse zero gaps and trailing allocation. A GLOBL
		// that shortens preceding DATA must not acquire a larger LLVM extent.
		image := make([]byte, definition.Size)
		size := global.Size
		for _, fragment := range file.Data {
			if fragment.Sym != global.Sym {
				continue
			}
			payload, err := dataStmtPayload(fragment)
			if err != nil || fragment.Addr != "" || fragment.Off < 0 || fragment.Off > int64(len(image))-int64(len(payload)) {
				return nil, nil, goAMD64FrameContext("fixed local DATA initializer has an unbound source byte extent")
			}
			copy(image[fragment.Off:], payload)
			if end := fragment.Off + int64(len(payload)); end > size {
				size = end
			}
		}
		if size != int64(definition.Size) || !bytes.Equal(image[:len(definition.Data)], definition.Data) ||
			!bytes.Equal(image[len(definition.Data):], make([]byte, len(image)-len(definition.Data))) {
			return nil, nil, goAMD64FrameContext("fixed local translated DATA differs from the original Go initialized extent")
		}
		literal := x86FixedLocalData{size: size, alignment: goAssemblyDataAlignment(ArchAMD64, size)}
		for offset, width := range requests[global.Sym] {
			if offset > size-int64(width) {
				continue // The ordinary full access check owns this rejection.
			}
			if literal.literals == nil {
				literal.literals = make(map[int64]x86ShiftLiteral)
			}
			tuple := x86ShiftLiteral{width: uint8(width)}
			copy(tuple.bytes[:], image[offset:offset+int64(width)])
			literal.literals[offset] = tuple
		}
		data[global.Sym] = literal
		symbols[name] = emitted
	}
	return data, symbols, nil
}

// Project only immutable original DATA facts while constructing the local
// effect plan. The full memory read and its bounds/alignment remain unchanged.
func fixedLocalLogicalLiteralEffect(ins Instr, effect x86TypedByteEffect, binding *x86FixedLocalBinding) x86TypedByteEffect {
	if binding == nil || len(ins.Args) == 0 || ins.Args[0].Kind != OpSym {
		return effect
	}
	form, known, err := x86PackedLogicalProperties(ins, "amd64")
	if !known || err != nil || form.memory != form.first || form.memoryBytes <= 0 {
		return effect
	}
	address, valid := x86StaticSBReadAddress(form.source, "amd64")
	literal := binding.literalData[address.symbol].literals[address.offset]
	if !valid || int(literal.width) < form.memoryBytes {
		return effect
	}
	var required uint64
	for index := 0; index < form.byteWidth; index++ {
		if x86PackedLogicalSecondBits(form.spec.mode, literal.bytes[index%form.memoryBytes]) != 0 {
			required |= uint64(1) << uint(index)
		}
	}
	if required == x86CallerVectorByteMask(int64(form.byteWidth)) {
		return effect
	}
	effect.operands = append([]x86TypedByteOperand(nil), effect.operands...)
	for index := range effect.operands {
		operand := &effect.operands[index]
		if operand.index == form.second && operand.operand.Kind == OpReg {
			// requiredBytes zero otherwise means the ordinary full-width read.
			operand.read, operand.requiredBytes = required != 0, required
		}
	}
	return effect
}

// Readonly DATA never receives a frame offset or a native-frame certificate.
// The only consumer is an already registered numerical memory operand. The
// complete original file and immutable symbol resolution own its LLVM global.
func fixedLocalReadMemory(ins *Instr, index int, state *x86FixedLocalState, proof *x86FixedLocalProof,
	residue int, width, alignment int64) (offset int64, role x86FixedLocalMemoryRole, err error) {
	if index >= 0 && index < len(ins.Args) && ins.Args[index].Kind == OpSym {
		if proof.binding == nil || width <= 0 || alignment <= 0 {
			return 0, x86FixedLocalLiteralMemory, goAMD64FrameContext("fixed local DATA read has no original literal owner")
		}
		name, offset, valid := parseSBRef(ins.Args[index].Sym)
		if !valid || !fixedLocalLiteralRange(proof.binding, x86StaticSBAddress{name, offset}, width, alignment) {
			return 0, x86FixedLocalLiteralMemory, goAMD64FrameContext("fixed local DATA read exceeds original identity, extent or alignment")
		}
		return offset, x86FixedLocalLiteralMemory, nil
	}
	return fixedLocalMemoryAccess(ins, index, state, proof, residue, width, alignment, false, false)
}

func fixedLocalLiteralRange(binding *x86FixedLocalBinding, address x86StaticSBAddress, width, alignment int64) bool {
	if binding == nil || width <= 0 || alignment <= 0 {
		return false
	}
	data, found := binding.literalData[address.symbol]
	return found && address.offset >= 0 && width <= data.size && address.offset <= data.size-width &&
		alignment <= data.alignment && address.offset%alignment == 0
}

func fixedLocalStaticAddressStep(ins Instr, state *x86FixedLocalState, proof *x86FixedLocalProof) (bool, error) {
	address, valid := fixedLocalStaticAddress(ins)
	if !valid {
		return false, nil
	}
	fail := func() (bool, error) {
		return true, goAMD64FrameContext("fixed local address has no matching original storage: %s", ins.Op)
	}
	if proof == nil || proof.binding == nil {
		return fail()
	}
	var origin x86FixedLocalOrigin
	if _, literal := proof.binding.literalData[address.symbol]; literal {
		// Address computation may leave an object before returning. A later
		// exact access owns its bounds diagnostic, never adjacent storage.
		origin.literal = address
	} else {
		object, found := proof.binding.globals[fixedLocalGlobalSymbol(address.symbol)]
		if ins.Op == "LEAQ" || !found || object.variable == nil || object.native == "" {
			return fail()
		}
		origin.global = object.native
	}
	writeFixedLocalOrigin(state, ins.Args[1].Reg, fixedLocalOrigin(origin))
	return true, nil
}

func writeFixedLocalOrigin(state *x86FixedLocalState, destination Reg, origin x86FixedLocalOrigins) {
	state.revokeRange(destination)
	delete(state.pointers, destination)
	delete(state.constants, destination)
	state.opaque[destination], state.known[destination], state.booleans[destination] = origin, 0, 0
}
