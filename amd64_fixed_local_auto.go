package plan9asm

import (
	"math"
	"reflect"
	"strings"
)

// NAME_AUTO is a source address role, not an input/storage permission. Go
// obj6 adds deltasp-bpsize to its explicit offset. This bounded observer has
// no CALL/PUSH/POP/ADJSP producer, so the lexical bias is exactly TEXT's local
// size; separately proved SP relocation still contributes its native offset.
// Replay the original operand because parsing constant expressions alone
// loses the difference between tmp-8(SP) and physical -8(SP).
func fixedLocalMemoryAddress(ins Instr, index int, frame int64) (MemRef, error) {
	fail := func() (MemRef, error) {
		return MemRef{}, goAMD64FrameContext("fixed local original memory address role is not closed")
	}
	if index < 0 || index >= len(ins.Args) {
		return fail()
	}
	operand := ins.Args[index]
	addressMove := false
	if index == 0 {
		if view, known, err := x86NamedFrameMoveAddressInstruction(ins, "amd64"); known {
			if err != nil {
				return fail()
			}
			operand, addressMove = view.Args[0], true
		}
	}
	if operand.Kind != OpMem {
		return fail()
	}
	memory := operand.Mem
	if memory.Base != SP {
		if memory.OffRaw != "" {
			return fail()
		}
		return memory, nil
	}
	op, rest := splitOpcode(ins.Raw)
	literals := splitTopLevelCSV(rest)
	if !strings.EqualFold(op, string(ins.Op)) || len(literals) != len(ins.Args) {
		return fail()
	}
	parsed, err := parseOperandForArch(ArchAMD64, literals[index])
	if err != nil || !reflect.DeepEqual(parsed, ins.Args[index]) {
		return fail()
	}
	spelling := strings.TrimSpace(literals[index])
	if addressMove {
		spelling = strings.TrimSpace(strings.TrimPrefix(spelling, "$"))
	}
	literal := x86ResultAUTOLiteral.FindStringSubmatch(spelling)
	if literal == nil {
		// Indexing/segment/symbol roles are independently validated by the
		// native observer; none may be relabeled as a named local offset.
		if memory.OffRaw != "" {
			return fail()
		}
		return memory, nil
	}
	prefix := strings.TrimSpace(literal[1])
	offset, named := parseNamedStackConstantOffset(prefix)
	if validPPIdentifier(prefix) {
		offset, named = 0, true
	}
	if !named {
		if memory.OffRaw != "" {
			return fail()
		}
		return memory, nil // Numeric, unnamed (SP) remains post-prologue SP.
	}
	if offset != memory.Off || frame <= 0 || offset > 0 && frame > math.MaxInt64-offset {
		return fail()
	}
	memory.Off += frame
	memory.OffRaw = ""
	return memory, nil
}

// This query resolves only a complete numerical constant index. It neither
// changes the emitted address nor supplies a memory origin, extent or access.
// All arithmetic is checked before an original private/literal bound is used.
func fixedLocalConstantDisplacement(memory MemRef, state *x86FixedLocalState) (int64, bool) {
	if memory.OffRaw != "" || memory.Sym != "" || memory.Segment != "" || memory.IndexExt != "" {
		return 0, false
	}
	if memory.Index == "" {
		return memory.Off, memory.Scale == 0
	}
	root, valid := x86CallerGP(memory.Index)
	value, known := state.constants[root]
	scale := memory.Scale
	if !valid || root != memory.Index || !known ||
		!fixedLocalNumericRead(Operand{Kind: OpReg, Reg: root}, 8, state) ||
		scale != 1 && scale != 2 && scale != 4 && scale != 8 {
		return 0, false
	}
	if value > math.MaxInt64/scale || value < math.MinInt64/scale {
		return 0, false
	}
	delta := value * scale
	if delta > 0 && memory.Off > math.MaxInt64-delta || delta < 0 && memory.Off < math.MinInt64-delta {
		return 0, false
	}
	return memory.Off + delta, true
}

// Reads, writes and complete pointer-spill lookups use the same resolved
// byte address. An indexed read must not borrow the unindexed slot's role.
func fixedLocalPrivateOffset(memory MemRef, state *x86FixedLocalState) (int64, bool) {
	base, private := state.pointers[memory.Base]
	displacement, known := fixedLocalConstantDisplacement(memory, state)
	if !private || !known || displacement > 0 && base > math.MaxInt64-displacement ||
		displacement < 0 && base < math.MinInt64-displacement {
		return 0, false
	}
	return base + displacement, true
}

// Descriptive bare NAME_AUTO is offset zero, not an undefined preprocessor
// expression. This syntax query does not grant a native memory certificate.
func x86ConditionalMoveOffsetKnown(memory MemRef) bool {
	if memory.OffRaw == "" {
		return true
	}
	if memory.Base != SP || memory.Sym != "" {
		return false
	}
	if offset, named := parseNamedStackConstantOffset(memory.OffRaw); named {
		return offset == memory.Off
	}
	return validPPIdentifier(memory.OffRaw) && memory.Off == 0
}

func fixedLocalConditionalMoveStep(ins *Instr, state *x86FixedLocalState, sig FuncSig, proof *x86FixedLocalProof, residue int) (bool, error) {
	form, known, err := x86ConditionalMoveProperties(ins.Op, *ins, "amd64")
	if !known {
		return false, nil
	}
	fail := func() (bool, error) {
		return true, goAMD64FrameContext("fixed local CMOV flags or conditional value roles are not defined")
	}
	required := x86ByteConditionFlags(form.condition)
	if err != nil || required == 0 || state.flags&required != required {
		return fail()
	}
	if ins.Args[0].Kind == OpFP {
		// Declared numerical FP inputs use the shared GP effect. This value
		// transport path retains its existing pointer and private-spill roles.
		value, err := fixedLocalReadValue(ins, 0, state, sig, proof, residue, int64(form.bits/8), false)
		if err != nil || value.pointer || value.opaque {
			return fail()
		}
		old, err := fixedLocalReadValue(ins, 1, state, sig, proof, residue, int64(form.bits/8), false)
		if err != nil || old.pointer || old.opaque {
			return fail()
		}
		return false, nil
	}
	width := int64(form.bits / 8)
	old, err := fixedLocalReadValue(ins, 1, state, FuncSig{}, proof, residue, width, false)
	if err != nil {
		return true, err
	}
	// Both potential values remain mandatory. In particular memory is read
	// unconditionally; selecting it never grants logical FP pointer imports.
	value, err := fixedLocalReadValue(ins, 0, state, FuncSig{}, proof, residue, width, false)
	if err != nil {
		return true, err
	}
	if value.opaque && old.opaque && !value.identity.equal(old.identity) &&
		(!fixedLocalOriginOwners(value.identity, proof) || !fixedLocalOriginOwners(old.identity, proof)) {
		return fail()
	}
	value, valid := mergeFixedLocalScalarValues(value, old)
	if !valid {
		return fail()
	}
	return true, fixedLocalWriteValue(ins, 1, 0, value, state, FuncSig{}, proof, residue, width)
}
