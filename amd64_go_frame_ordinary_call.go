package plan9asm

import (
	"reflect"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/goabi"
)

// A Go implementation is a separately compiled callable, not an assembly
// entry or an inlineable private leaf. Select only actual direct references;
// unrelated Go declarations retain their existing transport roles.
func (source *GoAMD64FrameSource) ordinaryCallDeclarations(pkg GoPackage, file *File) (map[string]goAMD64FrameDeclaration, error) {
	leaves, err := goAMD64FramePrivateLeaves(file, pkg)
	if err != nil {
		return nil, err
	}
	entries := make(map[string]bool)
	for _, fn := range file.Funcs {
		for _, ins := range fn.Instrs {
			if ins.Op != OpCALL || len(ins.Args) != 1 || ins.Args[0].Kind != OpSym {
				continue
			}
			name, offset, valid := parseSBRef(ins.Args[0].Sym)
			if valid && offset == 0 && leaves[name] {
				continue
			}
			local := strings.TrimPrefix(name, "·")
			if local == name {
				local = strings.TrimPrefix(name, pkg.Path+".")
			}
			if !valid || offset != 0 || local == name || local == "" || strings.ContainsAny(local, "·./<>") {
				return nil, goAMD64FrameContext("ordinary CALL needs a selected same-package Go body")
			}
			entries[local] = true
		}
	}
	if len(entries) == 0 {
		return nil, nil
	}
	return source.typedSourceDeclarations(pkg, true, "amd64", false, entries, false, true)
}

func fixedLocalOrdinaryCall(ins Instr, binding *x86FixedLocalBinding) (FuncSig, bool) {
	if binding == nil || ins.Op != OpCALL || len(ins.Args) != 1 || ins.Args[0].Kind != OpSym {
		return FuncSig{}, false
	}
	symbol, offset, valid := parseSBRef(ins.Args[0].Sym)
	name := binding.symbols[symbol]
	declaration, found := binding.callees[name]
	sig, supplied := binding.signatures[name]
	return sig, valid && offset == 0 && found && supplied &&
		declaration.transport == goAMD64FrameNumericTransport && reflect.DeepEqual(sig, declaration.signature)
}

// The existing ABI0 emitter reads outgoing slots and writes only typed result
// slots. No pointer or physical scratch state crosses this numeric contract.
// A Go callee may overwrite its entire outgoing extent and every scratch bank;
// only unescaped caller locals outside that extent remain initialized.
func fixedLocalOrdinaryCallStep(ins Instr, state *x86FixedLocalState, proof *x86FixedLocalProof) error {
	sig, found := fixedLocalOrdinaryCall(ins, proof.binding)
	sp, original := state.pointers[SP]
	if !found || !original || sp != 0 || !x86ABI0FrameLayout(sig, proof.frame, "amd64") {
		return goAMD64FrameContext("ordinary CALL lacks its exact bound ABI0 outgoing layout")
	}
	_, changedBP := state.known[BP]
	if _, privateBP := state.pointers[BP]; changedBP || privateBP || state.opaque[BP].valid() {
		return goAMD64FrameContext("ordinary Go CALL requires the unchanged automatic frame pointer")
	}
	var extent int64
	for group, slots := range [][]FrameSlot{sig.Frame.Params, sig.Frame.Results} {
		for _, slot := range slots {
			width := frameTypeSize(slot.Type, 8)
			if slot.Type == Ptr || width <= 0 || slot.Offset < 0 || slot.Offset > proof.frame-width ||
				group == 0 && (!state.bytes.all(slot.Offset, width) ||
					slot.Type == I1 && !state.booleanBytes.all(slot.Offset, width)) {
				return goAMD64FrameContext("ordinary CALL reads uninitialized or nonnumeric outgoing bytes")
			}
			if end := slot.Offset + width; end > extent {
				extent = end
			}
		}
	}
	var valid bool
	extent, valid = goabi.ABI0StackSize("amd64", extent)
	if !valid || extent > proof.frame {
		return goAMD64FrameContext("ordinary CALL outgoing aligned extent exceeds its private frame")
	}
	state.bytes.setRange(0, extent, false)
	fixedLocalRevokeSpillRoles(state, 0, extent)
	for _, slot := range sig.Frame.Results {
		width := frameTypeSize(slot.Type, 8)
		state.bytes.setRange(slot.Offset, width, true)
		state.booleanBytes.setRange(slot.Offset, width, slot.Type == I1)
	}
	// This is the existing architectural GP bank, not a native-MMX grant.
	for _, reg := range x86NativeMMXGPRegisters {
		if reg == SP || reg == BP {
			continue
		}
		delete(state.known, reg)
		delete(state.pointers, reg)
		delete(state.opaque, reg)
		delete(state.booleans, reg)
		delete(state.constants, reg)
		delete(state.ranges, reg)
	}
	for reg := range state.vectors {
		delete(state.vectors, reg)
	}
	for reg := range state.masks {
		delete(state.masks, reg)
	}
	state.flags, state.comparison = 0, x86FixedLocalComparison{}
	return nil
}
