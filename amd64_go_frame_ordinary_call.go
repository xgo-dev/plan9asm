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
	foreign := make(map[string]map[string]bool)
	for _, fn := range file.Funcs {
		for _, ins := range fn.Instrs {
			if ins.Op != OpCALL || len(ins.Args) != 1 || ins.Args[0].Kind != OpSym {
				continue
			}
			name, offset, valid := parseSBRef(ins.Args[0].Sym)
			if valid && offset == 0 && leaves[name] {
				continue
			}
			path, local := goReadOnlyImportedName(goAMD64FrameCallName(pkg.Path, name))
			if !valid || offset != 0 || path == "" {
				return nil, goAMD64FrameContext("ordinary CALL needs an exact selected Go target")
			}
			if path == pkg.Path {
				entries[local] = true
			} else {
				if foreign[path] == nil {
					foreign[path] = make(map[string]bool)
				}
				foreign[path][local] = true
			}
		}
	}
	if len(entries)+len(foreign) == 0 {
		return nil, nil
	}
	declarations := make(map[string]goAMD64FrameDeclaration)
	if len(entries) != 0 {
		declarations, err = source.typedSourceDeclarations(pkg, false, "amd64", true, entries, false, true)
		if err != nil {
			return nil, err
		}
	}
	for path, names := range foreign {
		selected, err := source.ordinarySDKCallDeclarations(path, names)
		if err != nil {
			return nil, err
		}
		for name, declaration := range selected {
			declarations[name] = declaration
		}
	}
	for _, declaration := range declarations {
		if !goAMD64FrameScalarCall(declaration.signature) {
			return nil, goAMD64FrameContext("ordinary CALL has a non-scalar transport")
		}
	}
	return declarations, nil
}

func goAMD64FrameCallName(path, symbol string) string {
	if strings.HasPrefix(symbol, "·") {
		symbol = path + "." + strings.TrimPrefix(symbol, "·")
	}
	owner, name := goReadOnlyImportedName(symbol)
	if owner == "" {
		return ""
	}
	return owner + "." + name
}

func goAMD64FrameScalarCall(sig FuncSig) bool {
	scalar := func(typ LLVMType) bool {
		return typ == Ptr || typ == I1 || typ == I8 || typ == I16 || typ == I32 || typ == I64
	}
	for _, typ := range sig.Args {
		if !scalar(typ) {
			return false
		}
	}
	if sig.Ret == Void || scalar(sig.Ret) {
		return true
	}
	fields, valid := parseLiteralStructFields(sig.Ret)
	for _, typ := range fields {
		valid = valid && scalar(typ)
	}
	return valid
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
		(declaration.transport == goAMD64FrameNumericTransport || declaration.transport == goAMD64FrameCompositeTransport) &&
		goAMD64FrameScalarCall(sig) && reflect.DeepEqual(sig, declaration.signature)
}

// The existing ABI0 emitter reads outgoing slots and writes only typed result
// slots. Opaque pointer words supply no private-frame or pointee authority.
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
			if width <= 0 || slot.Offset < 0 || slot.Offset > proof.frame-width {
				return goAMD64FrameContext("ordinary CALL slot exceeds its exact outgoing frame")
			}
			initialized := state.bytes.all(slot.Offset, width)
			if slot.Type == Ptr && group == 0 {
				origin := state.opaqueCells[slot.Offset]
				_, private := state.addresses[slot.Offset]
				initialized = width == 8 && !private && (initialized || origin.valid() && !origin.readonly())
			}
			if group == 0 && (!initialized || slot.Type == I1 && !state.booleanBytes.all(slot.Offset, width)) {
				return goAMD64FrameContext("ordinary CALL reads uninitialized or noncanonical outgoing bytes")
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
		state.bytes.setRange(slot.Offset, width, slot.Type != Ptr)
		state.booleanBytes.setRange(slot.Offset, width, slot.Type == I1)
		if slot.Type == Ptr {
			state.opaqueCells[slot.Offset] = fixedLocalOrigin(x86FixedLocalOrigin{})
		}
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
