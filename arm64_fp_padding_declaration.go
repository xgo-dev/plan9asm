package plan9asm

import (
	"go/types"
	"reflect"
)

type arm64FPReadDeclaration struct {
	signature  FuncSig
	parameter  FrameSlot
	paddingEnd int64
}

// This first contract is only the final direct scalar parameter's ABI0
// parameter/result alignment gap. Internal aggregate holes, result/tail
// padding, pointers, custom data models and incomplete signatures stay strict.
func arm64FPReadDeclarationForGo(sig FuncSig, decl *types.Signature, sizes, frameSizes types.Sizes) *arm64FPReadDeclaration {
	if decl == nil || decl.Recv() != nil || decl.Variadic() || decl.Params().Len() == 0 ||
		decl.Results().Len() == 0 || len(sig.Frame.Params) == 0 || len(sig.Frame.Results) == 0 {
		return nil
	}
	last := sig.Frame.Params[len(sig.Frame.Params)-1]
	if last.Index != decl.Params().Len()-1 || last.Field != -1 || len(last.Fields) != 0 ||
		(last.Type != I8 && last.Type != I16 && last.Type != I32) {
		return nil
	}
	basic, ok := decl.Params().At(last.Index).Type().Underlying().(*types.Basic)
	if !ok || basic.Info()&types.IsInteger == 0 {
		return nil
	}
	for _, layout := range []types.Sizes{sizes, frameSizes} {
		if layout == nil || layout.Sizeof(types.Typ[types.Int]) != 8 ||
			layout.Sizeof(types.Typ[types.Uintptr]) != 8 || layout.Alignof(types.Typ[types.Int64]) != 8 ||
			!arm64PaddingDeclarationLayoutMatches(layout, decl) {
			return nil
		}
	}
	// Compare the entire actual declaration layout with gc's ARM64 model, not
	// just its word size. A custom Sizes may agree on int yet move an earlier
	// aggregate or change the narrow parameter's alignment.
	gc := types.SizesFor("gc", "arm64")
	args, params, offset, err := goLLVMArgsAndFrameSlotsForTuple(decl.Params(), "arm64", gc, gc, 0, false)
	if err != nil {
		return nil
	}
	results, resultSlots, _, err := goLLVMArgsAndFrameSlotsForTuple(decl.Results(), "arm64", gc, gc, goAlignOff(offset, 8), true)
	if err != nil || !reflect.DeepEqual(args, sig.Args) || !reflect.DeepEqual(params, sig.Frame.Params) ||
		!reflect.DeepEqual(resultSlots, sig.Frame.Results) || goTupleRetType(results) != sig.Ret {
		return nil
	}
	end := last.Offset + frameTypeSize(last.Type, 8)
	boundary := sig.Frame.Results[0].Offset
	if last.Offset < 0 || end <= last.Offset || boundary <= end || boundary != goAlignOff(end, 8) {
		return nil
	}
	snapshot := sig
	snapshot.Args = append([]LLVMType(nil), sig.Args...)
	snapshot.Frame.Params = arm64CopyFPSlots(sig.Frame.Params)
	snapshot.Frame.Results = arm64CopyFPSlots(sig.Frame.Results)
	return &arm64FPReadDeclaration{signature: snapshot, parameter: last, paddingEnd: boundary}
}

func arm64PaddingDeclarationLayoutMatches(layout types.Sizes, declaration *types.Signature) bool {
	gc := types.SizesFor("gc", "arm64")
	seen := make(map[types.Type]bool)
	var check func(types.Type) bool
	check = func(typ types.Type) bool {
		if seen[typ] {
			return true
		}
		if len(seen) >= 4096 || layout.Sizeof(typ) != gc.Sizeof(typ) || layout.Alignof(typ) != gc.Alignof(typ) {
			return false
		}
		seen[typ] = true
		switch underlying := typ.Underlying().(type) {
		case *types.Array:
			return check(underlying.Elem())
		case *types.Struct:
			fields := make([]*types.Var, underlying.NumFields())
			for i := range fields {
				fields[i] = underlying.Field(i)
				if !check(fields[i].Type()) {
					return false
				}
			}
			return reflect.DeepEqual(layout.Offsetsof(fields), gc.Offsetsof(fields))
		}
		return true // Pointee/element contents do not change a pointer/header ABI.
	}
	for _, tuple := range []*types.Tuple{declaration.Params(), declaration.Results()} {
		for i := 0; i < tuple.Len(); i++ {
			if !check(tuple.At(i).Type()) {
				return false
			}
		}
	}
	return true
}

func arm64CopyFPSlots(slots []FrameSlot) []FrameSlot {
	copySlots := append([]FrameSlot(nil), slots...)
	for i := range copySlots {
		copySlots[i].Fields = append([]int(nil), copySlots[i].Fields...)
	}
	return copySlots
}

func (d *arm64FPReadDeclaration) matches(sig FuncSig) bool {
	if d == nil || sig.ARMEntry != nil || sig.ARM64GoRegisterABI != nil ||
		sig.ARM64ClosureABI != nil || len(sig.ArgRegs) != 0 {
		return false
	}
	sig.arm64FPReadDeclaration = nil
	sig.arm64ABI0Declaration, sig.arm64ABI0TailDeclaration = nil, nil
	return reflect.DeepEqual(d.signature, sig)
}
