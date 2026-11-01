package plan9asm

import (
	"reflect"
	"strings"
)

// This is an ordinary source's data-register view, not physical BP entry or
// frame backing. Go's nonempty NOSPLIT frame preserves its caller BP. The
// complete named source must independently exclude every observation of that
// frame, native entry, call and escaping frame address. Reaching input facts
// are still proved by the ordinary whole-source CFG below.
func x86DataBPSourceScope(fn Func, sig FuncSig, arch string) bool {
	if arch != "amd64" || fn.FrameSize <= 0 || fn.FrameSize > 4096 || fn.FrameSize%8 != 0 ||
		strings.Contains(fn.Sym, "<") || len(sig.ArgRegs) != 0 || len(fn.X86RawText) != 0 ||
		fn.x86SourceStack != nil || fn.x86FixedLocal != nil || fn.x86DirectTailRoot != nil ||
		fn.x86ContinuationFlow != nil || fn.x86BoolCalls != nil || sig.x86CallerRegions != nil ||
		len(fn.x86ContinuationAddresses) != 0 || len(fn.x86IndirectLabels) != 0 || fn.x86BoolReadonlyInputs ||
		len(fn.Instrs) == 0 || len(fn.Instrs) > 4096 || fn.Instrs[0].Op != OpTEXT {
		return false
	}
	_, rest := splitOpcode(fn.Instrs[0].Raw)
	parts := strings.Split(rest, ",")
	if len(parts) != 3 {
		return false
	}
	frame, args, err := parseTEXTFrame(parts)
	if err != nil || frame != fn.FrameSize || args != fn.ArgSize {
		return false
	}
	expression := globlFlagName.ReplaceAllStringFunc(parts[1], func(name string) string {
		if value, known := goTextFlagValues[name]; known {
			return value
		}
		return name
	})
	flags, known := parseImmExpr(strings.TrimSpace(expression))
	if !known || flags != 4 { // NOSPLIT, never NOFRAME, NEEDCTXT or another prologue role.
		return false
	}
	found := false
	var source strings.Builder
	for _, ins := range fn.Instrs {
		if ins.Raw == "" || len(ins.Raw) > (1<<20)-source.Len()-1 {
			return false
		}
		source.WriteString(ins.Raw)
		source.WriteByte('\n')
		if !x86ResultNamedPredicateInstruction(ins) {
			return false
		}
		switch ins.Op {
		case OpCALL, "BYTE", "WORD", "LONG", "QUAD":
			return false
		}
		if _, stack, _ := x86StackWidthProperties(ins, arch); stack {
			return false // Private PUSH/FLAGS storage keeps its own source owner.
		}
		if x86LEAWidth(ins.Op, arch) != 0 && len(ins.Args) != 0 && ins.Args[0].Kind == OpFP {
			return false // LEA's Ym operand takes the FP address without OpFPAddr.
		}
		for _, operand := range ins.Args {
			if operand.Kind == OpFPAddr || operand.Kind == OpSym {
				return false
			}
			if operand.Kind == OpReg {
				root, gp := x86CallerGP(operand.Reg)
				if gp && root == SP {
					return false
				}
				found = found || operand.Reg == BP
			}
			if operand.Kind == OpMem {
				memory := operand.Mem
				if memory.Base == SP || memory.Index == SP || memory.Sym != "" || memory.Segment != "" {
					return false
				}
				found = found || memory.Base == BP || memory.Index == BP
			}
		}
	}
	if !found {
		return false
	}
	// One bounded source replay, not one parse per instruction. Mutable fields
	// cannot reinterpret a physical-frame use or a different source spelling.
	parsed, err := Parse(ArchAMD64, source.String())
	return err == nil && len(parsed.Funcs) == 1 && len(parsed.UnlinkedPrelude) == 0 &&
		len(parsed.Data) == 0 && len(parsed.Globl) == 0 && parsed.Funcs[0].Sym == fn.Sym &&
		parsed.Funcs[0].FrameSize == fn.FrameSize && parsed.Funcs[0].ArgSize == fn.ArgSize &&
		reflect.DeepEqual(parsed.Funcs[0].Instrs, fn.Instrs)
}

// Project only the grammar query, never the original source or emitted address.
// AX is an ordinary encoding-equivalent base; the complete displacement/index
// checks remain with the existing scalar move descriptor. BP as an index is
// not a numerical input and cannot borrow this opaque-pointer holder role.
func x86DataBPScalarMove(ins Instr) (x86ScalarNativeLoadForm, x86ScalarNativeStoreForm, bool, bool) {
	if len(ins.Args) != 2 {
		return x86ScalarNativeLoadForm{}, x86ScalarNativeStoreForm{}, false, false
	}
	projected := ins
	projected.Args = append([]Operand(nil), ins.Args...)
	for index, operand := range ins.Args {
		if operand.Kind != OpMem || operand.Mem.Base != BP || operand.Mem.Index == BP {
			continue
		}
		projected.Args[index].Mem.Base = AX
		if index == 0 {
			form, known, err := x86ScalarNativeLoadProperties(ins.Op, projected, "amd64")
			if known && err == nil && !x86LogicalSourceFrameRegister(form.destination, "amd64") {
				form.source = operand
				return form, x86ScalarNativeStoreForm{}, true, false
			}
		} else {
			form, known, err := x86ScalarNativeStoreProperties(ins.Op, projected, "amd64")
			if known && err == nil && (form.source.Kind != OpReg || !x86LogicalSourceFrameRegister(form.source.Reg, "amd64")) {
				form.destination = operand
				return x86ScalarNativeLoadForm{}, form, false, true
			}
		}
	}
	return x86ScalarNativeLoadForm{}, x86ScalarNativeStoreForm{}, false, false
}

func x86ResultDataBPStep(ins Instr, state *x86ResultState, owned []bool, resultOffset int64) (bool, bool) {
	if !x86ResultNamedPredicateInstruction(ins) || len(ins.Args) != 2 {
		return false, false
	}
	local := x86SourceMoveInstruction(ins, "amd64")
	first, last := ins.Args[0], ins.Args[1]
	if local.Op == "MOVQ" && (first.Kind == OpReg && first.Reg == BP || last.Kind == OpReg && last.Reg == BP) {
		pointer := false
		if first.Kind == OpFP {
			pointer = state.pointerFP[first.FPOffset]
		} else if first.Kind == OpReg && first.Reg == BP {
			pointer = state.shapeOnly || state.pointerGP[5]
		} else if first.Kind == OpReg {
			if index, _, valid := x86ResultGP(first.Reg, 8, "amd64"); valid {
				pointer = state.shapeOnly || state.pointerGP[index]
			}
		}
		index, _, valid := x86ResultGP(last.Reg, 8, "amd64")
		if last.Kind == OpReg && last.Reg == BP {
			index, valid = 5, true
		}
		if last.Kind != OpReg || !valid || !pointer {
			return false, true
		}
		state.pointerGP[index], state.gp[index], state.canonicalGP[index] = true, 0, 0
		state.callerAddressGP[index], state.callerAddressOrigin[index] = false, 0
		state.resultAddressGP[index] = x86ResultSlotAddress{}
		return true, true // No pointer bits become NUM or a caller/frame address.
	}
	load, store, read, write := x86DataBPScalarMove(ins)
	if !read && !write {
		return false, false
	}
	memory := load.source
	if write {
		memory = store.destination
	}
	if !state.shapeOnly && !state.pointerGP[5] {
		return false, true
	}
	if memory.Mem.Index != "" && !x86ResultRead(Operand{Kind: OpReg, Reg: memory.Mem.Index}, 8, state, owned, "amd64") {
		return false, true
	}
	if write {
		return x86ResultRead(store.source, store.bytes, state, owned, "amd64"), true
	}
	return x86ResultStore(Operand{Kind: OpReg, Reg: load.destination}, load.bytes, state, owned, resultOffset, "amd64"), true
}

func (c *amd64Ctx) lowerDataBPScalarMove(ins Instr) (bool, error) {
	if !c.dataBPSource {
		return false, nil
	}
	load, store, read, write := x86DataBPScalarMove(ins)
	if !read && !write {
		return false, nil
	}
	if err := c.scalarFPResultInitialized(); err != nil {
		return true, err
	}
	if read {
		return true, c.lowerScalarNativeLoad(load, ins)
	}
	return true, c.lowerScalarNativeStore(store, ins)
}
