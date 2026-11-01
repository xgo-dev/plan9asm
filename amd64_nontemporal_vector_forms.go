package plan9asm

import (
	"fmt"
	"strings"
)

type x86NonTemporalVectorSpec struct {
	native string
	vector bool
	load   bool
}

// Complete Go yxr_ml/ylddqu and _yvmovntdq/_yvmovntdqa rows. MOVNTDQ
// is Go's source alias of MOVNTO, not a distinct physical MMX operation.
var x86NonTemporalVectorSpecs = map[Op]x86NonTemporalVectorSpec{
	"MOVNTO":    {"movntdq", false, false},
	"MOVNTDQ":   {"movntdq", false, false},
	"MOVNTPD":   {"movntpd", false, false},
	"MOVNTPS":   {"movntps", false, false},
	"MOVNTDQA":  {"movntdqa", false, true},
	"VMOVNTDQ":  {"vmovntdq", true, false},
	"VMOVNTPD":  {"vmovntpd", true, false},
	"VMOVNTPS":  {"vmovntps", true, false},
	"VMOVNTDQA": {"vmovntdqa", true, true},
}

type x86NonTemporalVectorForm struct {
	spec x86NonTemporalVectorSpec
	move amd64PackedVectorMoveForm
	trap bool
}

func x86NonTemporalVectorProperties(op Op, ins Instr, arch string) (x86NonTemporalVectorForm, bool, error) {
	name, _, dotted := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := x86NonTemporalVectorSpecs[Op(name)]
	form := x86NonTemporalVectorForm{spec: spec, move: amd64PackedVectorMoveForm{
		spec:   amd64PackedVectorMoveSpec{elementBits: 8, encoding: amd64PackedMoveVEXOrEVEX, aligned: true},
		memory: 1, destination: 1, mask: -1, memoryWrite: !spec.load,
	}}
	if !known {
		return form, false, nil
	}
	fail := func() (x86NonTemporalVectorForm, bool, error) {
		return form, true, fmt.Errorf("%s %s outside complete Go non-temporal vector grammar: %q", arch, op, ins.Raw)
	}
	if arch != "amd64" && arch != "386" || dotted || len(ins.Args) != 2 ||
		ins.Op != "" && !strings.EqualFold(string(ins.Op), name) {
		return fail()
	}
	vector, memory := ins.Args[0], ins.Args[1]
	if spec.load {
		vector, memory, form.move.memory = ins.Args[1], ins.Args[0], 0
	}
	form.move.byteWidth = amd64VectorByteWidth(vector.Reg)
	index, _ := amd64VectorRegisterIndex(vector.Reg, form.move.byteWidth)
	if vector.Kind != OpReg || !amd64GoPackedVectorMoveRegister(vector, form.move.byteWidth, arch) ||
		!spec.vector && (form.move.byteWidth != 16 || !amd64VEXVectorRegister(vector, 16) ||
			arch == "386" && index >= 8) {
		return fail()
	}
	if !spec.vector && !spec.load && memory.Kind == OpReg && isX86YrlRegisterForArch(memory.Reg, arch) {
		form.trap, form.move.memory = true, -1
		return form, true, nil // Go's Yml accepts ModRM.mod=3; the ISA raises #UD before inputs.
	}
	if !isAMD64MemoryOperand(memory) || memory.Kind == OpSym && strings.HasPrefix(memory.Sym, "$") {
		return fail()
	}
	if memory.Kind == OpMem {
		if err := x86SymbolIndexedMemoryError(memory.Mem, arch); err != nil {
			return form, true, err
		}
		if memory.Mem.OffRaw != "" || memory.Mem.IndexExt != "" {
			return fail()
		}
		if arch == "386" && strings.HasSuffix(memory.Mem.Sym, "(SB)") {
			memory.Mem.Base = "" // Go ignores Reg on this symbol role, not Index.
		}
	}
	if !x86PackedShiftMemoryValid(memory, arch) {
		return fail()
	}
	return form, true, nil
}

// Only the paired native instruction supplies a continuation. Standalone
// queries cannot replace native alignment, non-temporal ordering or backing
// with initialized logical FP bytes or an incoming pointer declaration.
func x86ResultNonTemporalVectorStep(ins Instr, state *x86ResultState, owned []bool,
	resultOffset int64, arch string, native bool) (bool, bool) {
	form, known, err := x86NonTemporalVectorProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	if form.trap {
		return true, true // Control-flow checks separately recognize this exact terminal #UD.
	}
	memory := ins.Args[form.move.memory]
	if !native || !x86ResultNamedPredicateInstruction(ins) ||
		x86Mode32VectorRegisterContext(ins, arch) != nil || memory.Kind != OpMem || memory.Mem.Sym != "" {
		return false, true
	}
	width := int64(form.move.byteWidth)
	if !form.spec.load {
		index, valid := amd64VectorRegisterIndex(ins.Args[0].Reg, form.move.byteWidth)
		mask := x86CallerVectorByteMask(width)
		return x86ResultIncomingPointerAddressIdentity(memory, state, arch) &&
			valid && state.vectorBytes(index)&mask == mask, true
	}
	if !x86ResultIncomingPointerReadAddressIdentity(memory, state, arch) {
		return false, true
	}
	index, valid := amd64VectorRegisterIndex(ins.Args[1].Reg, form.move.byteWidth)
	if !valid {
		return false, true
	}
	state.writeVector(index, form.move.byteWidth, x86CallerVectorByteMask(width), !form.spec.vector)
	return true, true
}
