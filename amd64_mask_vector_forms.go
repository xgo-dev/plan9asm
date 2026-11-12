package plan9asm

import (
	"fmt"
	"strings"
)

type x86MaskVectorSpec struct {
	laneBits     int
	maskToVector bool
}

// Go's complete _yvpbroadcastmb2q/_yvpmovb2m rows are EVEX register-only
// moves. K0 is data, not the absence of writemasking; no suffix is permitted.
var x86MaskVectorSpecs = map[Op]x86MaskVectorSpec{
	"VPMOVM2B": {8, true}, "VPMOVM2W": {16, true},
	"VPMOVM2D": {32, true}, "VPMOVM2Q": {64, true},
	"VPMOVB2M": {8, false}, "VPMOVW2M": {16, false},
	"VPMOVD2M": {32, false}, "VPMOVQ2M": {64, false},
}

type x86MaskVectorForm struct {
	spec         x86MaskVectorSpec
	vector, mask int
	byteWidth    int
}

// Syntax and physical register roles are shared by lowering and caller effects.
// The form supplies no mask value, initialized vector bytes or entry contract.
func x86MaskVectorProperties(ins Instr, arch string) (x86MaskVectorForm, bool, error) {
	base, _, dotted := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	spec, recognized := x86MaskVectorSpecs[Op(base)]
	if !recognized {
		return x86MaskVectorForm{}, false, nil
	}
	form := x86MaskVectorForm{spec: spec, vector: 0, mask: 1}
	if spec.maskToVector {
		form.vector, form.mask = 1, 0
	}
	fail := func() (x86MaskVectorForm, bool, error) {
		return form, true, fmt.Errorf("%s %s requires register-only K0-K7 and X/Y/Z operands without suffix: %q", arch, base, ins.Raw)
	}
	if arch == "" {
		arch = "amd64"
	}
	if arch != "amd64" && arch != "386" || dotted || len(ins.Args) != 2 || !amd64IsKOperand(ins.Args[form.mask]) {
		return fail()
	}
	vector := ins.Args[form.vector]
	form.byteWidth = amd64VectorByteWidth(vector.Reg)
	if !amd64GoPackedVectorMoveRegister(vector, form.byteWidth, arch) {
		return fail()
	}
	return form, true, x86Mode32VectorRegisterContext(ins, arch)
}

func x86CallerMaskVectorStep(ins *Instr, form x86MaskVectorForm, state *x86SourceStackState) bool {
	mask := ins.Args[form.mask].Reg
	vector := x86CallerVectorRoot(ins.Args[form.vector].Reg)
	if form.spec.maskToVector {
		if !state.masks[mask] {
			return false
		}
		// EVEX writes the selected vector and clears every wider alias byte.
		state.vectors[vector] = ^uint64(0)
		return true
	}
	required := form.signByteInputs()
	if state.vectors[vector]&required != required {
		return false // An entry/partially initialized vector is not numeric data.
	}
	// Sign bits fill the low mask lanes and all remaining K bits become zero.
	state.masks[mask] = true
	return true
}

// Only each lane's sign bit contributes to a vector-to-mask result. At byte
// granularity its containing byte is sufficient; unrelated bytes stay unknown.
func (form x86MaskVectorForm) signByteInputs() uint64 {
	lane := form.spec.laneBits / 8
	var required uint64
	for offset := lane - 1; offset < form.byteWidth; offset += lane {
		required |= uint64(1) << uint(offset)
	}
	return required
}

func x86MaskVectorResultStep(ins Instr, state *x86ResultState, arch string) (bool, bool) {
	form, known, err := x86MaskVectorProperties(ins, arch)
	if !known || err != nil || !x86ResultNamedPredicateInstruction(ins) {
		return false, known
	}
	mask, _ := amd64ParseKReg(ins.Args[form.mask].Reg)
	vector, _ := amd64VectorRegisterIndex(ins.Args[form.vector].Reg, form.byteWidth)
	if form.spec.maskToVector {
		if !state.masks[mask] {
			return false, true
		}
		state.writeVector(vector, form.byteWidth, x86CallerVectorByteMask(int64(form.byteWidth)), false)
		return true, true // EVEX clears wider aliases; this is not writemasking.
	}
	required := form.signByteInputs()
	if state.vectorBytes(vector)&required != required {
		return false, true
	}
	state.masks[mask] = true // Every inactive high K bit is architecturally zero.
	return true, true
}
