package plan9asm

import (
	"fmt"
	"strings"
)

type x86ScalarReciprocalSpec struct {
	opcode byte
	vector bool
}

// Go's yxm and _yvrcpss tables contain exactly these scalar estimate forms.
// RCP14/28, packed estimates, EVEX and masks have separate source grammars.
var x86ScalarReciprocalSpecs = map[Op]x86ScalarReciprocalSpec{
	"RCPSS": {0x53, false}, "RSQRTSS": {0x52, false},
	"VRCPSS": {0x53, true}, "VRSQRTSS": {0x52, true},
}

type x86ScalarReciprocalForm struct {
	spec              x86ScalarReciprocalSpec
	base, destination int
}

func x86ScalarReciprocalProperties(op Op, ins Instr, arch string) (x86ScalarReciprocalForm, bool, error) {
	name, _, dotted := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := x86ScalarReciprocalSpecs[Op(name)]
	form := x86ScalarReciprocalForm{spec: spec, base: 1, destination: len(ins.Args) - 1}
	if !known {
		return form, false, nil
	}
	if arch == "" {
		arch = "amd64"
	}
	fail := func() (x86ScalarReciprocalForm, bool, error) {
		return form, true, fmt.Errorf("%s %s outside complete Go scalar reciprocal grammar: %q", arch, op, ins.Raw)
	}
	if arch != "amd64" && arch != "386" || dotted ||
		ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return fail()
	}
	want := 2
	if spec.vector {
		want = 3
	}
	if len(ins.Args) != want {
		return fail()
	}
	vector := func(operand Operand) bool {
		index, valid := amd64ParseXReg(operand.Reg)
		limit := 16
		if !spec.vector && arch == "386" {
			limit = 8
		}
		return operand.Kind == OpReg && valid && index < limit
	}
	if !vector(ins.Args[form.base]) || !vector(ins.Args[form.destination]) {
		return fail()
	}
	source := ins.Args[0]
	if !vector(source) {
		if spec.vector && x86Mode32UnboundVEXMemorySource(source, arch) {
			return form, true, fmt.Errorf("%w: 386 %s extended source base has no physical address binding", ErrProbeNeedsContext, op)
		}
		if !isAMD64MemoryOperand(source) || !x86PackedShiftMemoryValid(source, arch) {
			return fail()
		}
		if err := x86NamedMultiplyMemoryError(source, arch); err != nil {
			return form, true, err
		}
	}
	if err := x86Mode32VectorRegisterContext(ins, arch); err != nil {
		return form, true, err
	}
	return form, true, nil
}

// Go's non-SIB asmandsz branch accepts an extended base spelling before
// physical mode32 binding. asmidx rejects extended base/index SIB forms.
// This recognizes frontend syntax only; it supplies no address permission.
func x86Mode32UnboundVEXMemorySource(source Operand, arch string) bool {
	if arch != "386" || source.Kind != OpMem || source.Mem.Index != "" || source.Mem.Base == "R12" ||
		x86MemoryRegistersValidForArch(source.Mem, arch) {
		return false
	}
	frontend := source
	if frontend.Mem.Off == int64(uint32(frontend.Mem.Off)) {
		// Normalize only this grammar check, never the original operand.
		frontend.Mem.Off = int64(int32(frontend.Mem.Off))
	}
	return x86PackedShiftMemoryValid(frontend, "amd64") && x86NamedMultiplyMemoryError(frontend, "amd64") == nil
}

func x86TypedScalarReciprocalByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	form, known, err := x86ScalarReciprocalProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	effect := x86TypedByteEffect{requiresResultProof: true}
	for index, operand := range ins.Args {
		width := int64(16)
		if index == 0 {
			width = 4
		}
		effect.operands = append(effect.operands, x86TypedByteOperand{
			index: index, operand: operand, width: width,
			read: index == 0 || index == form.base, write: index == form.destination,
		})
	}
	return effect, true, nil
}
