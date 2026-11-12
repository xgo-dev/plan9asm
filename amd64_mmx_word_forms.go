package plan9asm

import (
	"fmt"
	"strings"
)

// These are source-selected bank/width facts, not initialized register,
// native-memory, x87 state or entry permissions. In particular Go's ordered
// ymovq Ymm/Ymr row reads a GP for the spelling MOVQ M0,M1.
type x86MMXWordForm struct {
	source, destination Operand
	bytes               int64
	sourceM, targetM    bool
	sourceX, targetX    bool
	gpSpelling          bool
	nonTemporal         bool
}

func x86MMXWordProperties(ins Instr, arch string) (x86MMXWordForm, bool, error) {
	if !x86ResultNamedPredicateInstruction(ins) {
		return x86MMXWordForm{}, false, nil // Raw bytes have their own physical-bank contract.
	}
	name, _, dotted := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	streaming := name == "MOVNTQ"
	if name != "MOVL" && name != "MOVQ" && name != "MOVD" && name != "MOVDQ2Q" && name != "MOVQOZX" && !streaming {
		return x86MMXWordForm{}, false, nil
	}
	mmx := false
	for _, operand := range ins.Args {
		mmx = mmx || isAMD64MOVDMRegister(operand)
	}
	if !mmx && !streaming {
		return x86MMXWordForm{}, false, nil
	}
	fail := func() (x86MMXWordForm, bool, error) {
		return x86MMXWordForm{}, true, fmt.Errorf("%s %s outside complete Go MMX word rows: %q", arch, ins.Op, ins.Raw)
	}
	if dotted || len(ins.Args) != 2 || arch != "amd64" && arch != "386" {
		return fail()
	}
	form := x86MMXWordForm{source: ins.Args[0], destination: ins.Args[1], bytes: 8}
	form.sourceM, form.targetM = isAMD64MOVDMRegister(form.source), isAMD64MOVDMRegister(form.destination)
	form.sourceX, form.targetX = isAMD64MOVDXRegister(form.source), isAMD64MOVDXRegister(form.destination)
	vector := func(operand Operand) bool {
		index, valid := amd64ParseXReg(operand.Reg)
		return operand.Kind == OpReg && valid && index < 16 && (arch != "386" || index < 8)
	}
	memory := func(operand Operand) bool {
		return isAMD64MemoryOperand(operand) && x86PackedShiftMemoryValid(operand, arch)
	}
	gp := func(operand Operand) bool {
		return operand.Kind == OpReg && isX86YrlRegisterForArch(operand.Reg, arch)
	}
	if streaming {
		if !form.sourceM || !memory(form.destination) {
			return fail()
		}
		form.nonTemporal = true
		return form, true, nil // ymr_ml: one MMX source and an m64 destination.
	}
	if name == "MOVQOZX" {
		if !form.sourceM || !vector(form.destination) {
			return fail()
		}
		return form, true, nil // ymrxr: MMX -> X low64, with the X high64 cleared.
	}
	if name == "MOVL" {
		form.bytes = 4
	}
	if form.targetM {
		if form.sourceM {
			if form.bytes != 8 || arch != "amd64" {
				return fail()
			}
			index, _ := amd64ParseMReg(form.source.Reg)
			form.source.Reg = amd64MMXEncodingGP(index)
			form.sourceM, form.gpSpelling = false, true
		} else if form.sourceX {
			if form.bytes != 8 || !vector(form.source) {
				return fail()
			}
		} else if gp(form.source) {
			if form.bytes == 8 && arch == "386" {
				return fail()
			}
		} else if !memory(form.source) {
			return fail()
		}
		return form, true, nil
	}
	if form.sourceM && (memory(form.destination) || gp(form.destination) && (form.bytes == 4 || arch == "amd64")) {
		return form, true, nil
	}
	return fail()
}
