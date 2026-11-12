package plan9asm

import (
	"fmt"
	"strings"
)

// This is source grammar, not a native-register, thread or storage permission.
// Go's complete MOVQ source aliases include the mode32 MMX/XMM memory rows.
// Width describes the physical memory transfer, never a virtual GP slot.
type x86TLSMoveForm struct {
	op      Op
	bits    int
	memory  int // -1 is the Ytls-to-Yrl pseudo-register row
	write   bool
	gp      bool
	mmx     bool
	xmm     bool
	segment bool
}

func x86TLSMoveProperties(ins Instr, arch string) (x86TLSMoveForm, bool, error) {
	form := x86TLSMoveForm{memory: -1}
	op := strings.ToUpper(string(ins.Op))
	base := strings.SplitN(op, ".", 2)[0]
	_, alias := x86GoMOVQSourceAliases[Op(base)]
	if base != "MOVB" && base != "MOVW" && base != "MOVL" && base != "MOVQ" && !alias {
		return form, false, nil
	}
	present := false
	for _, operand := range ins.Args {
		present = present || operand.Kind == OpReg && operand.Reg == TLS ||
			operand.Kind == OpMem && (operand.Mem.Base == TLS || operand.Mem.Index == TLS)
	}
	if !present {
		return form, false, nil
	}
	bad := func(reason string) (x86TLSMoveForm, bool, error) {
		return x86TLSMoveForm{}, true, fmt.Errorf("%s %s %s: %q", arch, op, reason, ins.Raw)
	}
	if arch != "386" && arch != "amd64" || op != base || len(ins.Args) != 2 {
		return bad("has an invalid mode, suffix or operand count")
	}
	if alias {
		base = string(x86GoMOVQSourceAliases[Op(base)])
	}
	form.op = Op(base)
	form.bits = map[string]int{"MOVB": 8, "MOVW": 16, "MOVL": 32, "MOVQ": 64}[base]
	source, destination := ins.Args[0], ins.Args[1]
	if source.Kind == OpReg && source.Reg == TLS {
		// progedit checks the complete AX..R15 source range before mode32
		// encoding. Direct profiles NOP even R8..R15 and the other width.
		// Accepting this source role grants no physical mode32 register bank.
		if base != "MOVL" && base != "MOVQ" || destination.Kind != OpReg || !isAMD64YrlRegister(destination.Reg) {
			return bad("requires the original Ytls-to-Yrl row")
		}
		form.gp = true
		return form, true, nil
	}
	for index, operand := range ins.Args {
		if operand.Kind == OpMem && (operand.Mem.Base == TLS || operand.Mem.Index == TLS) {
			if form.memory >= 0 || !x86SourceTLSMemoryRole(operand, arch) {
				return bad("requires one encodable TLS memory role")
			}
			form.memory = index
		}
	}
	if form.memory < 0 {
		return bad("has no row with a TLS destination register")
	}
	form.write = form.memory == 1
	other := ins.Args[1-form.memory]
	valid := false
	switch other.Kind {
	case OpImm:
		valid = form.write && !other.ImmIsFloat && other.ImmRaw == "" &&
			(base != "MOVQ" || arch == "amd64") &&
			(arch == "386" || other.Imm >= -1<<31 && other.Imm <= 1<<32-1)
	case OpReg:
		form.gp = isX86YrlRegisterForArch(other.Reg, arch) && (base != "MOVQ" || arch == "amd64")
		if base == "MOVB" {
			form.gp = isGoYmbRegisterForArch(other.Reg, arch)
		}
		if base == "MOVW" {
			switch other.Reg {
			case CS, SS, DS, ES, FS, GS:
				form.segment = true
			}
		}
		if base == "MOVL" || base == "MOVQ" {
			_, form.mmx = amd64ParseMReg(other.Reg)
			index, xmm := amd64ParseXReg(other.Reg)
			form.xmm = xmm && index < 16 && (arch == "amd64" || index < 8)
		}
		valid = form.gp || form.mmx || form.xmm || form.segment
	case OpSym:
		if form.write && arch == "386" && base != "MOVQ" && strings.HasPrefix(other.Sym, "$") {
			_, _, valid = x86ScalarCompareSBAddress(Operand{Kind: OpSym, Sym: strings.TrimPrefix(other.Sym, "$")}, arch)
		}
	}
	if !valid {
		return bad("operands do not match a complete Go move row")
	}
	return form, true, nil
}
