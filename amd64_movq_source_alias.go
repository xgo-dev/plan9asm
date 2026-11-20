package plan9asm

import (
	"fmt"
	"strings"
)

// These are the complete archX86 frontend registrations for AMOVQ. They are
// source spellings, not physical Intel opcode identities or MMX permissions.
var x86GoMOVQSourceAliases = map[Op]Op{
	"MOVD":    "MOVQ",
	"MOVDQ2Q": "MOVQ",
}

func x86GoMOVQSourceInstruction(ins Instr) Instr {
	if !ins.x86Encoded && ins.x86SourceRaw == nil {
		if canonical, present := x86GoMOVQSourceAliases[ins.Op]; present {
			ins.Op = canonical
		}
	}
	return ins
}

// Go progedit rewrites AMOVQ TYPE_ADDR to ALEAQ before matching ymovq.
// Source aliases must retain that complete source class, not mistake it for
// a memory read or a SIMD immediate. This validates syntax only; actual FP,
// AUTO, symbol and numerical address roles remain separate consumers.
func x86GoMOVQAddressSource(operand Operand, arch string) bool {
	if arch != "386" && operand.Kind == OpFPAddr {
		address := Operand{Kind: OpFP, FPOffset: operand.FPOffset}
		_, err := x86LEAOperandWidth(Instr{Op: "LEAQ", Args: []Operand{address, {Kind: OpReg, Reg: AX}}}, arch)
		return err == nil
	}
	if arch == "386" || operand.Kind != OpSym {
		return false
	}
	source := strings.TrimSpace(operand.Sym)
	if !strings.HasPrefix(source, "$") {
		return false
	}
	source = strings.TrimSpace(strings.TrimPrefix(source, "$"))
	address := Operand{Kind: OpSym, Sym: source}
	if memory, matched, err := x86UnnamedSourceAddressInMode(operand, arch); matched || err != nil {
		if err != nil {
			return false
		}
		address = Operand{Kind: OpMem, Mem: memory}
	} else if memory, matched, err := parseX86SymbolIndexedMemory(source); matched {
		if err != nil {
			return false
		}
		address = Operand{Kind: OpMem, Mem: memory}
	} else if _, offset, valid := parseFP(source); valid {
		address = Operand{Kind: OpFP, FPOffset: offset}
	} else if memory, valid := parseMem(source); valid {
		address = Operand{Kind: OpMem, Mem: memory}
	}
	_, err := x86LEAOperandWidth(Instr{Op: "LEAQ", Args: []Operand{address, {Kind: OpReg, Reg: AX}}}, arch)
	return err == nil
}

// Do not normalize the actual source: caller/raw/frame certificates bind its
// entire original Op and Raw. Consumers canonicalize only local dispatch copies.
func validateX86MoveSourceAliases(file *File, arch string) error {
	if file == nil || file.Arch != ArchAMD64 {
		return nil
	}
	if arch == "" {
		arch = "amd64"
	}
	for _, function := range file.Funcs {
		for _, ins := range function.Instrs {
			if _, _, err := x86ScalarMoveAliasProperties(ins.Op, ins, arch); err != nil {
				return err
			}
			if ins.x86Encoded || ins.x86SourceRaw != nil {
				continue
			}
			base, _, dotted := strings.Cut(string(ins.Op), ".")
			if _, alias := x86GoMOVQSourceAliases[Op(base)]; !alias && base != "MOVQ" {
				continue
			}
			if dotted || len(ins.Args) != 2 || arch != "amd64" && arch != "386" {
				return fmt.Errorf("%s %s has an invalid source mode, suffix or operand count: %q", arch, ins.Op, ins.Raw)
			}
			for _, operand := range ins.Args {
				if operand.Kind == OpImm && operand.ImmIsFloat {
					return fmt.Errorf("%s %s has no original Go FLOAT-immediate row: %q", arch, ins.Op, ins.Raw)
				}
			}
			if arch == "386" {
				// These aliases retain MOVQ's five pre-Pw8 memory/MMX/X rows,
				// never its mode64-only GP, immediate or MMX-register copies.
				_, _, sourceMachine := x86MachineRegisterOperand(ins.Args[0])
				_, _, destinationMachine := x86MachineRegisterOperand(ins.Args[1])
				if !sourceMachine && !destinationMachine {
					context := amd64Ctx{goarch: arch}
					if err := context.validateMOVDAliasForm(ins); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}
