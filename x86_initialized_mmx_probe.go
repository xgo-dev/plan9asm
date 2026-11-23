package plan9asm

import "fmt"

// InitializedMMXProbe describes a synthetic, object-only native region.
// The original instruction belongs between Before and After.
type InitializedMMXProbe struct {
	Before, After         []Instr
	MemoryPointerArgument bool
	FrameSize             int64
}

// BuildInitializedMMXProbe defines the physical registers read by one named
// MMX form. Native addresses use a declared pointer or a bounded 386 local
// frame. The resulting region always closes the x87 tag state with EMMS.
func BuildInitializedMMXProbe(goarch string, ins Instr) (InitializedMMXProbe, bool) {
	if (goarch != "386" && goarch != "amd64") || ins.Op == "EMMS" ||
		!x86ResultNamedPredicateInstruction(ins) {
		return InitializedMMXProbe{}, false
	}
	site, known, err := x86NativeMMXInstruction(ins, goarch)
	if !known || err != nil {
		return InitializedMMXProbe{}, false
	}

	operands := site.frameOperands()
	if site.maskStore != nil {
		for _, operand := range ins.Args {
			operands = append(operands, x86TypedByteOperand{operand: operand, width: 8, read: true})
		}
		operands = append(operands, x86TypedByteOperand{
			operand: Operand{Kind: OpMem, Mem: MemRef{Base: DI}}, width: 8, write: true,
		})
	}

	probe := InitializedMMXProbe{After: []Instr{{Op: "EMMS", Raw: "EMMS"}}}
	var mmx [8]bool
	var xmm [16]bool
	var base Reg
	var gp []Reg
	gpInputs := make(map[Reg]bool)
	addGP := func(operand Operand) bool {
		root, ok := initializedX86GPRegister(goarch, operand)
		if ok && !gpInputs[root] {
			gpInputs[root] = true
			gp = append(gp, root)
		}
		return ok
	}
	for _, effect := range operands {
		operand := effect.operand
		switch operand.Kind {
		case OpImm:
			// The native form parser validated its immediate.
		case OpReg:
			if !effect.read {
				continue
			}
			if i, ok := amd64ParseMReg(operand.Reg); ok {
				mmx[i] = true
			} else if i, ok := amd64ParseXReg(operand.Reg); ok && i < len(xmm) {
				xmm[i] = true
			} else if !addGP(operand) {
				return InitializedMMXProbe{}, false
			}
		case OpMem:
			memory := operand.Mem
			if memory.Base == SP {
				if goarch != "386" || memory != (MemRef{Base: SP, Off: memory.Off}) ||
					memory.Off < 0 || effect.width <= 0 || memory.Off > 4096-effect.width {
					return InitializedMMXProbe{}, false
				}
				probe.FrameSize = (memory.Off + effect.width + 3) &^ 3
				if effect.read {
					for offset := memory.Off; offset < memory.Off+effect.width; offset += 4 {
						cell := Operand{Kind: OpMem, Mem: MemRef{Base: SP, Off: offset}}
						probe.Before = append(probe.Before, x86ProbeInstruction("MOVL", Operand{Kind: OpImm, Imm: 129}, cell))
					}
				}
				continue
			}
			var valid bool
			base, valid = initializedX86GPRegister(goarch, Operand{Kind: OpReg, Reg: memory.Base})
			if !valid || !x86OrdinaryNativeMemoryOperand(operand, goarch) || memory.Sym != "" {
				return InitializedMMXProbe{}, false
			}
			if memory.Index != "" && !addGP(Operand{Kind: OpReg, Reg: memory.Index}) {
				return InitializedMMXProbe{}, false
			}
		default:
			return InitializedMMXProbe{}, false
		}
	}
	if gpInputs[base] {
		return InitializedMMXProbe{}, false
	}
	if base != "" {
		probe.MemoryPointerArgument = true
		probe.Before = append(probe.Before, initializedProbeMemoryBinding(goarch, base))
	}
	for _, register := range gp {
		probe.Before = append(probe.Before, x86ProbeInstruction("MOVL", Operand{Kind: OpImm, Imm: 1},
			Operand{Kind: OpReg, Reg: register}))
	}
	for i, used := range xmm {
		if used {
			x := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", i))}
			probe.Before = append(probe.Before, x86ProbeInstruction("XORPS", x, x))
		}
	}

	// Put every GP/XMM definition before the first physical MMX instruction.
	// One scratch GP supplies all MMX inputs without splitting the region.
	var scratch Operand
	for i, used := range mmx {
		if !used {
			continue
		}
		if scratch.Reg == "" {
			for _, candidate := range [...]Reg{AX, CX, DX, BX} {
				if candidate != base && !gpInputs[candidate] {
					scratch = Operand{Kind: OpReg, Reg: candidate}
					break
				}
			}
			if scratch.Reg == "" {
				return InitializedMMXProbe{}, false
			}
			probe.Before = append(probe.Before, x86ProbeInstruction("MOVL", Operand{Kind: OpImm, Imm: 129}, scratch))
		}
		register := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("M%d", i))}
		probe.Before = append(probe.Before, x86ProbeInstruction("MOVL", scratch, register))
	}
	return probe, true
}
