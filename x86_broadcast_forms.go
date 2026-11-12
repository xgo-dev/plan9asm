package plan9asm

import (
	"fmt"
	"strings"
)

type x86BroadcastKind uint8

const (
	x86BroadcastInteger x86BroadcastKind = iota
	x86BroadcastFloat
	x86BroadcastBlock
	x86BroadcastMask
)

type x86BroadcastForm struct {
	kind                             x86BroadcastKind
	sourceBytes, laneBits, byteWidth int
	destination, mask                int
	zeroing                          bool
	vex                              bool // Family has VEX forms; operand/encoding guards still apply.
}

// Scalar, block and mask-data forms share one Go grammar, not one authority.
// A validated memory shape supplies neither initialized data nor an envelope.
func x86BroadcastProperties(op Op, ins Instr, arch string) (x86BroadcastForm, bool, error) {
	name, suffix, dotted := strings.Cut(strings.ToUpper(string(op)), ".")
	f := x86BroadcastForm{mask: -1, destination: len(ins.Args) - 1}
	allowGP, allowX, vexOnly := false, true, false
	widths := map[int]bool{16: true, 32: true, 64: true}
	switch name {
	case "VPBROADCASTB", "VPBROADCASTW", "VPBROADCASTD", "VPBROADCASTQ":
		f.kind, allowGP = x86BroadcastInteger, true
		f.vex = true
		f.sourceBytes = map[string]int{"VPBROADCASTB": 1, "VPBROADCASTW": 2, "VPBROADCASTD": 4, "VPBROADCASTQ": 8}[name]
		f.laneBits = f.sourceBytes * 8
	case "VBROADCASTSS", "VBROADCASTSD":
		f.kind, f.sourceBytes = x86BroadcastFloat, 4
		f.vex = true
		if name == "VBROADCASTSD" {
			f.sourceBytes, widths = 8, map[int]bool{32: true, 64: true}
		}
		f.laneBits = f.sourceBytes * 8
	default:
		if spec, known := amd64PackedBlockBroadcastSpecs[name]; known {
			f.kind, f.sourceBytes, f.laneBits = x86BroadcastBlock, spec.sourceBytes, spec.laneBits
			allowX, vexOnly, widths = spec.allowXSource, spec.vexMemoryOnly, spec.allowDestinations
			f.vex = vexOnly
		} else if spec, known := amd64MaskBroadcastSpecs[Op(name)]; known {
			f.kind, f.sourceBytes, f.laneBits = x86BroadcastMask, spec.sourceBits/8, spec.laneBits
		} else {
			return f, false, nil
		}
	}
	fail := func() (x86BroadcastForm, bool, error) {
		return f, true, fmt.Errorf("%s %s outside complete Go broadcast grammar: %q", arch, op, ins.Raw)
	}
	if arch != "amd64" && arch != "386" || ins.Op != "" && !strings.EqualFold(string(op), string(ins.Op)) ||
		dotted && suffix != "Z" || len(ins.Args) != 2 && len(ins.Args) != 3 {
		return fail()
	}
	f.zeroing = dotted
	if f.kind == x86BroadcastMask || vexOnly {
		if dotted || len(ins.Args) != 2 {
			return fail()
		}
	}
	if len(ins.Args) == 3 {
		mask, valid := amd64ParseKReg(ins.Args[1].Reg)
		if ins.Args[1].Kind != OpReg || !valid || mask == 0 {
			return fail()
		}
		f.mask = 1
	}
	if f.zeroing && f.mask < 0 {
		return fail()
	}
	dst := ins.Args[f.destination]
	f.byteWidth = amd64VectorByteWidth(dst.Reg)
	if !widths[f.byteWidth] || !amd64GoPackedVectorMoveRegister(dst, f.byteWidth, arch) {
		return fail()
	}
	if vexOnly {
		index, valid := amd64ParseYReg(dst.Reg)
		if !valid || index >= 16 {
			return fail()
		}
	}
	src := ins.Args[0]
	if f.kind == x86BroadcastMask {
		if _, valid := amd64ParseKReg(src.Reg); src.Kind != OpReg || !valid {
			return fail()
		}
	} else if src.Kind == OpReg {
		if index, valid := amd64ParseXReg(src.Reg); allowX && valid && index < 32 {
			// Go selects EVEX for the higher banks. Mode32 still needs a
			// physical binding, checked below rather than guessed from names.
		} else if !allowGP || !isX86YrlRegisterForArch(src.Reg, arch) {
			return fail()
		} else if arch == "386" && f.sourceBytes == 8 {
			// Intel's GP-Q opcode 7C ignores EVEX.W outside 64-bit mode:
			// dword input AND dword lanes. X/memory opcode 59 remains qword.
			f.sourceBytes, f.laneBits = 4, 32
		}
	} else if src.Kind == OpImm && !src.ImmIsFloat && src.ImmRaw == "" &&
		(f.kind == x86BroadcastInteger && ins.x86Encoded || f.kind == x86BroadcastFloat && ins.x86RIPLiteral) {
		// A decoder-bound RIP literal is not a named immediate permission.
	} else if !isAMD64MemoryOperand(src) || !x86PackedShiftMemoryValid(src, arch) {
		return fail()
	}
	return f, true, x86Mode32VectorRegisterContext(ins, arch)
}

// A broadcast reads its exact scalar/block source and defines the complete
// destination width. A low-X source cannot stand in for a wider block input.
func x86ResultBroadcastStep(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	return x86ResultBroadcastStepWithRead(ins, state, owned, arch, false)
}

func x86ResultBroadcastStepWithRead(ins Instr, state *x86ResultState, owned []bool, arch string, nativeRead bool) (bool, bool) {
	return x86ResultBroadcastInputs(ins, state, owned, arch, nativeRead, false)
}

func x86ResultBroadcastInputs(ins Instr, state *x86ResultState, owned []bool, arch string, nativeRead, boundLiteral bool) (bool, bool) {
	f, known, err := x86BroadcastProperties(ins.Op, ins, arch)
	if !known {
		return false, false
	}
	if err != nil {
		return false, true
	}
	return x86ResultBroadcastTransfer(ins, f, state, owned, arch, nativeRead, boundLiteral)
}

// Retain the validated physical form when a source-local consumer projects
// provenance. The mode32 GP-Q opcode still reads and repeats dword lanes;
// projecting its identity must not change the captured input or tuple roles.
func x86ResultBroadcastTransfer(ins Instr, f x86BroadcastForm, state *x86ResultState,
	owned []bool, arch string, nativeRead, boundLiteral bool) (bool, bool) {
	dst, valid := amd64VectorRegisterIndex(ins.Args[f.destination].Reg, f.byteWidth)
	if !valid || dst >= len(state.xmm) {
		return false, true
	}
	if f.mask >= 0 {
		mask, valid := amd64ParseKReg(ins.Args[f.mask].Reg)
		if !valid || !state.masks[mask] || !f.zeroing && state.xmm[dst] != 0xffff {
			return false, true
		}
	}
	required := x86CallerVectorByteMask(int64(f.sourceBytes))
	src := ins.Args[0]
	if f.kind == x86BroadcastMask {
		mask, valid := amd64ParseKReg(src.Reg)
		if !valid || !state.masks[mask] {
			return false, true
		}
	} else if src.Kind == OpImm {
		if !boundLiteral {
			return false, true // Only the complete lowering-bound raw source supplies this input.
		}
	} else if src.Kind != OpReg {
		// Reuse the exact initialized FP/AUTO bytes or the lowering-only
		// same-file DATA extent. The tuple is the scalar/block input, not
		// the wider destination. A mask cannot waive any potential input.
		// Only the paired exact volatile emitter supplies a native continuation;
		// the standalone query still has no native memory or raw address role.
		if !isAMD64MemoryOperand(src) || ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride ||
			!x86ResultReadWithNativeContinuation(ins, src, int64(f.sourceBytes), state, owned, arch, nativeRead) {
			return false, true
		}
	} else if index, valid := amd64VectorRegisterIndex(src.Reg, amd64VectorByteWidth(src.Reg)); valid {
		if index >= len(state.xmm) || state.vectorBytes(index)&required != required {
			return false, true
		}
	} else {
		// A Yrl source exposes low scalar bits without requiring a byte
		// alias spelling (e.g. SI in mode32). SP/BP and opaque values still
		// lack numerical input permission in x86ResultGP.
		index, _, valid := x86ResultGP(src.Reg, 4, arch)
		if !valid || state.pointerGP[index] || uint64(state.gp[index])&required != required {
			return false, true
		}
	}
	// All reads, including an aliased source and masked merge, precede writes.
	defined := ^uint64(0)
	if f.mask >= 0 && !f.zeroing {
		defined &= state.vectorBytes(dst)
	}
	state.writeVector(dst, f.byteWidth, defined, false)
	return true, true
}
