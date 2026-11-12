package plan9asm

import "strings"

// The first ABI0 bool-byte role is a complete 386 no-argument/zero-frame
// declaration. Neither this shape query nor its canonical facts authenticate a
// source, initialize numerical bytes, grant FP backing or describe native entry.
func x86ABI0SingleByteBoolResultRole(fn Func, sig FuncSig, arch string) bool {
	if arch != "386" || strings.Contains(fn.Sym, "<") || fn.FrameSize != 0 || fn.ArgSize != 1 ||
		sig.Ret != I1 || len(sig.Args) != 0 || len(sig.ArgRegs) != 0 || len(sig.Frame.Params) != 0 || len(sig.Frame.Results) != 1 ||
		sig.ARMEntry != nil || sig.ARM64GoRegisterABI != nil || sig.ARM64ClosureABI != nil || sig.WASMContext != "" || sig.WASMNative ||
		len(fn.X86RawText) != 0 || fn.x86SourceStack != nil || fn.x86FixedLocal != nil || fn.x86DirectTailRoot != nil {
		return false
	}
	result := sig.Frame.Results[0]
	return result.Type == I1 && result.Offset == 0 && result.Index == 0 && result.Field == -1 && len(result.Fields) == 0
}

// NUM reads and stores see the complete physical ABI0 byte. Only RET consumes
// the logical i1 after the cached complete canonical result proof. The separate
// physical source-stack seal has its own checked byte-storage handoff; it never
// changes the public logical role. Other bool/frame roles remain unchanged.
func (c *amd64Ctx) abi0BoolResultByteStorage() bool {
	if !c.fpScalarChecked || c.fpScalarCheckErr != nil {
		return false
	}
	if c.fpMixedBoolBytes {
		return true
	}
	if stack := c.sourceStack; stack != nil && stack == c.fpScalarSource.x86SourceStack && stack.scalarResult != nil && c.sig.Ret == I1 {
		return true // The independent physical producer/consumer already checked its complete byte role.
	}
	return x86ABI0LogicalBoolFrameRole(c.fpScalarSource, c.sig, c.goarch)
}

func x86ABI0CanonicalBoolTransfer(transfer x86ResultSourceTransfer) x86ResultSourceTransfer {
	return func(ordinal int, ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) bool {
		if isX86RawDirective(ins) {
			return false
		}
		if !x86ABI0BoolFrameTransfer(ordinal, ins, state, owned, resultOffset, arch, transfer) {
			return false
		}
		for offset := range state.canonicalFP {
			state.canonicalFP[offset] = offset < len(state.fp) && state.canonicalFP[offset] && state.fp[offset]
		}
		for index := range state.canonicalGP {
			state.canonicalGP[index] &= state.gp[index]
		}
		return true
	}
}

// Canonicality is independent of NUM initialization. The consumer must first
// execute its complete typed transfer, then intersect these byte facts with
// initialized bytes. Only actual declared slots allocate this bounded FP state.
func x86ABI0CanonicalBytesAfter(original Instr, beforeFP []bool, beforeGP [16]uint8, arch string) ([]bool, [16]uint8) {
	ins := x86SourceMoveInstruction(original, arch)
	nextFP := append([]bool(nil), beforeFP...)
	nextGP := x86RegisterCanonicalBytesAfter(original, beforeGP, arch)
	read := func(operand Operand, width int64) uint8 {
		if width <= 0 || width > 8 {
			return 0
		}
		switch operand.Kind {
		case OpImm:
			if operand.ImmRaw == "" && !operand.ImmIsFloat {
				return fixedLocalConstantBooleans(operand.Imm, width)
			}
		case OpReg:
			if root, _, valid := x86ResultGP(operand.Reg, width, arch); valid {
				return beforeGP[root] >> fixedLocalBooleanShift(operand.Reg) & uint8((uint16(1)<<uint(width))-1)
			}
		case OpFP:
			if operand.FPOffset >= 0 && operand.FPOffset <= int64(len(beforeFP))-width {
				var bits uint8
				for index := int64(0); index < width; index++ {
					if beforeFP[operand.FPOffset+index] {
						bits |= 1 << uint(index)
					}
				}
				return bits
			}
		}
		return 0
	}
	writeFP := func(operand Operand, width int64, bits uint8) {
		if operand.Kind != OpFP || operand.FPOffset < 0 || width <= 0 || operand.FPOffset > int64(len(nextFP))-width {
			return
		}
		for index := int64(0); index < width; index++ {
			nextFP[operand.FPOffset+index] = bits&(1<<uint(index)) != 0
		}
	}
	if form, known, err := x86ConditionalSetProperties(ins.Op, ins, arch); known && err == nil {
		writeFP(form.destination, 1, 1)
		return nextFP, nextGP
	}
	if width := x86RawReturnScalarMoveBytes(ins.Op); width > 0 && len(ins.Args) == 2 {
		bits := read(ins.Args[0], width)
		writeFP(ins.Args[1], width, bits)
		if ins.Args[0].Kind == OpFP && ins.Args[1].Kind == OpReg {
			if root, mask, valid := x86ResultGP(ins.Args[1].Reg, width, arch); valid {
				bits <<= fixedLocalBooleanShift(ins.Args[1].Reg)
				nextGP[root] = nextGP[root]&^mask | bits&mask
			}
		}
		return nextFP, nextGP
	}
	if form, known, err := x86ScalarExtensionProperties(ins.Op, ins, arch); known && err == nil && form.source.Kind == OpFP {
		from, to := int64(form.spec.sourceBits/8), int64(form.spec.destinationBits/8)
		bits := read(form.source, from)
		if !form.spec.signed || bits&(1<<uint(from-1)) != 0 {
			for index := from; index < to; index++ {
				bits |= 1 << uint(index)
			}
		}
		if root, mask, valid := x86ResultGP(form.result, to, arch); valid {
			if to == 4 && arch == "amd64" {
				mask, bits = 255, bits|240
			}
			nextGP[root] = nextGP[root]&^mask | bits&mask
		}
		return nextFP, nextGP
	}
	// Unknown numeric/vector/mask values never become canonical. The shared
	// exact memory-shape registry accounts for every possible typed FP write.
	for index, operand := range ins.Args {
		if operand.Kind != OpFP {
			continue
		}
		width, write, known := x86InstructionMemoryShape(ins, index, arch)
		if known && write {
			writeFP(operand, width, 0)
		} else if !known {
			for offset := range nextFP {
				nextFP[offset] = false
			}
		}
	}
	return nextFP, nextGP
}
