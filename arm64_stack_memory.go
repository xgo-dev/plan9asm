package plan9asm

import (
	"fmt"
	"strings"
)

// Size the statically expressed displacement and transfer. Register/vector
// indexes are address computations, not declarations of additional stack
// storage; their source program must keep accesses inside its allocated frame.
func arm64StackMemoryExtent(ins Instr, mem MemRef) (low, high, width int64, err error) {
	low, high, width = mem.Off, mem.Off, 64
	op := strings.ToUpper(string(ins.Op))
	if strings.HasPrefix(op, "Z") || strings.HasPrefix(op, "P") {
		// At most four scalable vectors, each at most 256 bytes. Predicate
		// and widening/narrowing memory forms require no larger footprint.
		width = 4 * 256
	}
	if mem.OffRaw == "" {
		return
	}
	if arm64NamedStackOffset(mem) {
		return
	}
	if offset, ok := parseNamedStackConstantOffset(mem.OffRaw); ok && offset == mem.Off {
		return
	}
	if multiplier, ok := parseVectorLengthScaleExpr(mem.OffRaw); ok {
		if multiplier < -arm64MaxLocalStackSpan/256 || multiplier > arm64MaxLocalStackSpan/256 {
			err = fmt.Errorf("scalable stack displacement exceeds allocation limit")
			return
		}
		// Using full vector bytes also conservatively covers predicate-sized
		// VL units and narrower element-memory ratios.
		low, high = 0, multiplier*256
		if low > high {
			low, high = high, low
		}
		return
	}
	err = fmt.Errorf("unresolved stack displacement %q", mem.OffRaw)
	return
}

// Entry emission initializes non-argument GP registers to zero. Prove only
// registers untouched by the entire function, rather than guessing the value
// of a dynamic writeback register. Calls and unknown effects invalidate this
// small proof. This also keeps isolated operand-form probes faithful to their
// actual initialized state.
func (c *arm64Ctx) stackUnwrittenZeroRegisters() uint32 {
	if len(c.sig.Args) != 0 {
		return 0
	}
	written := uint32(1 << 31)
	for _, block := range c.blocks {
		for _, original := range block.instrs {
			if original.Op == OpWORD && len(original.Args) == 1 {
				word := uint32(original.Args[0].Imm)
				if word&0xfffffc1f == 0xd65f0000 {
					continue
				}
				mask, known := arm64RawPoolGPWrites(word)
				if !known {
					return 0
				}
				written |= mask
				continue
			}
			ins := arm64StackInstruction(original)
			op := strings.ToUpper(string(ins.Op))
			if op == "BL" || op == "BLR" || op == "CALL" || op == "SVC" {
				return 0
			}
			mark := func(reg Reg) {
				if index, ok := arm64StackIndex(reg); ok {
					written |= 1 << uint(index)
				}
			}
			for _, arg := range ins.Args {
				switch arg.Kind {
				case OpReg, OpRegShift, OpRegExtend:
					mark(arg.Reg)
				case OpRegList:
					for _, reg := range arg.RegList {
						mark(reg)
					}
				case OpMem:
					if strings.HasSuffix(op, ".P") || strings.HasSuffix(op, ".W") {
						mark(arg.Mem.Base)
					}
				}
			}
		}
	}
	return ^written
}
