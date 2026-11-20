package plan9asm

import (
	"math"
	"strconv"
	"strings"

	"golang.org/x/arch/arm64/arm64asm"
)

func arm64RawPoolIndexedLoadInBounds(ins arm64asm.Inst, word uint32, memory arm64asm.MemExtend, at int, offset int64, bounds *arm64RawPoolBounds) bool {
	upper := bounds.values.boundedUpper(at, memory.Index)
	switch memory.Extend.String() {
	case "UXTW":
		if upper > math.MaxUint32 {
			upper = math.MaxUint32
		}
	case "SXTW":
		if upper > math.MaxInt32 {
			return false
		}
	case "SXTX":
		if upper > math.MaxInt64 {
			return false
		}
	case "LSL":
	default:
		return false
	}
	shift := memory.Amount
	if memory.ShiftMustBeZero {
		shift = 0
	}
	if offset < 0 || shift >= 63 || upper > uint64(math.MaxInt64-offset)>>shift {
		return false
	}
	return arm64RawPoolContains(offset+int64(upper<<shift), arm64RawPoolLoadBytes(ins, word), bounds.size)
}

func arm64RawPoolContains(offset, bytes, size int64) bool {
	return offset >= 0 && bytes > 0 && bytes <= size && offset <= size-bytes
}

func arm64RawPoolReplicateLoad(word uint32) (Instr, bool) {
	if ins, ok := decodeARM64RawSVEReplicateScalar(word); ok {
		return ins, true
	}
	return decodeARM64RawSVEReplicateBlock(word)
}

func arm64RawPoolLoadInBounds(ins arm64asm.Inst, word uint32, memory arm64asm.MemImmediate, offset, size int64) bool {
	displacement, _, ok := arm64PoolImmediateAddress(memory)
	if !ok {
		return false
	}
	if memory.Mode != arm64asm.AddrOffset {
		if _, _, valid := arm64PoolLoadWriteback(ins, word); !valid {
			return false
		}
	}
	return arm64RawPoolContains(offset+displacement, arm64RawPoolLoadBytes(ins, word), size)
}

// Return the load displacement and the separate base-register update. A post
// index is not part of the read footprint; a pre index is part of both effects.
func arm64PoolImmediateAddress(memory arm64asm.MemImmediate) (int64, int64, bool) {
	// x/arch exposes the addressing mode but keeps the decoded immediate
	// private. Its checked printer specifies offset, pre and post separately.
	// Use that checked representation rather than duplicating every encoder.
	text := memory.String()
	prefix := "[" + memory.Base.String()
	suffix := "]"
	switch memory.Mode {
	case arm64asm.AddrOffset:
		if text == prefix+"]" {
			return 0, 0, true
		}
		prefix += ",#"
	case arm64asm.AddrPreIndex:
		prefix, suffix = prefix+",#", "]!"
	case arm64asm.AddrPostIndex:
		prefix, suffix = prefix+"],#", ""
	default:
		return 0, 0, false
	}
	if !strings.HasPrefix(text, prefix) || !strings.HasSuffix(text, suffix) {
		return 0, 0, false
	}
	delta, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(text, prefix), suffix), 10, 32)
	if err != nil {
		return 0, 0, false
	}
	switch memory.Mode {
	case arm64asm.AddrPreIndex:
		return delta, delta, true
	case arm64asm.AddrPostIndex:
		return 0, delta, true
	}
	return delta, 0, true
}

func arm64PoolLoadWriteback(ins arm64asm.Inst, word uint32) (int, int64, bool) {
	if !arm64RawPoolReadOnlyLoad(ins.Op) || arm64RawPoolLoadBytes(ins, word) == 0 {
		return 0, 0, false
	}
	for _, arg := range ins.Args {
		memory, ok := arg.(arm64asm.MemImmediate)
		if !ok || memory.Mode != arm64asm.AddrPreIndex && memory.Mode != arm64asm.AddrPostIndex {
			continue
		}
		base, gp := arm64RawPoolGP(arm64asm.Reg(memory.Base))
		_, delta, valid := arm64PoolImmediateAddress(memory)
		if !gp || !valid {
			return 0, 0, false
		}
		for _, output := range ins.Args {
			if register, ok := output.(arm64asm.Reg); ok {
				if index, gp := arm64RawPoolGP(register); gp && index == base {
					return 0, 0, false // Constrained-unpredictable base/destination overlap.
				}
			}
		}
		return base, delta, true
	}
	return 0, 0, false
}

func arm64RawPoolLoadBytes(ins arm64asm.Inst, word uint32) int64 {
	switch ins.Op {
	case arm64asm.LDRB, arm64asm.LDRSB, arm64asm.LDURB, arm64asm.LDURSB,
		arm64asm.LDTRB, arm64asm.LDTRSB, arm64asm.LDARB:
		return 1
	case arm64asm.LDRH, arm64asm.LDRSH, arm64asm.LDURH, arm64asm.LDURSH,
		arm64asm.LDTRH, arm64asm.LDTRSH, arm64asm.LDARH:
		return 2
	case arm64asm.LDRSW, arm64asm.LDURSW, arm64asm.LDTRSW:
		return 4
	case arm64asm.LDPSW:
		return 8
	case arm64asm.LDR, arm64asm.LDUR, arm64asm.LDTR, arm64asm.LDAR,
		arm64asm.LDP, arm64asm.LDNP:
		reg, ok := ins.Args[0].(arm64asm.Reg)
		if !ok {
			return 0
		}
		bytes := int64(0)
		switch {
		case reg >= arm64asm.B0 && reg <= arm64asm.B31:
			bytes = 1
		case reg >= arm64asm.H0 && reg <= arm64asm.H31:
			bytes = 2
		case reg >= arm64asm.W0 && reg <= arm64asm.WZR || reg >= arm64asm.S0 && reg <= arm64asm.S31:
			bytes = 4
		case reg >= arm64asm.X0 && reg <= arm64asm.XZR || reg >= arm64asm.D0 && reg <= arm64asm.D31:
			bytes = 8
		case reg >= arm64asm.Q0 && reg <= arm64asm.Q31:
			bytes = 16
		}
		if ins.Op == arm64asm.LDP || ins.Op == arm64asm.LDNP {
			bytes *= 2
		}
		return bytes
	case arm64asm.LD1R, arm64asm.LD2R, arm64asm.LD3R, arm64asm.LD4R:
		if form, ok := decodeARM64RawLDnR(word); ok && !form.post {
			return int64(form.count * form.arrangement.elementBits / 8)
		}
	case arm64asm.LD1, arm64asm.LD2, arm64asm.LD3, arm64asm.LD4:
		if form, ok := decodeARM64RawStructureLane(word); ok && form.load && !form.post {
			return int64(form.count * form.elementBits / 8)
		}
		// x/arch already validated this multiple-structure instruction.
		// Restrict to no writeback, then use opcode's register count and Q.
		if word&0xbfff0000 == 0x0c400000 {
			count := map[uint32]int64{0: 4, 2: 4, 4: 3, 6: 3, 7: 1, 8: 2, 10: 2}[word>>12&15]
			return count * (8 << (word >> 30 & 1))
		}
	}
	return 0
}
