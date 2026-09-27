package plan9asm

import (
	"encoding/binary"

	"golang.org/x/arch/arm64/arm64asm"
)

type arm64PoolStackAccess struct {
	offset, bytes int64
	registers     [2]int
	count         int
	read, gp64    bool
}

// Decode ordinary scalar/pair SP-relative accesses. Narrow/vector stores still
// have a footprint, but cannot provide a saved 64-bit GP value. Writeback,
// indexed, atomic and exclusive accesses are deliberately not folded.
func arm64PoolDecodeStackAccess(ins arm64asm.Inst, word uint32) (arm64PoolStackAccess, bool) {
	access := arm64PoolStackAccess{count: 1, gp64: true}
	size := ins
	switch ins.Op {
	case arm64asm.LDR, arm64asm.LDUR:
		access.read = true
	case arm64asm.LDP, arm64asm.LDNP:
		access.read, access.count = true, 2
	case arm64asm.STR:
		size.Op = arm64asm.LDR
	case arm64asm.STUR:
		size.Op = arm64asm.LDUR
	case arm64asm.STP, arm64asm.STNP:
		size.Op, access.count = arm64asm.LDP, 2
	case arm64asm.STRB, arm64asm.STURB:
		size.Op, access.gp64 = arm64asm.LDRB, false
	case arm64asm.STRH, arm64asm.STURH:
		size.Op, access.gp64 = arm64asm.LDRH, false
	default:
		return access, false
	}
	memory, ok := ins.Args[access.count].(arm64asm.MemImmediate)
	if !ok || arm64asm.Reg(memory.Base) != arm64asm.SP || memory.Mode != arm64asm.AddrOffset {
		return access, false
	}
	access.offset, _, ok = arm64PoolImmediateAddress(memory)
	access.bytes = arm64RawPoolLoadBytes(size, word)
	if !ok || access.offset < 0 || access.bytes <= 0 {
		return access, false
	}
	for n := 0; n < access.count; n++ {
		reg, ok := ins.Args[n].(arm64asm.Reg)
		if !ok || reg < arm64asm.X0 || reg > arm64asm.XZR {
			access.gp64 = false
			continue
		}
		access.registers[n] = int(reg - arm64asm.X0)
	}
	if access.bytes != int64(access.count*8) {
		access.gp64 = false
	}
	if access.read && access.count == 2 && access.gp64 &&
		access.registers[0] == access.registers[1] && access.registers[0] != 31 {
		return access, false // Constrained-unpredictable pair destination overlap.
	}
	return access, true
}

func arm64PoolDecodeWord(word uint32) (arm64asm.Inst, bool) {
	var code [4]byte
	binary.LittleEndian.PutUint32(code[:], word)
	ins, err := arm64asm.Decode(code[:])
	return ins, err == nil
}

// Rewind the whole query to a dominating save, not just the source register's
// current value. Every other queried GP value must be unchanged along the one
// predecessor chain. Any possible aliasing store, overlap, call, unknown effect
// or SP change rejects the proof. Nonoverlapping direct SP stores are harmless.
func (flow *arm64RawPoolValues) rewindStackLoad(at int, query arm64PoolAffine) (int, arm64PoolAffine, bool) {
	word := flow.words[at]
	if word&0x0a000000 != 0x08000000 || word>>5&31 != 31 {
		return 0, query, false
	}
	ins, ok := arm64PoolDecodeWord(flow.words[at])
	if !ok {
		return 0, query, false
	}
	load, ok := arm64PoolDecodeStackAccess(ins, flow.words[at])
	if !ok || !load.read || !load.gp64 {
		return 0, query, false
	}
	remainder := query
	var scales [2]int64
	for n := 0; n < load.count; n++ {
		if reg := load.registers[n]; reg < 31 {
			scales[n] = remainder.coefficient[reg]
			remainder.coefficient[reg] = 0
		}
	}
	if scales == [2]int64{} {
		return 0, query, false
	}
	visited := make(map[int]bool)
	for steps := 0; steps < 512; steps++ {
		if flow.affineWork >= 16384 {
			return 0, query, false
		}
		flow.affineWork++
		if len(flow.before[at]) != 1 {
			return 0, query, false
		}
		at = flow.before[at][0]
		if at < 0 || flow.opaque[at] || visited[at] {
			return 0, query, false
		}
		visited[at] = true
		word := flow.words[at]
		ins, decoded := arm64PoolDecodeWord(word)
		writes, known := arm64RawPoolGPWrites(word)
		if !decoded || !known || writes&remainder.registerMask() != 0 {
			return 0, query, false
		}
		// SP used as a GP operand could change or expose the frame base.
		// Memory operands carry their base inside a distinct typed argument.
		for _, arg := range ins.Args {
			switch arg := arg.(type) {
			case arm64asm.RegSP:
				if arm64asm.Reg(arg) == arm64asm.SP || arm64asm.Reg(arg) == arm64asm.WSP {
					return 0, query, false
				}
			case arm64asm.MemImmediate:
				if arm64asm.Reg(arg.Base) == arm64asm.SP && arg.Mode != arm64asm.AddrOffset {
					return 0, query, false
				}
			}
		}
		if store, ok := arm64PoolDecodeStackAccess(ins, word); ok && !store.read {
			overlap, matches := false, true
			saved := remainder
			for n := 0; n < load.count; n++ {
				if scales[n] == 0 {
					continue
				}
				offset := load.offset + int64(n*8)
				overlap = overlap || offset < store.offset+store.bytes && store.offset < offset+8
				part := (offset - store.offset) / 8
				if !store.gp64 || offset < store.offset || (offset-store.offset)%8 != 0 ||
					part >= int64(store.count) || !saved.add(arm64PoolRegisterExpression(store.registers[part]), scales[n]) {
					matches = false
				}
			}
			if overlap {
				return at, saved, matches
			}
			continue
		}
		// Typed non-SP stores may alias the slot. Never assume that an
		// arbitrary GP address names a different allocation from the stack.
		if !arm64RawPoolReadOnlyLoad(ins.Op) {
			for _, arg := range ins.Args {
				switch arg.(type) {
				case arm64asm.MemImmediate, arm64asm.MemExtend:
					return 0, query, false
				}
			}
		}
	}
	return 0, query, false
}
