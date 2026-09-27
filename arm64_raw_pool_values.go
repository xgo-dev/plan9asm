package plan9asm

import (
	"encoding/binary"
	"math"

	"golang.org/x/arch/arm64/arm64asm"
)

// Value bounds are separate from pointer relocation: a bound proves only an
// unsigned integer interval, never that copying or escaping a pointer is safe.
// Predecessors include every reachable edge. A conditional edge can narrow a
// value only when its exact comparison and flag provenance are established.
type arm64RawPoolValues struct {
	words       []uint32
	before      [][]int
	cache       map[arm64RawPoolValue]uint64
	active      map[arm64RawPoolValue]bool
	vectorBytes int64

	affineCache    map[arm64PoolAffineQuery]arm64PoolInterval
	affineActive   map[arm64PoolAffineQuery]bool
	affineWork     int
	affineDirect   bool
	maskConstants  map[int]uint64
	invariantCache map[arm64PoolAffineQuery]arm64PoolInterval
	poolOrigins    map[int]uint64
	excluded       map[arm64RawPoolEdge]bool
	loopBounds     map[int]arm64PoolConstraint
	loopLatches    map[int]int
	opaque         map[int]bool
	opaqueLoops    map[int]int
}

type arm64RawPoolValue struct {
	at  int
	reg arm64asm.Reg
}

type arm64RawPoolEdge struct {
	from, to int
}

func newARM64RawPoolValues(instructions []Instr, start, end int, reachable map[int]bool) *arm64RawPoolValues {
	return newARM64RawPoolValuesForVL(instructions, start, end, reachable, 0)
}

func newARM64RawPoolValuesForVL(instructions []Instr, start, end int, reachable map[int]bool, vectorBytes int64) *arm64RawPoolValues {
	flow := &arm64RawPoolValues{
		vectorBytes: vectorBytes,
		words:       make([]uint32, end), before: make([][]int, end),
		cache: make(map[arm64RawPoolValue]uint64), active: make(map[arm64RawPoolValue]bool),
	}
	flow.before[start] = []int{-1} // The function's unknown incoming registers.
	// Stable predecessor order keeps bounded proofs and their caches
	// reproducible; map iteration must not decide whether a budget is met.
	for at := start; at < end; at++ {
		if !reachable[at] {
			continue
		}
		word := uint32(instructions[at].Args[0].Imm)
		flow.words[at] = word
		if word&0xfffffc1f == 0xd65f0000 {
			continue
		}
		displacement, op, relative, _ := arm64RawPCRelativeDisplacement(instructions[at])
		if relative && op != "ADR" {
			target := at + int(displacement/4)
			if target >= start && target < end {
				flow.before[target] = append(flow.before[target], at)
			}
		}
		if word&0xfc000000 != 0x14000000 && at+1 < end {
			flow.before[at+1] = append(flow.before[at+1], at)
		}
	}
	flow.prepareControlFlow()
	return flow
}

func arm64RawPoolGP(reg arm64asm.Reg) (int, bool) {
	switch {
	case reg >= arm64asm.W0 && reg < arm64asm.WZR:
		return int(reg - arm64asm.W0), true
	case reg >= arm64asm.X0 && reg < arm64asm.XZR:
		return int(reg - arm64asm.X0), true
	}
	return 0, false
}

// Walk backwards through unchanged-register edges, unioning all reaching
// definitions. A loop that preserves the register is harmless. A value-changing
// cycle, unknown effect or unknown entry produces the full unsigned range.
func (flow *arm64RawPoolValues) upper(at int, reg arm64asm.Reg) uint64 {
	if reg == arm64asm.XZR || reg == arm64asm.WZR {
		return 0
	}
	index, ok := arm64RawPoolGP(reg)
	if flow == nil || !ok {
		return math.MaxUint64
	}
	key := arm64RawPoolValue{at, reg}
	if value, ok := flow.cache[key]; ok {
		return value
	}
	limit := uint64(math.MaxUint64)
	if reg < arm64asm.WZR {
		limit = math.MaxUint32
	}
	if flow.active[key] {
		return limit
	}
	flow.active[key] = true
	defer delete(flow.active, key)

	var queue []arm64RawPoolEdge
	enqueue := func(at int) {
		for _, previous := range flow.before[at] {
			queue = append(queue, arm64RawPoolEdge{previous, at})
		}
	}
	enqueue(at)
	visited := make(map[int]bool)
	upper, found := uint64(0), false
	for len(queue) > 0 {
		edge := queue[len(queue)-1]
		previous := edge.from
		queue = queue[:len(queue)-1]
		if previous < 0 {
			return limit
		}
		if flow.opaque[previous] {
			return limit
		}
		if bound, ok := flow.edgeUpper(edge, reg); ok {
			if bound > limit {
				bound = limit
			}
			if bound > upper {
				upper = bound
			}
			found = true
			continue
		}
		if visited[previous] {
			continue
		}
		visited[previous] = true
		word := flow.words[previous]
		writes, known := arm64RawPoolGPWrites(word)
		if !known {
			return limit
		}
		if writes&(1<<uint(index)) == 0 {
			enqueue(previous)
			continue
		}
		value := flow.definitionUpper(previous, word, index)
		if value > limit {
			value = limit
		}
		if value > upper {
			upper = value
		}
		found = true
	}
	if !found {
		return limit
	}
	flow.cache[key] = upper
	return upper
}

func (flow *arm64RawPoolValues) definitionUpper(at int, word uint32, index int) uint64 {
	var code [4]byte
	binary.LittleEndian.PutUint32(code[:], word)
	ins, err := arm64asm.Decode(code[:])
	if err != nil {
		return math.MaxUint64
	}
	destination, ok := ins.Args[0].(arm64asm.Reg)
	if reg, sp := ins.Args[0].(arm64asm.RegSP); sp {
		destination, ok = arm64asm.Reg(reg), true
	}
	if actual, gp := arm64RawPoolGP(destination); !ok || !gp || actual != index {
		return math.MaxUint64 // Includes memory-base writeback and second outputs.
	}
	// Loads with writeback may also overwrite the nominal destination's base.
	for _, arg := range ins.Args {
		if memory, ok := arg.(arm64asm.MemImmediate); ok && memory.Mode != arm64asm.AddrOffset {
			if base, gp := arm64RawPoolGP(arm64asm.Reg(memory.Base)); gp && base == index {
				return math.MaxUint64
			}
		}
	}
	argUpper := func(arg arm64asm.Arg) uint64 {
		switch arg := arg.(type) {
		case arm64asm.Reg:
			return flow.upper(at, arg)
		case arm64asm.Imm:
			return uint64(arg.Imm)
		case arm64asm.Imm64:
			return arg.Imm
		}
		return math.MaxUint64
	}
	switch ins.Op {
	case arm64asm.MOV:
		return argUpper(ins.Args[1])
	case arm64asm.AND:
		if _, ok := ins.Args[2].(arm64asm.Imm); ok {
			return argUpper(ins.Args[2])
		}
		if _, ok := ins.Args[2].(arm64asm.Imm64); ok {
			return argUpper(ins.Args[2])
		}
	case arm64asm.CSEL:
		left, right := argUpper(ins.Args[1]), argUpper(ins.Args[2])
		if left > right {
			return left
		}
		return right
	case arm64asm.LSR:
		if shift, ok := ins.Args[2].(arm64asm.Imm); ok {
			return argUpper(ins.Args[1]) >> shift.Imm
		}
	case arm64asm.LDRB, arm64asm.LDURB, arm64asm.LDTRB, arm64asm.LDARB, arm64asm.UXTB:
		return math.MaxUint8
	case arm64asm.LDRH, arm64asm.LDURH, arm64asm.LDTRH, arm64asm.LDARH, arm64asm.UXTH:
		return math.MaxUint16
	}
	return math.MaxUint64
}

// Explicit destination effects for the base data-processing classes and
// ordinary memory instructions. x/arch must validate the encoding first. Do
// not infer effects for system, call, exclusive, atomic or unknown operations.
func arm64RawPoolGPWrites(word uint32) (uint32, bool) {
	if form, ok := decodeARM64RawSVEAddress(word); ok {
		return 1 << uint(form.destination), true
	}
	if form, ok := decodeARM64RawSVECnt(word); ok && !form.vector {
		return 1 << uint(form.destination), true
	}
	if _, ok := decodeARM64RawSVEPredicateCount(word); ok {
		return 1 << (word & 31), true
	}
	if arm64RawPoolSVEIgnoresAddress(word, -1) {
		return 0, true
	}
	if _, ok := arm64RawPoolReplicateLoad(word); ok {
		return 0, true
	}
	var code [4]byte
	binary.LittleEndian.PutUint32(code[:], word)
	ins, err := arm64asm.Decode(code[:])
	if err != nil {
		return 0, false
	}
	destinations := 0
	switch {
	case word&0x1c000000 == 0x10000000, word&0x0e000000 == 0x0a000000, word&0x0e000000 == 0x0e000000:
		destinations = 1
		switch ins.Op {
		case arm64asm.CMP, arm64asm.CMN, arm64asm.TST, arm64asm.CCMP, arm64asm.CCMN:
			destinations = 0
		}
	case arm64RawPoolReadOnlyLoad(ins.Op):
		destinations = 1
		if ins.Op == arm64asm.LDP || ins.Op == arm64asm.LDNP || ins.Op == arm64asm.LDPSW {
			destinations = 2
		}
	default:
		switch ins.Op {
		case arm64asm.B, arm64asm.CBZ, arm64asm.CBNZ, arm64asm.TBZ, arm64asm.TBNZ, arm64asm.NOP,
			arm64asm.STR, arm64asm.STRB, arm64asm.STRH, arm64asm.STUR, arm64asm.STURB, arm64asm.STURH,
			arm64asm.STTR, arm64asm.STTRB, arm64asm.STTRH, arm64asm.STLR, arm64asm.STLRB, arm64asm.STLRH,
			arm64asm.STP, arm64asm.STNP, arm64asm.ST1, arm64asm.ST2, arm64asm.ST3, arm64asm.ST4:
		default:
			return 0, false
		}
	}
	var writes uint32
	for n, arg := range ins.Args {
		if reg, ok := arg.(arm64asm.Reg); ok && n < destinations {
			if index, gp := arm64RawPoolGP(reg); gp {
				writes |= 1 << uint(index)
			}
		}
		if reg, ok := arg.(arm64asm.RegSP); ok && n < destinations {
			if index, gp := arm64RawPoolGP(arm64asm.Reg(reg)); gp {
				writes |= 1 << uint(index)
			}
		}
		if memory, ok := arg.(arm64asm.MemImmediate); ok && memory.Mode != arm64asm.AddrOffset {
			if index, gp := arm64RawPoolGP(arm64asm.Reg(memory.Base)); gp {
				writes |= 1 << uint(index)
			}
		}
	}
	return writes, true
}
