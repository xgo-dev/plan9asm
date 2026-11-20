package plan9asm

import (
	"math"
	"reflect"
	"testing"
)

func x86CallerJoinDomainState() (x86SourceStackState, *x86GoCallerRegionProof) {
	proof := &x86GoCallerRegionProof{arguments: []x86CallerArgumentRegion{
		{kind: x86CallerSliceInput, width: 4}, {kind: x86CallerSliceInput, width: 4},
		{kind: x86CallerFreshResult, width: 4}, {kind: x86CallerLocalLength, width: 8},
	}}
	state := x86SourceStackState{
		bp: x86SourceStackAddress{original: true}, numericFlags: true, gOriginal: true,
		callers: map[Reg]x86CallerPointerValue{DI: {argument: 0}, SI: {argument: 1}, DX: {argument: 2}, CX: {argument: 3}},
		known:   map[Reg]uint8{AX: 0xff}, vectors: map[Reg]uint64{"Z0": ^uint64(0)}, masks: map[Reg]bool{"K1": true},
	}
	return state, proof
}

func TestX86GoCallerAcyclicJoinDomainIntersectionAndNoAliasing(t *testing.T) {
	left, proof := x86CallerJoinDomainState()
	left.cells = []x86SourceStackCell{{offset: -8, width: 8,
		bp: &x86SourceStackAddress{original: true}, caller: &x86CallerPointerValue{argument: 0}}}
	right := x86CloneCallerState(left)
	right.callers[DI] = x86CallerPointerValue{argument: 0, offset: 4}
	right.known[AX] = 1
	right.known[BX] = 0xff
	right.vectors["Z0"] = 0xf
	right.vectors["Z1"] = ^uint64(0)
	delete(right.masks, "K1")
	right.masks["K2"] = true
	beforeLeft, beforeRight := x86CloneCallerState(left), x86CloneCallerState(right)
	merged, valid := x86CallerAcyclicMerge(left, right, proof)
	if !valid || merged.callers[DI] != (x86CallerPointerValue{argument: 0, span: 4}) ||
		merged.known[AX] != 1 || merged.known[BX] != 0 || merged.vectors["Z0"] != 0xf ||
		merged.vectors["Z1"] != 0 || merged.masks["K1"] || merged.masks["K2"] {
		t.Fatalf("not an all-path same-origin intersection: %+v, %t", merged, valid)
	}
	reversed, valid := x86CallerAcyclicMerge(right, left, proof)
	if !valid || !reflect.DeepEqual(merged, reversed) {
		t.Fatal("merge depends on predecessor arrival order")
	}
	merged.callers[DI] = x86CallerPointerValue{}
	merged.known[AX] = 0
	merged.vectors["Z0"] = 0
	merged.masks["K1"] = true
	merged.cells[0].bp.offset = 7
	merged.cells[0].caller.offset = 7
	if !reflect.DeepEqual(left, beforeLeft) || !reflect.DeepEqual(right, beforeRight) {
		t.Fatal("merged state aliases a predecessor map, cell or saved pointer")
	}
}

func TestX86GoCallerAcyclicJoinDomainRejectsChangedFixedOrigins(t *testing.T) {
	for _, change := range []string{
		"missing origin", "different argument", "result offset", "length offset", "SP", "BP", "g", "flags", "saved cell",
		"span on result", "negative span", "overflow span", "past offset cap", "past end cap",
	} {
		t.Run(change, func(t *testing.T) {
			left, proof := x86CallerJoinDomainState()
			right := x86CloneCallerState(left)
			switch change {
			case "missing origin":
				delete(right.callers, DI)
			case "different argument":
				right.callers[DI] = x86CallerPointerValue{argument: 1}
			case "result offset":
				right.callers[DX] = x86CallerPointerValue{argument: 2, offset: 1}
			case "length offset":
				right.callers[CX] = x86CallerPointerValue{argument: 3, offset: 1}
			case "SP":
				right.sp = -8
			case "BP":
				right.bp.original = false
			case "g":
				right.gOriginal = false
			case "flags":
				right.numericFlags = false
			case "saved cell":
				right.cells = []x86SourceStackCell{{offset: -8, width: 8}}
			case "span on result":
				left.callers[DX] = x86CallerPointerValue{argument: 2, span: 1}
				right.callers[DX] = left.callers[DX]
			case "negative span":
				right.callers[DI] = x86CallerPointerValue{argument: 0, span: -1}
			case "overflow span":
				right.callers[DI] = x86CallerPointerValue{argument: 0, offset: 1, span: math.MaxInt64}
			case "past offset cap":
				right.callers[DI] = x86CallerPointerValue{argument: 0, offset: -x86SourceStackLimit - 1}
			case "past end cap":
				right.callers[DI] = x86CallerPointerValue{argument: 0, offset: x86SourceStackLimit, span: 1}
			}
			if _, valid := x86CallerAcyclicMerge(left, right, proof); valid {
				t.Fatal("changed fixed state or invalid span acquired a join")
			}
		})
	}
}

func TestX86GoCallerAcyclicJoinPointerArithmeticBounds(t *testing.T) {
	for _, test := range []struct {
		pointer x86CallerPointerValue
		delta   int64
		valid   bool
	}{
		{x86CallerPointerValue{offset: -4, span: 8}, 4, true},
		{x86CallerPointerValue{offset: -x86SourceStackLimit, span: 2 * x86SourceStackLimit}, 0, true},
		{x86CallerPointerValue{offset: x86SourceStackLimit - 4, span: 4}, 1, false},
		{x86CallerPointerValue{offset: -x86SourceStackLimit, span: 4}, -1, false},
		{x86CallerPointerValue{offset: 1, span: 4}, math.MaxInt64, false},
		{x86CallerPointerValue{offset: -1, span: 4}, math.MinInt64, false},
		{x86CallerPointerValue{offset: math.MaxInt64, span: 1}, 0, false},
	} {
		shifted, valid := x86CallerPointerShift(test.pointer, test.delta)
		if valid != test.valid || valid && shifted.span != test.pointer.span {
			t.Fatalf("shift %+v by %d: %+v/%t", test.pointer, test.delta, shifted, valid)
		}
	}
}

func TestX86GoCallerAcyclicJoinDomainCannotRecoverUnknownFacts(t *testing.T) {
	left, proof := x86CallerJoinDomainState()
	unknown := x86CloneCallerState(left)
	delete(unknown.known, AX)
	delete(unknown.vectors, "Z0")
	delete(unknown.masks, "K1")
	joined, valid := x86CallerAcyclicMerge(left, unknown, proof)
	if !valid {
		t.Fatal("same origins with unknown numerical bytes should intersect")
	}
	joined, valid = x86CallerAcyclicMerge(joined, left, proof)
	if !valid || joined.known[AX] != 0 || joined.vectors["Z0"] != 0 || joined.masks["K1"] {
		t.Fatal("later predecessor recovered an erased all-path fact")
	}
}

func TestX86GoCallerAcyclicJoinDomainAllPredecessorPermutations(t *testing.T) {
	first, proof := x86CallerJoinDomainState()
	second, third := x86CloneCallerState(first), x86CloneCallerState(first)
	second.callers[DI] = x86CallerPointerValue{argument: 0, offset: -4}
	third.callers[DI] = x86CallerPointerValue{argument: 0, offset: 12}
	second.known[AX] = 0xf
	third.known[AX] = 3
	second.vectors["Z0"] = 0xff
	third.vectors["Z0"] = 0xf
	second.known[BX], third.known[BX] = 0xff, 0xff
	second.vectors["Z1"], third.vectors["Z1"] = 0xff, 0xff
	second.masks["K2"], third.masks["K2"] = true, true
	third.masks["K1"] = false
	states := []x86SourceStackState{first, second, third}
	var expected *x86SourceStackState
	for _, order := range [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}} {
		joined, valid := x86CallerAcyclicMerge(states[order[0]], states[order[1]], proof)
		if valid {
			joined, valid = x86CallerAcyclicMerge(joined, states[order[2]], proof)
		}
		if !valid || joined.callers[DI] != (x86CallerPointerValue{argument: 0, offset: -4, span: 16}) ||
			joined.known[AX] != 3 || joined.known[BX] != 0 || joined.vectors["Z0"] != 0xf ||
			joined.vectors["Z1"] != 0 || joined.masks["K1"] || joined.masks["K2"] {
			t.Fatalf("permutation %v recovered a missing fact: %+v/%t", order, joined, valid)
		}
		if expected != nil && !reflect.DeepEqual(*expected, joined) {
			t.Fatalf("three-predecessor merge depends on order %v", order)
		}
		copy := x86CloneCallerState(joined)
		expected = &copy
	}
}

func TestX86GoCallerAcyclicJoinGraphRequiresCompleteReachableDAG(t *testing.T) {
	for _, test := range []struct {
		name, body string
		acyclic    bool
	}{
		{"fallthrough", "MOVL $1,AX\nRET", true},
		{"diamond", "CMPQ AX,$0\nJE other\nMOVL $1,AX\nJMP done\nother:\nMOVL $2,AX\ndone:\nRET", true},
		{"dead cycle", "JMP done\ndead:\nJMP dead\ndone:\nRET", true},
		{"reachable cycle", "loop:\nCMPQ AX,$0\nJNE loop\nRET", false},
		{"cycle beyond join", "CMPQ AX,$0\nJE joined\nMOVL $1,AX\njoined:\nloop:\nJMP loop", false},
		{"PC forward", "JMP 1(PC)\nRET", true},
		{"PC self", "JMP 0(PC)", false},
		{"PC out of source", "JMP 3(PC)\nRET", false},
		{"unknown indirect target", "JMP AX\nRET", false},
		{"unknown label", "JMP missing\nRET", false},
		{"fall off source", "MOVL $1,AX", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT ·graph(SB),4,$0-0\n"+test.body+"\n")
			if err != nil {
				t.Fatal(err)
			}
			fn := file.Funcs[0]
			labels := map[string]int{}
			var instructions []int
			for index, ins := range fn.Instrs {
				if ins.Op == OpLABEL {
					labels[ins.Args[0].Sym] = len(instructions)
				} else {
					instructions = append(instructions, index)
				}
			}
			if got := x86CallerReachableAcyclic(fn, instructions, labels); got != test.acyclic {
				t.Fatalf("reachable graph acyclic=%t, want %t", got, test.acyclic)
			}
		})
	}
	if x86CallerReachableAcyclic(Func{}, nil, nil) ||
		x86CallerReachableAcyclic(Func{}, make([]int, 8193), nil) {
		t.Fatal("empty or over-budget source acquired a new merge")
	}
}
