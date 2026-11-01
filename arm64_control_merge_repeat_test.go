package plan9asm

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// Both operands retain all original tokens. Common entries are deliberately
// constructed independently, as happens when many incoming paths carry the
// same logical return destinations without sharing every physical trie node.
func arm64ControlMergeRepeatedOperands(targets int) (arm64ControlValue, arm64ControlValue) {
	tokens := make([]string, targets+2)
	for index := range tokens {
		tokens[index] = fmt.Sprintf("label:return_%d", index)
	}
	sort.Slice(tokens, func(left, right int) bool {
		return arm64ControlHash(tokens[left]) < arm64ControlHash(tokens[right])
	})
	left, right := make(map[string]bool), make(map[string]bool)
	for _, token := range tokens[:targets] {
		left[token], right[token] = true, true
	}
	left[tokens[targets]], right[tokens[targets+1]] = true, true
	return arm64ControlFromMap(left), arm64ControlFromMap(right)
}

func arm64ControlMergeRepeatedState(value arm64ControlValue, cells int) *arm64ControlState {
	state := &arm64ControlState{
		regs: map[Reg]arm64ControlValue{
			SP:    arm64ControlFromMap(map[string]bool{"sp:0": true}),
			"R30": value,
		},
		memory:      make(map[string]arm64ControlValue),
		escaped:     value,
		unexposedSP: true,
	}
	for cell := 0; cell < cells; cell++ {
		state.memory[fmt.Sprintf("sp:%d", (cell+1)*8)] = value
	}
	return state
}

func arm64ControlMergeCheckComplete(tb testing.TB, state *arm64ControlState, left, right arm64ControlValue, cells int) {
	tb.Helper()
	want := arm64ControlFrozenUnion(arm64ControlMap(left), arm64ControlMap(right))
	if len(state.memory) != cells || !state.unexposedSP || !arm64ControlEqual(state.regs[SP], arm64ControlFromMap(map[string]bool{"sp:0": true})) {
		tb.Fatal("merge changed outer frame/ownership or dropped private cells")
	}
	for cell := 0; cell < cells; cell++ {
		key := fmt.Sprintf("sp:%d", (cell+1)*8)
		if !reflect.DeepEqual(arm64ControlMap(state.memory[key]), want) {
			tb.Fatalf("changed complete original RET set in cell %s", key)
		}
	}
	if !reflect.DeepEqual(arm64ControlMap(state.escaped), want) || !reflect.DeepEqual(arm64ControlMap(state.regs["R30"]), want) {
		tb.Fatal("merge changed complete escaped/link target sets")
	}
}

func TestARM64ControlRepeatedMergeAllocation(t *testing.T) {
	const targets, cells = 512, 128
	left, right := arm64ControlMergeRepeatedOperands(targets)
	before, incoming := arm64ControlMergeRepeatedState(left, cells), arm64ControlMergeRepeatedState(right, cells)
	var result *arm64ControlState
	measurement := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for iteration := 0; iteration < b.N; iteration++ {
			result = before.clone()
			if !result.merge(incoming) {
				b.Fatal("lost new original return destination")
			}
		}
	})
	arm64ControlMergeCheckComplete(t, result, left, right, cells)
	arm64ControlMergeCheckComplete(t, before, left, left, cells)
	arm64ControlMergeCheckComplete(t, incoming, right, right, cells)
	t.Logf("complete %d-target/%d-cell repeated merge: %s %s", targets, cells, measurement, measurement.MemString())
	// A test-only allocation assertion, not a proof/target/work bound. Every
	// original target and cell was independently checked above.
	if measurement.AllocedBytesPerOp() > 1<<20 {
		t.Fatalf("one merge recomputes the identical complete union for every cell: %d bytes/op", measurement.AllocedBytesPerOp())
	}
}

func TestARM64ControlRepeatedMergeOrderedFalseNilReference(t *testing.T) {
	values := []arm64ControlValue{
		nil, arm64ControlFromMap(map[string]bool{}),
		arm64ControlFromMap(map[string]bool{"label:a": false}),
		arm64ControlFromMap(map[string]bool{"label:a": true}),
		arm64ControlFromMap(map[string]bool{"": false, "fp:8": true}),
		arm64ControlFromMap(map[string]bool{"sp:0": true, "code-derived:": false}),
	}
	for leftIndex, left := range values {
		for rightIndex, right := range values {
			name := fmt.Sprintf("ordered_%d_%d", leftIndex, rightIndex)
			t.Run(name, func(t *testing.T) {
				state, other := arm64ControlMergeRepeatedState(left, 8), arm64ControlMergeRepeatedState(right, 8)
				want, incoming := arm64ControlFrozenStateOf(state), arm64ControlFrozenStateOf(other)
				wantChanged := want.merge(incoming)
				changed := state.merge(other)
				if changed != wantChanged || !reflect.DeepEqual(arm64ControlFrozenStateOf(state), want) {
					t.Fatalf("changed ordered nil/false merge: %v, want %v", changed, wantChanged)
				}
			})
		}
	}
}

// Independent old map-state transfer, including ordered asymmetric equality,
// absent inputs and physical vector aliases. It is not used by production.
type arm64ControlFrozenState struct {
	regs        map[Reg]map[string]bool
	memory      map[string]map[string]bool
	escaped     map[string]bool
	unexposedSP bool
}

func arm64ControlFrozenStateOf(state *arm64ControlState) *arm64ControlFrozenState {
	result := &arm64ControlFrozenState{
		regs: make(map[Reg]map[string]bool), memory: make(map[string]map[string]bool),
		escaped: arm64ControlMap(state.escaped), unexposedSP: state.unexposedSP,
	}
	for reg, value := range state.regs {
		result.regs[reg] = arm64ControlMap(value)
	}
	for key, value := range state.memory {
		result.memory[key] = arm64ControlMap(value)
	}
	return result
}

func (state *arm64ControlFrozenState) read(reg Reg) map[string]bool {
	reg = arm64ControlBase(reg)
	value := state.regs[reg]
	root := arm64MachineRegister(reg)
	if strings.HasPrefix(root, "V") {
		for alias, witness := range state.regs {
			if arm64MachineRegister(alias) == root {
				value = arm64ControlFrozenUnion(value, witness)
			}
		}
	}
	if value == nil {
		return map[string]bool{"": true}
	}
	return value
}

func (state *arm64ControlFrozenState) merge(other *arm64ControlFrozenState) bool {
	changed := false
	if state.unexposedSP && !other.unexposedSP {
		state.unexposedSP, changed = false, true
	}
	escaped := arm64ControlFrozenUnion(state.escaped, other.escaped)
	if !arm64ControlFrozenEqual(state.escaped, escaped) {
		state.escaped, changed = escaped, true
	}
	for reg, value := range other.regs {
		merged := arm64ControlFrozenUnion(state.read(reg), value)
		if !arm64ControlFrozenEqual(state.regs[reg], merged) {
			state.regs[reg], changed = merged, true
		}
	}
	for reg, value := range state.regs {
		if other.regs[reg] == nil {
			merged := arm64ControlFrozenUnion(value, map[string]bool{"": true})
			if !arm64ControlFrozenEqual(value, merged) {
				state.regs[reg], changed = merged, true
			}
		}
	}
	for key, value := range other.memory {
		old := state.memory[key]
		if old == nil {
			old = map[string]bool{"": true}
		}
		merged := arm64ControlFrozenUnion(old, value)
		if !arm64ControlFrozenEqual(state.memory[key], merged) {
			state.memory[key], changed = merged, true
		}
	}
	for key, value := range state.memory {
		if other.memory[key] == nil {
			merged := arm64ControlFrozenUnion(value, map[string]bool{"": true})
			if !arm64ControlFrozenEqual(value, merged) {
				state.memory[key], changed = merged, true
			}
		}
	}
	return changed
}

func BenchmarkARM64ControlRepeatedCellMerge(b *testing.B) {
	for _, size := range []struct{ targets, cells int }{{128, 64}, {512, 128}, {1024, 256}} {
		b.Run(fmt.Sprintf("targets_%d_cells_%d", size.targets, size.cells), func(b *testing.B) {
			left, right := arm64ControlMergeRepeatedOperands(size.targets)
			before, incoming := arm64ControlMergeRepeatedState(left, size.cells), arm64ControlMergeRepeatedState(right, size.cells)
			b.ReportAllocs()
			b.ResetTimer()
			var result *arm64ControlState
			for iteration := 0; iteration < b.N; iteration++ {
				result = before.clone()
				if !result.merge(incoming) {
					b.Fatal("missing new original RET target")
				}
			}
			b.StopTimer()
			arm64ControlMergeCheckComplete(b, result, left, right, size.cells)
		})
	}
}

func BenchmarkARM64ControlRepeatedSubsetMerge(b *testing.B) {
	for _, size := range []struct{ targets, cells int }{{512, 1}, {512, 128}, {1024, 1}, {1024, 256}} {
		b.Run(fmt.Sprintf("targets_%d_cells_%d", size.targets, size.cells), func(b *testing.B) {
			left, extra := arm64ControlMergeRepeatedOperands(size.targets)
			// Keep equal common keys physically independent, so the complete
			// successful subset traversal is not hidden by node identity.
			rightEntries := arm64ControlFrozenUnion(arm64ControlMap(left), arm64ControlMap(extra))
			right := arm64ControlFromMap(rightEntries)
			before, incoming := arm64ControlMergeRepeatedState(left, size.cells), arm64ControlMergeRepeatedState(right, size.cells)
			b.ReportAllocs()
			b.ResetTimer()
			var result *arm64ControlState
			for iteration := 0; iteration < b.N; iteration++ {
				result = before.clone()
				if !result.merge(incoming) {
					b.Fatal("lost larger complete original RET set")
				}
			}
			b.StopTimer()
			arm64ControlMergeCheckComplete(b, result, left, right, size.cells)
		})
	}
}
