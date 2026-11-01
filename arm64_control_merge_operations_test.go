package plan9asm

import (
	"fmt"
	"math/rand"
	"reflect"
	"testing"
)

func TestARM64ControlMergeOperationOrderedIdentity(t *testing.T) {
	values := []arm64ControlValue{nil, {},
		arm64ControlFromMap(map[string]bool{"label:a": false}),
		arm64ControlFromMap(map[string]bool{"label:a": true}),
		arm64ControlFromMap(map[string]bool{"sp:0": true, "fp:8": false}),
		arm64ControlFromMap(map[string]bool{"": false, "code-derived:": true}),
	}
	var collision *arm64ControlNode
	collision = arm64ControlInsert(collision, 7, "label:collision_a", false)
	collision = arm64ControlInsert(collision, 7, "label:collision_b", true)
	values = append(values, &arm64ControlSet{root: collision})
	var operations arm64ControlMergeOperations
	for oldIndex, old := range values {
		for leftIndex, left := range values {
			for rightIndex, right := range values {
				want := arm64ControlFrozenUnion(arm64ControlMap(left), arm64ControlMap(right))
				wantChanged := !arm64ControlFrozenEqual(arm64ControlMap(old), want)
				result := operations.union(old, left, right)
				if result.changed != wantChanged || !reflect.DeepEqual(arm64ControlMap(result.value), want) {
					t.Fatalf("complete ordered triple %d/%d/%d changed", oldIndex, leftIndex, rightIndex)
				}
				if again := operations.union(old, left, right); again != result {
					t.Fatal("same complete ordered inputs did not retain exact result")
				}
			}
		}
	}
	// A distinct value carrying the same full strings must not retrieve a
	// pointer-identity entry, even if the independently computed answer agrees.
	copy := arm64ControlFromMap(arm64ControlMap(values[3]))
	operations.union(nil, copy, nil)
	if _, present := operations[arm64ControlMergeOperands{nil, copy, nil}]; !present {
		t.Fatal("distinct immutable operand identity was replaced by content/hash inference")
	}
}

func TestARM64ControlRepeatedMergeRandomCompleteMapState(t *testing.T) {
	for seed := int64(0); seed < 100; seed++ {
		t.Run(fmt.Sprintf("seed_%03d", seed), func(t *testing.T) {
			random := rand.New(rand.NewSource(seed))
			values := []arm64ControlValue{nil, {},
				arm64ControlFromMap(map[string]bool{"label:a": false}),
				arm64ControlFromMap(map[string]bool{"sp:0": true, "fp:8": false}),
				arm64ControlFromMap(map[string]bool{"": false, "code-derived:": true}),
			}
			for index := 0; index < 8; index++ {
				entries := make(map[string]bool)
				for token := 0; token < 16; token++ {
					if random.Intn(3) != 0 {
						entries[fmt.Sprintf("label:target_%d", token)] = random.Intn(3) != 0
					}
				}
				values = append(values, arm64ControlFromMap(entries))
			}
			makeState := func() *arm64ControlState {
				state := &arm64ControlState{
					regs: make(map[Reg]arm64ControlValue), memory: make(map[string]arm64ControlValue),
					escaped: values[random.Intn(len(values))], unexposedSP: random.Intn(2) == 0,
				}
				for _, reg := range []Reg{SP, "R0", "R1", "R30", "F0"} {
					if random.Intn(3) != 0 {
						state.regs[reg] = values[random.Intn(len(values))]
					}
				}
				for cell := 0; cell < 16; cell++ {
					if random.Intn(3) != 0 {
						state.memory[fmt.Sprintf("sp:%d", cell*8)] = values[random.Intn(len(values))]
					}
				}
				return state
			}
			state, other := makeState(), makeState()
			// Only the destination state has a second view, avoiding any
			// dependence on unordered sequential incoming alias updates.
			state.regs["V0"] = values[random.Intn(len(values))]
			want, incoming := arm64ControlFrozenStateOf(state), arm64ControlFrozenStateOf(other)
			otherBefore := arm64ControlFrozenStateOf(other)
			wantChanged := want.merge(incoming)
			if changed := state.merge(other); changed != wantChanged || !reflect.DeepEqual(arm64ControlFrozenStateOf(state), want) {
				t.Fatalf("complete original map-state transfer changed (changed %v want %v)", changed, wantChanged)
			}
			if !reflect.DeepEqual(arm64ControlFrozenStateOf(other), otherBefore) {
				t.Fatal("merge modified a predecessor or its shared exact sets")
			}
		})
	}
}
