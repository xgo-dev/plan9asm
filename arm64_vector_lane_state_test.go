package plan9asm

import (
	"errors"
	"testing"
)

func TestARM64GoRegisterVectorLaneStateIntersectsAndRevokes(t *testing.T) {
	write := func(state *arm64MachineState, offset, width int) {
		t.Helper()
		if err := state.applyVectorSpan(arm64MachineEffect{register: "V21", vectorOffset: offset, width: width, write: true}); err != nil {
			t.Fatal(err)
		}
	}
	read := func(state *arm64MachineState, offset, width int, available bool) {
		t.Helper()
		err := state.applyVectorSpan(arm64MachineEffect{register: "V21", vectorOffset: offset, width: width})
		if (err == nil) != available || (!available && !errors.Is(err, ErrProbeNeedsContext)) {
			t.Fatalf("span [%d,%d) available=%t: %v", offset, offset+width, available, err)
		}
	}
	state := arm64MachineBoundary(nil)
	write(&state, 64, 64)
	read(&state, 64, 64, true)
	read(&state, 0, 64, false)
	copy := state.clone()
	write(&copy, 0, 64)
	if copy.values["V21"] != arm64WholeScalableRegister || state.values["V21"] != 0 {
		t.Fatal("clone shared a lane mask or a full bank failed to initialize")
	}
	if !copy.merge(state) || copy.values["V21"] != 0 {
		t.Fatal("join did not remove the missing low half")
	}
	read(&copy, 64, 64, true)
	read(&copy, 0, 64, false)
	if copy.merge(state) {
		t.Fatal("identical definition merge did not converge")
	}
	other := arm64MachineBoundary(nil)
	write(&other, 0, 64)
	copy.merge(other)
	read(&copy, 64, 64, false)
	read(&copy, 0, 64, false)

	for _, effect := range []arm64MachineEffect{
		{register: "V21", vectorOffset: -1, width: 1},
		{register: "V21", vectorOffset: 128, width: 1},
		{register: "V21", vectorOffset: 127, width: 2},
		{register: "V21", width: 0},
		{register: "V21", width: 129},
		{register: "R21", width: 64},
	} {
		if err := state.applyVectorSpan(effect); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("invalid finite vector span accepted: %+v: %v", effect, err)
		}
	}
	for name, revoke := range map[string]arm64MachineEffect{
		"original scratch invalidation": {register: "V21", unavailable: true},
		"scalar overwrite":              {register: "V21", width: 32, write: true},
		"typed call":                    {call: &ARM64GoRegisterABI{}},
	} {
		t.Run(name, func(t *testing.T) {
			flow := &arm64MachineAvailability{used: true, entry: &ARM64GoRegisterABI{}, blocks: []arm64MachineBlock{{name: "entry", effects: []arm64MachineEffect{
				{register: "V21", vectorOffset: 64, width: 64, write: true, vectorSpan: true},
				revoke,
				{register: "V21", vectorOffset: 64, width: 64, vectorSpan: true},
			}}}}
			if err := flow.validate(); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("replaced or revoked bank retained old lane authority: %v", err)
			}
		})
	}
}
