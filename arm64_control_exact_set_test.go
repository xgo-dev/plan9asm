package plan9asm

import (
	"fmt"
	"reflect"
	"sync"
	"testing"
)

func arm64ControlExactCheckNode(t *testing.T, node *arm64ControlNode) map[string]bool {
	t.Helper()
	entries := make(map[string]bool)
	arm64ControlVisitNode(node, func(hash uint64, token string, present bool) bool {
		if _, duplicate := entries[token]; duplicate {
			t.Fatalf("duplicate complete string %q", token)
		}
		entries[token] = present
		if arm64ControlLookup(node, hash, token) != present {
			t.Fatalf("lookup %q lost exact bool or collision identity", token)
		}
		return true
	})
	if node == nil {
		return entries
	}
	falseEntries, frames, labels, nonUnknown := 0, 0, 0, 0
	for token, present := range entries {
		if !present {
			falseEntries++
		}
		if arm64ControlFrameToken(token) {
			frames++
		}
		if arm64ControlFrozenFilter(map[string]bool{token: present}, true)[token] {
			labels++
		}
		if token != "" {
			nonUnknown++
		}
	}
	if node.count != len(entries) || node.falseEntries != falseEntries || node.frames != frames || node.labels != labels || node.nonUnknown != nonUnknown {
		t.Fatal("node summaries differ from every complete original entry")
	}
	if node.split != 0 {
		if node.split&(node.split-1) != 0 || node.left == nil || node.right == nil {
			t.Fatal("invalid compressed branch")
		}
		arm64ControlExactCheckNode(t, node.left)
		arm64ControlExactCheckNode(t, node.right)
	}
	return entries
}

func TestARM64ControlExactForcedCollisionKeepsStringsAndBools(t *testing.T) {
	var root *arm64ControlNode
	expected := make(map[string]bool)
	for index := 0; index < 128; index++ {
		token, present := fmt.Sprintf("label:collision_%03d", index), index%3 != 0
		root = arm64ControlInsert(root, 7, token, present)
		expected[token] = present
	}
	before := arm64ControlExactCheckNode(t, root)
	if !reflect.DeepEqual(before, expected) || arm64ControlLookup(root, 7, "label:collision_missing") {
		t.Fatal("matching hash was used instead of complete string identity")
	}
	changed := arm64ControlInsert(root, 7, "label:collision_000", true)
	if !arm64ControlLookup(changed, 7, "label:collision_000") || arm64ControlLookup(root, 7, "label:collision_000") {
		t.Fatal("bool update mutated a published collision leaf")
	}
	other := arm64ControlInsert(nil, 1<<63, "code-derived:", false)
	other = arm64ControlInsert(other, 7, "label:collision_new", false)
	joined := arm64ControlUnionNodes(root, other)
	want := arm64ControlFrozenUnion(expected, map[string]bool{"code-derived:": false, "label:collision_new": false})
	if !reflect.DeepEqual(arm64ControlExactCheckNode(t, joined), want) || !reflect.DeepEqual(arm64ControlExactCheckNode(t, root), before) {
		t.Fatal("collision union changed full keys/bools or an old root")
	}
	for _, kind := range []arm64ControlProjection{arm64ControlLabelTokens, arm64ControlAddressTokens} {
		got := arm64ControlExactCheckNode(t, arm64ControlProject(joined, kind))
		if !reflect.DeepEqual(got, arm64ControlFrozenFilter(want, kind == arm64ControlLabelTokens)) {
			t.Fatal("collision projection changed full-string semantics")
		}
	}
}

func TestARM64ControlExactOwnershipAndAsymmetricEquality(t *testing.T) {
	input := map[string]bool{"label:one": false, "sp:0": true, "fp:8": false, "": false}
	value := arm64ControlFromMap(input)
	before := arm64ControlMap(value)
	input["label:one"], input["new"] = true, true
	delete(input, "sp:0")
	if !reflect.DeepEqual(arm64ControlMap(value), before) {
		t.Fatal("constructor retained caller-owned mutable input")
	}
	falseValue := arm64ControlFromMap(map[string]bool{"label:one": false})
	trueValue := arm64ControlFromMap(map[string]bool{"label:one": true})
	if !arm64ControlEqual(falseValue, trueValue) || arm64ControlEqual(trueValue, falseValue) || arm64ControlEqual(falseValue, falseValue) {
		t.Fatal("identity shortcut changed old asymmetric equality")
	}
	if empty := arm64ControlUnion(nil, nil); empty == nil || !arm64ControlEqual(nil, empty) {
		t.Fatal("nil/non-nil empty old semantics changed")
	}
	joined := arm64ControlUnion(value, value)
	if !reflect.DeepEqual(arm64ControlMap(joined), arm64ControlFrozenUnion(before, before)) || !reflect.DeepEqual(arm64ControlMap(value), before) {
		t.Fatal("false/frame conflict normalization changed old roots")
	}
	keys := arm64ControlKeys(value)
	if len(keys) != 0 {
		keys[0] = "mutated visitor output"
	}
	if !reflect.DeepEqual(arm64ControlMap(value), before) {
		t.Fatal("visitor leaked a mutable shared slice")
	}
}

func TestARM64ControlExactConcurrentProjection(t *testing.T) {
	input := map[string]bool{"": false, "sp:8": true, "fp:16": false, "code-derived:": false}
	for index := 0; index < 128; index++ {
		input[fmt.Sprintf("label:next_%d", index)] = index%2 == 0
	}
	value := arm64ControlFromMap(input)
	wantLabels, wantAddress := arm64ControlFrozenFilter(input, true), arm64ControlFrozenFilter(input, false)
	var workers sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for iteration := 0; iteration < 32; iteration++ {
				labels, address := arm64ControlLabels(value), arm64ControlAddressTaint(value)
				if !reflect.DeepEqual(arm64ControlMap(labels), wantLabels) || !reflect.DeepEqual(arm64ControlMap(address), wantAddress) {
					t.Error("concurrent projection changed exact original entries")
				}
				derived := arm64ControlWithToken(labels, "new local witness")
				if arm64ControlHas(labels, "new local witness") || !arm64ControlHas(derived, "new local witness") {
					t.Error("concurrent transform mutated shared projection")
				}
			}
		}()
	}
	workers.Wait()
	if !reflect.DeepEqual(arm64ControlMap(value), input) || arm64ControlLabels(value) != arm64ControlLabels(value) || arm64ControlAddressTaint(value) != arm64ControlAddressTaint(value) {
		t.Fatal("projection did not retain immutable per-value ownership")
	}
}

func TestARM64ControlExactInsertionPermutation(t *testing.T) {
	tokens := []string{"", "sp:0", "label:caller", "label:left", "label:right", "code-derived:"}
	var reference arm64ControlValue
	for shift := 0; shift < len(tokens); shift++ {
		var root *arm64ControlNode
		for index := range tokens {
			token := tokens[(index+shift)%len(tokens)]
			root = arm64ControlInsert(root, arm64ControlHash(token), token, true)
		}
		value := &arm64ControlSet{root: root}
		arm64ControlExactCheckNode(t, root)
		if reference == nil {
			reference = value
		} else if !reflect.DeepEqual(root, reference.root) || !arm64ControlEqual(value, reference) || !reflect.DeepEqual(arm64ControlKeys(value), arm64ControlKeys(reference)) {
			t.Fatal("construction order changed exact visitor/target identities")
		}
	}
}
