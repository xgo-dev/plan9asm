package plan9asm

import (
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

// These map operations are the frozen old semantics. They intentionally keep
// false entries, nil/empty distinctions and the asymmetric equality rule.
func arm64ControlFrozenUnion(left, right map[string]bool) map[string]bool {
	value := make(map[string]bool, len(left)+len(right))
	for token := range left {
		value[token] = true
	}
	for token := range right {
		value[token] = true
	}
	frame := ""
	for token := range value {
		if strings.HasPrefix(token, "sp:") || strings.HasPrefix(token, "fp:") {
			if frame != "" && frame != token {
				for candidate := range value {
					if strings.HasPrefix(candidate, "sp:") || strings.HasPrefix(candidate, "fp:") {
						delete(value, candidate)
					}
				}
				value[""] = true
				break
			}
			frame = token
		}
	}
	return value
}

func arm64ControlFrozenEqual(left, right map[string]bool) bool {
	if len(left) != len(right) {
		return false
	}
	for token := range left {
		if !right[token] {
			return false
		}
	}
	return true
}

func arm64ControlFrozenFilter(value map[string]bool, labels bool) map[string]bool {
	result := make(map[string]bool)
	for token := range value {
		selected := token != ""
		if labels {
			selected = strings.HasPrefix(token, "label:") || token == "code-derived:"
		}
		if selected {
			result[token] = true
		}
	}
	return result
}

func arm64ControlFrozenWithToken(value map[string]bool, token string) map[string]bool {
	if value[token] {
		return value
	}
	result := make(map[string]bool, len(value)+1)
	for old, present := range value {
		result[old] = present
	}
	result[token] = true
	return result
}

func arm64ControlExactReferenceMap(value arm64ControlValue) map[string]bool {
	if value == nil {
		return nil
	}
	result := make(map[string]bool, arm64ControlCount(value))
	for token, present := range arm64ControlMap(value) {
		result[token] = present
	}
	return result
}

func arm64ControlExactReferenceValue(value map[string]bool) arm64ControlValue {
	if value == nil {
		return nil
	}
	result := arm64ControlFromMap(make(map[string]bool, len(value)))
	for token, present := range value {
		result = arm64ControlSetToken(result, token, present)
	}
	return result
}

func TestARM64ControlExactFrozenMapOperations(t *testing.T) {
	tokens := []string{"", "label:caller", "label:next", "code-derived:", "sp:0", "sp:8", "fp:0", "fpa:8", "invalid", "label:", "sp:invalid"}
	values := []map[string]bool{nil, {}}
	random := rand.New(rand.NewSource(917))
	for sample := 0; sample < 96; sample++ {
		value := make(map[string]bool)
		for _, token := range tokens {
			if choice := random.Intn(3); choice != 0 {
				value[token] = choice == 2
			}
		}
		values = append(values, value)
	}
	for leftIndex, left := range values {
		for rightIndex, right := range values {
			a, b := arm64ControlExactReferenceValue(left), arm64ControlExactReferenceValue(right)
			beforeA, beforeB := arm64ControlExactReferenceMap(a), arm64ControlExactReferenceMap(b)
			got := arm64ControlExactReferenceMap(arm64ControlUnion(a, b))
			if want := arm64ControlFrozenUnion(left, right); !reflect.DeepEqual(got, want) {
				t.Fatalf("union %d/%d: got %v, want %v", leftIndex, rightIndex, got, want)
			}
			if arm64ControlEqual(a, b) != arm64ControlFrozenEqual(left, right) {
				t.Fatalf("asymmetric equality %d/%d changed", leftIndex, rightIndex)
			}
			if !reflect.DeepEqual(arm64ControlExactReferenceMap(a), beforeA) || !reflect.DeepEqual(arm64ControlExactReferenceMap(b), beforeB) {
				t.Fatalf("operation %d/%d mutated a published predecessor", leftIndex, rightIndex)
			}
		}
		value := arm64ControlExactReferenceValue(left)
		for _, labels := range []bool{false, true} {
			got := arm64ControlAddressTaint(value)
			if labels {
				got = arm64ControlLabels(value)
			}
			if !reflect.DeepEqual(arm64ControlExactReferenceMap(got), arm64ControlFrozenFilter(left, labels)) {
				t.Fatalf("projection %d/%t changed complete token/bool semantics", leftIndex, labels)
			}
		}
		for _, token := range tokens {
			got := arm64ControlWithToken(value, token)
			if !reflect.DeepEqual(arm64ControlExactReferenceMap(got), arm64ControlFrozenWithToken(left, token)) {
				t.Fatalf("copy-on-write %d/%q changed complete token/bool semantics", leftIndex, token)
			}
			if !reflect.DeepEqual(arm64ControlExactReferenceMap(value), left) {
				t.Fatalf("copy-on-write %d/%q modified its old root", leftIndex, token)
			}
		}
	}
}
