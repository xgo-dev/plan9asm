package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
)

// This checks only the consistency of the supplied parameter observation.
// Scalar and officially flattened parts are direct arguments; an unflattened
// part must project its exact scalar leaf through the actual aggregate path.
// It authenticates no declaration, physical layout, caller or pointee.
func x86ResultParameterRole(args []LLVMType, slot FrameSlot) (string, bool) {
	if slot.Index < 0 || slot.Index >= len(args) {
		return "", false
	}
	path := frameSlotFields(slot)
	leaf := string(args[slot.Index])
	for _, index := range path {
		var valid bool
		leaf, valid = x86ResultAggregateField(leaf, index)
		if !valid {
			return "", false
		}
	}
	if LLVMType(leaf) != slot.Type {
		return "", false
	}
	return fmt.Sprintf("%d/%v", slot.Index, path), true
}

// Go-derived LLVM aggregates are literal structs and arrays. Select only one
// field, with no allocation proportional to an array's declared length. The
// nested brace/bracket grammar matters: a comma inside a nested struct is not
// a sibling field. Named, packed, vector and malformed types grant no leaf.
func x86ResultAggregateField(typ string, index int) (string, bool) {
	typ = strings.TrimSpace(typ)
	if index < 0 || len(typ) < 2 {
		return "", false
	}
	if typ[0] == '[' && typ[len(typ)-1] == ']' {
		count, element, found := strings.Cut(strings.TrimSpace(typ[1:len(typ)-1]), " x ")
		if !found || count == "" || strings.TrimSpace(element) == "" {
			return "", false
		}
		for _, digit := range count {
			if digit < '0' || digit > '9' {
				return "", false
			}
		}
		n, err := strconv.ParseUint(count, 10, 64)
		if err != nil || uint64(index) >= n {
			return "", false
		}
		return strings.TrimSpace(element), true
	}
	if typ[0] != '{' || typ[len(typ)-1] != '}' {
		return "", false
	}
	inner := typ[1 : len(typ)-1]
	var stack []byte
	start, field := 0, 0
	selected := ""
	for offset := 0; offset <= len(inner); offset++ {
		if offset == len(inner) || inner[offset] == ',' && len(stack) == 0 {
			part := strings.TrimSpace(inner[start:offset])
			if part == "" {
				return "", false
			}
			if field == index {
				selected = part
			}
			field++
			start = offset + 1
			continue
		}
		switch inner[offset] {
		case '{', '[':
			stack = append(stack, inner[offset])
		case '}', ']':
			if len(stack) == 0 || (inner[offset] == '}' && stack[len(stack)-1] != '{') ||
				(inner[offset] == ']' && stack[len(stack)-1] != '[') {
				return "", false
			}
			stack = stack[:len(stack)-1]
		}
	}
	return selected, len(stack) == 0 && selected != ""
}
