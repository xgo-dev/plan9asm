// Package goabi describes the source Go stack layout, independently of the
// LLVM target's pointer width or the host running the translator.
package goabi

import "math"

// ABI0StackSize includes the trailing register-size alignment added by
// cmd/compile/internal/abi.ABIAnalyzeFuncType. dataSize is the end of the last
// declared parameter/result, which asmdecl reports without that alignment.
// Padding is allocation metadata, not a new parameter or result field.
func ABI0StackSize(goarch string, dataSize int64) (int64, bool) {
	var alignment int64
	switch goarch {
	case "386", "arm":
		alignment = 4
	case "amd64", "arm64", "wasm":
		// Go's wasm register/stack word is eight bytes even though the LLVM
		// wasm32 address space uses four-byte pointers.
		alignment = 8
	default:
		return 0, false
	}
	if dataSize < 0 || dataSize > math.MaxInt64-(alignment-1) {
		return 0, false
	}
	return (dataSize + alignment - 1) &^ (alignment - 1), true
}

// MatchesABI0TextSize accepts the logical data end or the actual aligned ABI0
// allocation, never arbitrary extra bytes. Legacy omitted/zero TEXT metadata
// is a separate convention handled by callers.
func MatchesABI0TextSize(goarch string, declared, dataSize int64) bool {
	padded, ok := ABI0StackSize(goarch, dataSize)
	return ok && (declared == dataSize || declared == padded)
}
