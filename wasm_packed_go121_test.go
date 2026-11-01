//go:build go1.21

package plan9asm

// wasip1 was introduced in Go 1.21. LLVM objects still cover both wasm
// targets regardless of which Go toolchain supplies the source oracle.
var wasmPackedGoPlatforms = []string{"js", "wasip1"}
