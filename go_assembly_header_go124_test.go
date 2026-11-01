//go:build go1.24

package plan9asm

import "testing"

// Generic aliases became a Go source-language feature in 1.24. The common
// oracle still runs every supported architecture on Go 1.20; this additional
// source fixture belongs only to toolchains that actually accept its syntax.
func TestGoAssemblyHeaderGenericAliasCompileOracle(t *testing.T) {
	// The module retains Go 1.20 defaults. Go 1.24-1.26's go/types otherwise
	// defaults to gotypesalias=0 even though their compiler accepts aliases.
	// This fixture explicitly exercises the source language's alias objects.
	t.Setenv("GODEBUG", "gotypesalias=1")
	testGoAssemblyHeaderCompileOracle(t, `package header
const Huge = 1234567890123456789012345678901234567890
const Fraction = 1.25
type Generic[T any] struct { first byte; Value T }
type GenericAlias[T any] = Generic[T]
type Concrete = GenericAlias[uint64]
type Alias = Concrete
`)
}
