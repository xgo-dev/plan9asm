package gotoolprofile

import (
	"path"
	"strings"
)

// AssemblySourceByteLimit bounds a complete generated assembly file or its
// expansion. It is a resource budget, not source, ABI or object authority.
// Go files and ordinary headers retain their smaller existing byte bounds.
const AssemblySourceByteLimit = 8 << 20

func instrumentationOriginalSourceByteLimit(name string) int {
	if path.Ext(name) == ".s" {
		return AssemblySourceByteLimit
	}
	return instrumentationOriginalFileLimit
}

// InstrumentationCPPInputByteLimit shares the producer/replay byte bound.
// Only original module assembly gets the larger allowance; tool, generated
// and module headers retain their independent limit. Origin authentication,
// complete input accounting and hash agreement are still required separately.
func InstrumentationCPPInputByteLimit(origin string) int {
	kind, name, present := strings.Cut(origin, "/")
	if present && kind == "module" {
		return instrumentationOriginalSourceByteLimit(name)
	}
	return instrumentationOriginalFileLimit
}
