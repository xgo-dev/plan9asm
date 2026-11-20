package plan9asm

import "testing"

func TestX86PackedIntegerCompareBuildOnlyNeverExecutesTestMain(t *testing.T) {
	const declaration = "package oracle\nfunc LinkedAssembly()\n"
	const assembly = "TEXT ·LinkedAssembly(SB),4,$0-0\nRET\n"
	const source = `package oracle

import (
    "os"
    "testing"
)

func TestMain(m *testing.M) {
    os.Exit(97)
}

func TestRequiresAssemblyLink(t *testing.T) {
    LinkedAssembly()
}
`
	// Even -run=^$ executes TestMain and process initialization. A compile/link
	// owner must never run either, on the host or through a cross executor.
	x86PackedIntegerCompareOriginalGoDriver(t, declaration, assembly, source, true)
}
