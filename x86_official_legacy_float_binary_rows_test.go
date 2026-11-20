package plan9asm

import (
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func x86OfficialLegacyFloatingAssembly(cases []x86OfficialPackedCase, arch string) (string, string) {
	source, declaration := x86OfficialPackedAssembly(cases)
	if arch == "386" {
		// Three pointers plus the existing uint64 mask occupy20 ABI0 bytes.
		// All literal instructions, vector seeds and result stores are shared.
		source = strings.NewReplacer(
			",$0-32\n", ",$0-20\n",
			"MOVQ out+0(FP),DX\n", "MOVL out+0(FP),DX\n",
			"MOVQ a+8(FP),AX\n", "MOVL a+4(FP),AX\n",
			"MOVQ b+16(FP),BX\n", "MOVL b+8(FP),BX\n",
		).Replace(source)
	}
	return source, declaration
}

// The existing-producer baseline and this row-owned version keep the same
// complete48 instructions/initialized sources per mode. Actual source row IDs
// and strict whole-function Go byte verification are added here.
func TestX86LegacyFloatingBinaryExistingObservableProducer(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, mode := range []struct{ arch, triple string }{
		{"amd64", "x86_64-unknown-linux-gnu"},
		{"386", "i386-unknown-linux-gnu"},
	} {
		t.Run(mode.arch, func(t *testing.T) {
			x86OfficialPackedRowsObjectsForTarget(t, mode.arch, mode.triple,
				goasmrules.X86LegacyFloatingBinaryRows, 24, 48, 0,
				func(cases []x86OfficialPackedCase) (string, string) {
					return x86OfficialLegacyFloatingAssembly(cases, mode.arch)
				},
				func(t *testing.T, ir string, _ []x86OfficialPackedCase) {
					x86PackedStringCompileObject(t, llc, mode.triple, ir, "-O2")
				})
		})
	}
}
