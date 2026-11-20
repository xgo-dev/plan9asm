package plan9asm

import (
	"fmt"
	"go/types"
	"strings"
	"testing"
)

// These fixtures test native instruction/address classification, not numerical
// results or pointee backing. All ordinary inputs are explicitly initialized;
// the unused native read must still retain its original fault/MXCSR effect.
func x86OrdinaryBPNativeFixture(t *testing.T, arch, name, instruction, address string, frame int) (string, FuncSig, GoPackage) {
	t.Helper()
	source := x86OrdinaryBPNativeSource(arch, name, instruction, address, frame)
	pkg := mustGoPackage(t, "sourceframe", "package sourceframe\nfunc "+name+"(p *byte)\n")
	object, ok := pkg.Types.Scope().Lookup(name).(*types.Func)
	if !ok {
		t.Fatal("missing actual typed void declaration", name)
	}
	sig, err := DeriveGoFuncABI0Signature("sourceframe."+name, object, arch, types.SizesFor("gc", arch))
	if err != nil {
		t.Fatal(err)
	}
	return source, sig, pkg
}

func x86OrdinaryBPNativeSource(arch, name, instruction, address string, frame int) string {
	word, move := 8, "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	setup := move + " p+0(FP),AX\nPXOR X0,X0\nPXOR X1,X1\n"
	if arch == "386" {
		if strings.Contains(address, "(BP*") {
			setup += "MOVL $0,BP\n"
		} else if strings.Contains(address, "(BP)") {
			setup += "MOVL AX,BP\n"
		}
	}
	return fmt.Sprintf("TEXT ·%s(SB),4,$%d-%d\n%s%s\nRET\n", name, frame, word, setup, instruction)
}

func x86RequireOrdinaryBPNativeOutcome(t *testing.T, arch, address, ir string, err error) {
	t.Helper()
	// Independent literal matrix expectation: BP is ordinary only in 386 mode.
	// Do not use the production address classifier to derive its own expected result.
	if arch == "386" && strings.Contains(address, "BP") && !strings.Contains(address, "SP") {
		if err != nil {
			t.Fatal("initialized ordinary mode32 BP lost its native opcode", err)
		}
		if !strings.Contains(ir, "asm sideeffect") || !strings.Contains(ir, "~{memory}") {
			t.Fatal("dead numerical output erased the original native memory effect")
		}
		return
	}
	x86LegacyFloatMemoryRequireContext(t, err)
}
