package plan9asm

import "testing"

func TestARM64NativeScratchActualABIRoleIdentity(t *testing.T) {
	_, pkg, _, _, source := arm64ScratchActualBoundSource(t, "linux", "aarch64-unknown-linux-gnu")
	t.Logf("actual selected ABI definitions: %+v", source.abis)
	for _, name := range []string{"Scratch", "Value"} {
		symbol := pkg.Path + "." + name
		if source.abis[symbol] != "ABI0" {
			t.Errorf("actual source ABI definition lost exact symbol %q: %q", symbol, source.abis[symbol])
		}
	}
}
