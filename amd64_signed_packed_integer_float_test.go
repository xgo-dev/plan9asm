package plan9asm

import (
	"strings"
	"testing"
)

func TestX86SignedPackedIntegerFloatOriginalCaller(t *testing.T) {
	const body = "VMOVUPS (DI),Y0\nVCVTDQ2PS Y0,Y1\nVMOVSS X1,(DX)"
	assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
	goAssemblerOracleOutput(t, "amd64", assembly, "", true)
	pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
	if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
		t.Fatal(err)
	}
}
