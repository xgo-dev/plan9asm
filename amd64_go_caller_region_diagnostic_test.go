package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

func TestX86GoCallerRegionRejectedEffectsRetainInstructionDiagnostic(t *testing.T) {
	for _, example := range []struct {
		name, replacement, diagnostic string
	}{
		{
			name: "uninitialized vector arithmetic", replacement: "VFMADD231SS (DI),X0,X1\nVMOVSS X1,(DX)",
			diagnostic: "unproved caller-region effect: VFMADD231SS",
		},
		{
			name: "pointer as scalar data", replacement: "MOVL DI,(DX)",
			diagnostic: "unproved caller-region effect: MOVL",
		},
		{
			name:        "different input origins",
			replacement: "CMPQ AX,$0\nJE joined\nMOVQ SI,DI\nCMPQ AX,$0\njoined:\nMOVL AX,(DX)",
			diagnostic:  "different source-stack or caller-region states at join",
		},
	} {
		t.Run(example.name, func(t *testing.T) {
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", example.replacement, 1)
			requireX86GoAssemblerResult(t, "amd64", assembly, true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu")
			if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), example.diagnostic) {
				t.Fatalf("source rejection lost its actual instruction/state cause: %v", err)
			}
		})
	}
}
