//go:build go1.27

package plan9asm

import "testing"

// These banks are registered by the actual current SDK, but are bare symbol
// names in Go 1.20. The historical test inventory must not invent their role.
func TestGoAssemblerOracleARM64CurrentSVEFromRegisterRoles(t *testing.T) {
	for _, name := range []string{"Z0", "P0", "PN0"} {
		t.Run(name, func(t *testing.T) {
			source := x86DiagnosticFixture(t, "BL "+name+",R1")
			if goAssemblerOracleARM64SourceDiagnostic(source, "arm64", arm64BranchDiagnostic(source,
				"CALL 0,R1", "ZOREG NONE NONE REG NONE, 3 7")) {
				t.Fatal("registered current-SDK bank borrowed a bare-symbol role")
			}
		})
	}
}
