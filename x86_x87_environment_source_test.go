package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

// This is the complete original source from the host-gated software status
// oracle, not a manufactured word initializer or an environment permission.
// Keep it independently visible on hosts that cannot execute the old oracle.
func TestX86X87SoftwareEnvironmentClearCompleteSourceThreeAPIs(t *testing.T) {
	const source = `TEXT clearModeledStatus(SB),4,$0-16
MOVQ env+0(FP),BX
FLDENV (BX)
BYTE $0xdb; BYTE $0xe2
XORL AX,AX
FSTSW AX
MOVQ AX,ret+8(FP)
RET
`
	for _, triple := range []string{
		"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc",
	} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(triple+"/"+api, func(t *testing.T) {
				ir, err := x86X87InitializedWordAPI(t, source, "func clearModeledStatus(env *byte) uint64",
					"amd64", triple, api, X87Software)
				if !errors.Is(err, ErrProbeNeedsContext) || ir != "" ||
					!strings.Contains(err.Error(), "logical x87 value stack is not balanced at RET") {
					t.Fatal("original environment supplied an unobserved empty Tag/TOP at RET", err)
				}
				// The separately named bounded counterpart adds a real FINIT
				// only after capturing/writing the result. Its successful
				// objects and runtime oracle do not certify this old source.
			})
		}
	}
}
