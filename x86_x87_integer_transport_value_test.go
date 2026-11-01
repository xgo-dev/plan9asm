package plan9asm

import (
	"fmt"
	"testing"
)

// An integer is an x87 value, not a remembered adjacent load/store pair.
// Observe it after the shared stack operations and a source-authored join.
func TestX86X87SignedIntegerValuesSurviveWholeStackTransport(t *testing.T) {
	const declaration = "func Value(input int64) int64"
	for _, target := range x86RawReturnTargets {
		for _, row := range []struct{ name, body string }{
			{"copy-pop-exchange", `FMOVV input+0(FP),F0
FLD1
FXCHD F1,F0
FMOVDP F0,F1
FMOVVP F0,ret+8(FP)
RET`},
			{"conditional-and-join", `FINIT
FMOVV input+0(FP),F0
FLD1
MOVL $0,AX
CMPL AX,AX
FCMOVEQ F1,F0
JE joined
FXCHD F1,F0
joined:
FMOVDP F0,F1
FRNDINT
FMOVVP F0,ret+8(FP)
RET`},
		} {
			t.Run(target.triple+"/"+row.name, func(t *testing.T) {
				_, _, _, source := x86ResultInitializationFixture(t, target.arch, declaration, row.body)
				ir, err := x86X87InitializedWordAPI(t, source, declaration, target.arch, target.triple, "text", X87Software)
				if err != nil || ir == "" {
					t.Fatal("whole source did not reach the integer value observation", err)
				}
				ir = x86X87InlineActualValue(t, ir, "i64", 64)
				for _, input := range x86X87SignedI64IdentityInputs {
					t.Run(fmt.Sprintf("input=%016x", uint64(input)), func(t *testing.T) {
						probe := ir + fmt.Sprintf("\ndefine i64 @TransportProbe() {\n %%r = call i64 @Value(i64 %d)\n ret i64 %%r\n}\n", input)
						x86ScalarFPNamedConstantResult(t, probe, "TransportProbe", []uint64{uint64(input)})
					})
				}
			})
		}
	}
}
