//go:build go1.27

package plan9asm

import (
	"strings"
	"testing"
)

func TestX86UnsignedScalarIntegerFloatExistingCompleteOwnersRemainFirst(t *testing.T) {
	owners := x86CaptureNativeFamilyOwnerOracle(t)
	for _, member := range x86UnsignedScalarIntegerFloatOracle {
		for _, kind := range []string{"GP", "FP", "native"} {
			t.Run(member.op+"/"+kind, func(t *testing.T) {
				row := x86UnsignedScalarIntegerFloatRow{op: member.op, source: kind, input: member.input, output: member.output, destination: 1}
				source, declaration, name := x86UnsignedScalarIntegerFloatProgram(0, row, "amd64")
				source = strings.Replace(source, "·"+name+"(SB)", "·Value(SB)", 1)
				declaration = strings.Replace(declaration, "func "+name+"(", "func Value(", 1)
				owners.checkProgram(t, source, declaration, row.instruction())
			})
		}
	}
}
