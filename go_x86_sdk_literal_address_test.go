package plan9asm

import (
	"errors"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

// This is an operand-role query, not a live factory or memory certificate.
// The unrelated package/name counterexample keeps the class independent of maps.
func TestGoX86SDKLiteralObservedAddressAndIndexedGrammar(t *testing.T) {
	source := &GoX86NumericalReadSource{request: GoX86NumericalReadCaptureRequest{PackagePath: "example.invalid/tableowner"},
		literals: &numericalSDKLiteralJoin{SourceOrdinal: 0,
			Initializers: sdkReadonlyLiteralDataReport{Initializers: []gostaticstorage.ReadonlyLiteralDataImage{{
				SourceOrdinal: 0, Definition: gostaticstorage.ASMDataDefinition{Name: "numericTable"},
				Initial: make([]byte, 256),
			}}},
		},
	}
	for _, test := range []struct {
		arch, instruction string
		admitted          bool
	}{
		{"amd64", "MOVQ $numericTable<>(SB), AX", true},
		{"amd64", "LEAQ numericTable<>(SB), AX", true},
		{"amd64", "LEAQ numericTable<>+256(SB), AX", true},
		{"386", "MOVL $numericTable<>(SB), AX", true},
		{"386", "LEAL numericTable<>(SB), AX", true},
		{"386", "PAND numericTable<>(SB)(CX*8), X0", true},
		{"386", "PSHUFB numericTable<>(SB)(CX*8), X0", true},
		{"386", "MOVL numericTable<>+4(SB)(BP)(CX*4), AX", true},
		{"amd64", "LEAL numericTable<>(SB), AX", false},
		{"amd64", "MOVL $numericTable<>(SB), AX", false},
		{"amd64", "LEAQ numericTable<>-1(SB), AX", false},
		{"amd64", "LEAQ numericTable<>+257(SB), AX", false},
		{"amd64", "MOVQ $numericTable<>(SB), SP", false},
		{"amd64", "MOVQ $numericTable<>(SB), X0", false},
		{"386", "MOVL AX, numericTable<>(SB)(CX*8)", false},
		{"386", "CALL numericTable<>(SB)(CX*8)", false},
	} {
		t.Run(test.arch+"/"+test.instruction, func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT ·entry(SB),4,$0-0\n"+test.instruction+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			operand := 0
			if test.instruction == "MOVL AX, numericTable<>(SB)(CX*8)" {
				operand = 1
			}
			local, err := source.sdkLiteralRead(file.Funcs[0].Instrs[1], operand, test.arch)
			if !local || test.admitted && err != nil || !test.admitted && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("observed private address/read role changed", local, err)
			}
			if source.ready || source.identity != nil {
				t.Fatal("an operand query forged source or numerical-memory authority")
			}
		})
	}
}
