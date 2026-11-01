package plan9asm

import (
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmoracle"
)

func TestGoAssemblerOracleX86IntegerAliasCompleteDiagnostic(t *testing.T) {
	for _, alias := range []string{"MOVD", "MOVDQ2Q"} {
		for _, row := range []struct{ original, printed string }{
			{"0x0123456789abcdef", "81985529216486895"},
			{"-0x80000001", "-2147483649"},
			{"0xffffffffffffffff", "-1"},
			{"+0xff", "255"},
		} {
			source := x86DiagnosticFixture(t, alias+" $"+row.original+",(DI)")
			output := x86DiagnosticListing(source, "MOVQ $"+row.printed+",(DI)")
			for _, arch := range []string{"386", "amd64"} {
				if !goAssemblerOracleX86SourceDiagnostic(source, arch, output) {
					t.Fatal("complete original alias/integer listing lost its exact source", alias, row, arch)
				}
				for _, changed := range []string{"MOVQ $7,(DI)", "MOVQ $" + row.printed + ",(SI)",
					"MOVQ $(" + row.printed + "),(DI)", "MOVQ $" + row.printed + ",(DI),AX"} {
					if goAssemblerOracleX86SourceDiagnostic(source, arch, x86DiagnosticListing(source, changed)) {
						t.Fatal("changed integer/address/cardinality acquired a diagnostic join", changed)
					}
				}
			}
			if goasmoracle.SourceDiagnosticLine(source, output, 2) ||
				goAssemblerOracleX86SourceDiagnostic(source, "arm64", output) {
				t.Fatal("integer alias escaped the selected x86 adapter")
			}
		}
	}
}
