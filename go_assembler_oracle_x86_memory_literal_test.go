package plan9asm

import (
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmoracle"
)

func TestGoAssemblerOracleX86AliasMemoryDisplacementListing(t *testing.T) {
	// Complete alias directory, literal displacement rendering and both SIB
	// shapes. These fabricated observations are not instruction acceptance.
	for alias, canonical := range goAssemblerOracleX86Aliases {
		t.Run(alias, func(t *testing.T) {
			for _, displacement := range []struct{ original, printed string }{
				{"0", ""}, {"+0", ""}, {"-0", ""}, {"0x0", ""},
				{"0x10", "16"}, {"-0x10", "-16"}, {"017", "15"},
				{"0xffffffffffffffff", "-1"}, {"0b101", "5"}, {"1_024", "1024"},
			} {
				for _, address := range []string{"", "(AX)", "(AX)(CX*2)", "(CX*2)"} {
					source := x86DiagnosticFixture(t, alias+" "+displacement.original+address+",X1")
					printed := displacement.printed
					if printed == "" && (address == "" || address == "(CX*2)") {
						printed = "0"
					}
					instruction := canonical + " " + printed + address + ",X1"
					for _, arch := range []string{"386", "amd64"} {
						output := x86DiagnosticListing(source, instruction)
						if !goAssemblerOracleX86SourceDiagnostic(source, arch, output) {
							t.Fatal("complete alias and displacement rendering lost its exact source", arch, displacement, address)
						}
						if goasmoracle.SourceDiagnosticLine(source, output, 2) {
							t.Fatal("target-free parser acquired an x86 alias/displacement role")
						}
						for _, changed := range []string{
							canonical + " 7" + address + ",X1",
							canonical + " " + displacement.printed + "(DX),X1",
							canonical + " " + displacement.printed + address + ",X2",
							canonical + " " + displacement.printed + address + ",X1,X2",
						} {
							if goAssemblerOracleX86SourceDiagnostic(source, arch, x86DiagnosticListing(source, changed)) {
								t.Fatal("changed address, value or cardinality borrowed the displacement role", changed)
							}
						}
					}
					if !goAssemblerOracleX86SourceDiagnostic(source, "386", x86Mode32Diagnostic(source, instruction, "(24 21)")) ||
						goAssemblerOracleX86SourceDiagnostic(source, "arm64", x86DiagnosticListing(source, instruction)) {
						t.Fatal("displacement rendering lost its explicit mode/target boundary")
					}
				}
			}
		})
	}
	for _, original := range []string{
		"0(FP)", "0(SP)", "0(SB)", "local+0(SP)", "value(AX)", "0+0(AX)",
		"0.0(AX)", "0(UNKNOWN)", "0(AX)(CX*3)", "0(AX)(CX*2)(DX*4)", "$0(AX)",
	} {
		source := x86DiagnosticFixture(t, "MOVBEQQ "+original+",BX")
		for _, arch := range []string{"386", "amd64"} {
			if goAssemblerOracleX86SourceDiagnostic(source, arch, x86DiagnosticListing(source, "MOVBEQ (AX),BX")) {
				t.Fatal("literal displacement joined a symbol, expression, pseudo-frame or unknown address", original)
			}
		}
	}
}

func TestGoAssemblerOracleActualMOVBEAliasMemoryRejections(t *testing.T) {
	for _, alias := range []string{"MOVBEWW", "MOVBELL", "MOVBEQQ"} {
		for _, operands := range []string{"0(AX),X0", "X0,0(AX)"} {
			t.Run(alias+"/"+operands, func(t *testing.T) {
				goAssemblerOracleOutput(t, "386", "TEXT bad(SB),4,$0-0\n"+alias+" "+operands+"\nRET\n", "", false)
			})
		}
	}
}
