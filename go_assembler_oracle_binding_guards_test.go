package plan9asm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGoAssemblerOracleSourcePositionAndStatementGuards(t *testing.T) {
	source := filepath.Join(t.TempDir(), "probe.s")
	if err := os.WriteFile(source, []byte("#include \"textflag.h\"\nTEXT probe(SB),$0-0\n\tMOVD R0,R1\n\tRET\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, diagnostic string
	}{
		{"foreign-prefix", "foreign" + source + ":3: bad operand\n"},
		{"out-of-range-line", source + ":9999: bad operand\n"},
		{"blank-line", source + ":5: bad operand\n"},
		{"preprocessor-header", source + ":1: bad operand\n"},
		{"out-of-range-column", source + ":3:9999: bad operand\n"},
		{"wrong-listing-opcode", "asm: illegal combination: 00000 (" + source + ":3) MOVK $65537,R0\n"},
		{"noncanonical-listing-PC", "asm: illegal combination: 000000 (" + source + ":3) MOVD R0,R1\n"},
		{"foreign-listing-prefix", "foreign asm: illegal combination: 00000 (" + source + ":3) MOVD R0,R1\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if goAssemblerOracleSourceDiagnostic(source, test.diagnostic) {
				t.Fatalf("unbound source diagnostic accepted: %q", test.diagnostic)
			}
		})
	}
	if !goAssemblerOracleSourceDiagnostic(source, "asm: illegal combination: 00000 ("+source+":3) MOVD R0,R1\n") {
		t.Fatal("exact Go listing lost its source statement")
	}
}
