package plan9asm

import (
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmoracle"
)

func x86Mode32Diagnostic(source, listing, classes string) string {
	return "asm: asmins: illegal in mode 32: 00000 (" + source + ":2) " + listing + " " + classes + "\n"
}

func TestGoAssemblerOracleX86Mode32ClassTailRoles(t *testing.T) {
	source := x86DiagnosticFixture(t, "PADDD X0,X8")
	for class := 0; class < 90; class++ {
		for _, pair := range []string{fmt.Sprintf("(%d 66)", class), fmt.Sprintf("(64 %d)", class)} {
			output := x86Mode32Diagnostic(source, "PADDL X0,X8", pair)
			if !goAssemblerOracleX86SourceDiagnostic(source, "386", output) {
				t.Errorf("complete class-tail listing lost: %s", pair)
			}
			if goasmoracle.SourceDiagnosticLine(source, output, 2) {
				t.Fatal("default diagnostic parser acquired x86 alias/class-tail authority")
			}
		}
	}

	for _, tail := range []string{
		"", "(64)", "(64 66 0)", "(64,66)", "(64 66", "64 66)",
		"(-1 66)", "(90 66)", "(64 90)", "(+64 66)", "(064 66)",
		"(0x40 66)", "(64 6.6)", "(64 66) extra", "(64 66) (64 66)",
	} {
		if goAssemblerOracleX86SourceDiagnostic(source, "386", x86Mode32Diagnostic(source, "PADDL X0,X8", tail)) {
			t.Errorf("malformed/unknown class tail accepted: %q", tail)
		}
	}
	output := x86Mode32Diagnostic(source, "PADDL X0,X8", "(64 66)")
	for _, changed := range []string{
		strings.Replace(output, "illegal in mode 32", "illegal in mode 64", 1),
		strings.Replace(output, "asmins: illegal in mode 32", "invalid instruction", 1),
		strings.Replace(output, "(64 66)", "(64 66); NOP", 1),
		strings.Replace(output, "PADDL X0,X8", "PADDL X0,X9", 1),
		strings.Replace(output, "PADDL X0,X8", "PADDL X0", 1),
		strings.Replace(output, "00000", "0", 1),
		strings.Replace(output, source+":2", source+":3", 1),
		strings.Replace(output, source+":2", "foreign"+source+":2", 1),
	} {
		if goAssemblerOracleX86SourceDiagnostic(source, "386", changed) {
			t.Errorf("class tail escaped original source/backend boundary: %q", changed)
		}
	}
	for _, arch := range []string{"amd64", "arm", "arm64", "wasm", ""} {
		if goAssemblerOracleX86SourceDiagnostic(source, arch, output) {
			t.Errorf("386 mode diagnostic borrowed another architecture: %q", arch)
		}
	}
}
