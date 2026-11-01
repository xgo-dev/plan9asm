package plan9asm

import (
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmoracle"
)

func arm64BranchDiagnostic(source, listing, classes string) string {
	return "asm: illegal combination: 00000 (" + source + ":2) " + listing + " " + classes + "\n"
}

func TestGoAssemblerOracleARM64CompleteBranchListingRoles(t *testing.T) {
	for _, alias := range []struct{ source, listing string }{{"B", "JMP"}, {"BL", "CALL"}} {
		t.Run(alias.source, func(t *testing.T) {
			source := x86DiagnosticFixture(t, alias.source+" R0")
			for class := range goAssemblerOracleARM64Classes {
				for position := 0; position < 5; position++ {
					classes := []string{"NONE", "NONE", "NONE", "REG", "NONE"}
					classes[position] = class
					output := arm64BranchDiagnostic(source, alias.listing+" R0", strings.Join(classes, " ")+", 0 7")
					if !goAssemblerOracleARM64SourceDiagnostic(source, "arm64", output) {
						t.Fatalf("complete DRconv class %s/%d lost", class, position)
					}
					if goasmoracle.SourceDiagnosticLine(source, output, 2) {
						t.Fatal("default diagnostic acquired ARM64 aliases")
					}
				}
			}
			for kind := 0; kind <= 14; kind++ {
				for _, types := range []string{fmt.Sprintf("%d 7", kind), fmt.Sprintf("0 %d", kind)} {
					if !goAssemblerOracleARM64SourceDiagnostic(source, "arm64",
						arm64BranchDiagnostic(source, alias.listing+" R0", "NONE NONE NONE REG NONE, "+types)) {
						t.Fatalf("complete AddrType ordinal lost: %s", types)
					}
				}
			}
			for _, suffix := range []struct{ source, listing string }{
				{"", ""}, {".P", ".P"}, {".W", ".W"}, {".P.W", ".P.W"},
				{".W.P", ".P.W"}, {".P.P", ".P"}, {".W.P.W", ".P.W"},
			} {
				for _, args := range []string{"", "R0", "(V0)", "$1", "8(R1)", "R0,R1", "R0,R1,R2", "R0,R1,R2,R3"} {
					fixture := x86DiagnosticFixture(t, strings.TrimSpace(alias.source+suffix.source+" "+args))
					if !goAssemblerOracleARM64SourceDiagnostic(fixture, "arm64", arm64BranchDiagnostic(fixture,
						strings.TrimSpace(alias.listing+suffix.listing+" "+args), "NONE NONE NONE REG NONE, 0 7")) {
						t.Fatalf("complete alias suffix/cardinality lost: %s %s", suffix.source, args)
					}
				}
			}
		})
	}
}

func TestGoAssemblerOracleARM64BranchListingRejectsUnboundMetadata(t *testing.T) {
	source := x86DiagnosticFixture(t, "BL R0")
	// Go 1.20 prints four complete DRconv classes; current Go prints five.
	// Both are diagnostic schemas, not accepted instruction or ABI authority.
	for _, schema := range []struct{ name, tail string }{
		{"historical_four", "NONE NONE NONE REG, 0 7"},
		{"historical_four_reg_third", "NONE NONE REG NONE, 0 7"},
		{"current_five", "NONE NONE NONE REG NONE, 0 7"},
	} {
		t.Run(schema.name, func(t *testing.T) {
			if !goAssemblerOracleARM64SourceDiagnostic(source, "arm64", arm64BranchDiagnostic(source, "CALL R0", schema.tail)) {
				t.Fatalf("complete diagnostic schema lost: %q", schema.tail)
			}
		})
	}

	for _, tail := range []string{
		"", "NONE NONE REG, 0 7", "NONE NONE NONE REG NONE NONE, 0 7",
		"NONE NONE NONE C_?? NONE, 0 7", "NONE NONE NONE UNKNOWN NONE, 0 7",
		"NONE NONE NONE REG NONE, -1 7", "NONE NONE NONE REG NONE, 15 7",
		"NONE NONE NONE REG NONE, 0 15", "NONE NONE NONE REG NONE, 00 7",
		"NONE NONE NONE REG NONE, +0 7", "NONE NONE NONE REG NONE, 0 7 extra",
	} {
		if goAssemblerOracleARM64SourceDiagnostic(source, "arm64", arm64BranchDiagnostic(source, "CALL R0", tail)) {
			t.Errorf("malformed/unmodeled metadata bound: %q", tail)
		}
	}
	output := arm64BranchDiagnostic(source, "CALL R0", "NONE NONE NONE REG NONE, 0 7")
	for _, changed := range []string{
		strings.Replace(output, "CALL R0", "CALL R1", 1),
		strings.Replace(output, "CALL R0", "CALL", 1),
		strings.Replace(output, "CALL R0", "JMP R0", 1),
		strings.Replace(output, "CALL R0", "CALL.P R0", 1),
		strings.Replace(output, "illegal combination:", "invalid instruction:", 1),
		strings.Replace(output, "00000", "0", 1),
		strings.Replace(output, source+":2", source+":3", 1),
		strings.Replace(output, source+":2", "foreign"+source+":2", 1),
	} {
		if goAssemblerOracleARM64SourceDiagnostic(source, "arm64", changed) {
			t.Errorf("alias escaped exact source/backend/operand boundary: %q", changed)
		}
	}
	for _, arch := range []string{"386", "amd64", "arm", "wasm", ""} {
		if goAssemblerOracleARM64SourceDiagnostic(source, arch, output) {
			t.Errorf("alias escaped target: %q", arch)
		}
	}
}
