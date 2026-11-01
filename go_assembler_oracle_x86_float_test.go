package plan9asm

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
	"github.com/xgo-dev/plan9asm/internal/goasmoracle"
)

// Go's TYPE_FCONST formatter preserves the float64 value, not its source
// spelling. These independent expected strings include signed zero, rounding,
// exponent normalization and unary/parenthesized frontend expressions.
var x86OracleFloatListingCases = []struct{ source, printed string }{
	{"0.0", "0.0"},
	{"-0.0", "-0.0"},
	{"1.25", "1.25"},
	{"1e-50", "1e-50"},
	{"0x1.fp+2", "7.75"},
	{"+(-(-1.25))", "1.25"},
	{"1.0000000000000002", "1.0000000000000002"},
	{"1e20", "1e+20"},
}

func TestGoAssemblerOracleX86AliasFloatCompleteOperandRoles(t *testing.T) {
	for alias, canonical := range goAssemblerOracleX86Aliases {
		t.Run(alias, func(t *testing.T) {
			for _, pair := range [][2]string{
				{"$1.25", "$(1.25)"},
				{"$1.25,X1", "$(1.25),X1"},
				{"X0,$1.25", "X0,$(1.25)"},
				{"$1.25,X1,K1,$-0.0", "$(1.25),X1,K1,$(-0.0)"},
			} {
				source := x86DiagnosticFixture(t, alias+" "+pair[0])
				output := x86DiagnosticListing(source, canonical+" "+pair[1])
				for _, arch := range []string{"amd64", "386"} {
					if !goAssemblerOracleX86SourceDiagnostic(source, arch, output) {
						t.Errorf("%s complete FLOAT alias listing lost: %s %s", arch, alias, pair[0])
					}
				}
				if goasmoracle.SourceDiagnosticLine(source, output, 2) ||
					goAssemblerOracleX86SourceDiagnostic(source, "arm64", output) {
					t.Fatal("FLOAT alias join escaped its explicit x86 observation role")
				}
			}
		})
	}
}

func TestGoAssemblerOracleX86AliasFloatValueAndLexicalBoundaries(t *testing.T) {
	for _, test := range x86OracleFloatListingCases {
		t.Run(test.source, func(t *testing.T) {
			source := x86DiagnosticFixture(t, "MOVD $"+test.source+",X1")
			output := x86DiagnosticListing(source, "MOVQ $("+test.printed+"),X1")
			if !goAssemblerOracleX86SourceDiagnostic(source, "amd64", output) {
				t.Fatal("complete source FLOAT value lost", test)
			}
			for _, changed := range []string{
				"MOVQ $(2.5),X1", "MOVQ $(" + test.printed + "),X2",
				"MOVQ $(" + test.printed + ")", "MOVQ $(" + test.printed + "),X1,K1",
				"MOVQ.Z $(" + test.printed + "),X1", "MOVL $(" + test.printed + "),X1",
			} {
				if goAssemblerOracleX86SourceDiagnostic(source, "amd64", x86DiagnosticListing(source, changed)) {
					t.Fatal("FLOAT join discarded a complete source axis", changed)
				}
			}
		})
	}
	for _, sourceFloat := range []string{"1", "0 . 0", "1.0+0.25", "1.25*1", "NaN", "Inf", "1e309"} {
		source := x86DiagnosticFixture(t, "MOVD $"+sourceFloat+",X1")
		if goAssemblerOracleX86SourceDiagnostic(source, "amd64", x86DiagnosticListing(source, "MOVQ $(1.25),X1")) {
			t.Fatal("non-FLOAT or unresolved expression borrowed TYPE_FCONST", sourceFloat)
		}
	}
	source := x86DiagnosticFixture(t, "MOVD $-0.0,X1")
	for _, printed := range []string{"0.0", "-0", "-0.00", "(-0.0)", "-0.0+0.0"} {
		if goAssemblerOracleX86SourceDiagnostic(source, "amd64", x86DiagnosticListing(source, "MOVQ $("+printed+"),X1")) {
			t.Fatal("noncanonical or sign-changing FLOAT listing accepted", printed)
		}
	}
}

func TestGoAssemblerOracleActualX86AliasFloatFamily(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, alias := range []string{"MOVD", "MOVDQ2Q", "MOVOA"} {
			for _, test := range x86OracleFloatListingCases {
				for _, destination := range []bool{false, true} {
					name := arch + "/" + alias + "/" + test.source + "/from"
					operands := "$" + test.source + ",X1"
					if destination {
						name = strings.TrimSuffix(name, "from") + "to"
						operands = "X0,$" + test.source
					}
					t.Run(name, func(t *testing.T) {
						source := x86DiagnosticFixture(t, alias+" "+operands)
						object := filepath.Join(filepath.Dir(source), "forms.o")
						stage, cancelStage := runtimeOracleStageContext(t)
						defer cancelStage()
						ctx, cancel := context.WithTimeout(stage, time.Minute)
						defer cancel()
						observed, err := goasmcmd.Observe(ctx, filepath.Dir(source),
							append(os.Environ(), "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH="+arch),
							"go", "tool", "asm", "-o", object, source)
						encoded, encodeErr := json.Marshal(observed)
						if encodeErr != nil {
							t.Fatal(encodeErr)
						}
						t.Logf("ORACLE_CHILD %s", encoded)
						if !observed.Waited || observed.ExitCode != 1 || ctx.Err() != nil {
							t.Fatalf("actual original FLOAT refusal absent: %+v %v", observed, err)
						}
						additional := func(source, output string) bool {
							return goAssemblerOracleX86SourceDiagnostic(source, arch, output)
						}
						if failure := goasmoracle.CheckOutcome(source, object, observed.Stdout, observed.Stderr,
							err, ctx.Err(), false, 2, additional); failure != nil {
							t.Fatalf("actual complete FLOAT alias observation lost: %v\n%s", failure, observed.Stderr)
						}
					})
				}
			}
		}
	}
}
