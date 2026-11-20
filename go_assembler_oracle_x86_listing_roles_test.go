package plan9asm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmoracle"
)

func x86DiagnosticFixture(t *testing.T, statement string) string {
	t.Helper()
	source := filepath.Join(t.TempDir(), "forms.s")
	if err := os.WriteFile(source, []byte("TEXT probe(SB),$0-0\n"+statement+"\nRET\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return source
}

func x86DiagnosticListing(source, listing string) string {
	return "asm: bad: invalid instruction: 00000 (" + source + ":2)\t" + listing + "\n"
}

// These fabricated-output joins test the diagnostic adapter, not Go acceptance.
func TestGoAssemblerOracleX86CompleteAliasListingRoles(t *testing.T) {
	for alias, canonical := range goAssemblerOracleX86Aliases {
		t.Run(alias, func(t *testing.T) {
			for _, arch := range []string{"amd64", "386"} {
				for _, suffix := range []string{"", ".Z", ".SAE", ".SAE.Z", ".RN_SAE", ".RZ_SAE", ".RD_SAE", ".RU_SAE",
					".RN_SAE.Z", ".RZ_SAE.Z", ".RD_SAE.Z", ".RU_SAE.Z", ".BCST", ".BCST.Z"} {
					source := x86DiagnosticFixture(t, alias+suffix+" 8(AX)(CX*2), X1")
					listing := x86DiagnosticListing(source, canonical+suffix+" 8(AX)(CX*2), X1")
					if !goAssemblerOracleX86SourceDiagnostic(source, arch, listing) {
						t.Fatalf("complete alias lost for %s/%s%s", arch, alias, suffix)
					}
					if goasmoracle.SourceDiagnosticLine(source, listing, 2) {
						t.Fatal("default parser acquired a global alias role")
					}
					for _, changed := range []string{canonical + suffix + " 8(AX)(CX*2), X2", canonical + " 8(AX)(CX*2), X1, X2", canonical + suffix} {
						if goAssemblerOracleX86SourceDiagnostic(source, arch, x86DiagnosticListing(source, changed)) {
							t.Fatalf("changed/truncated complete alias listing acquired a role: %q", changed)
						}
					}
					for _, other := range []string{"", "arm", "arm64", "wasm", "AMD64"} {
						if goAssemblerOracleX86SourceDiagnostic(source, other, listing) {
							t.Fatalf("alias acquired unknown/foreign target %q", other)
						}
					}
				}
			}
		})
	}
}

func TestGoAssemblerOracleX86CompleteAliasOperandCardinality(t *testing.T) {
	for alias, canonical := range goAssemblerOracleX86Aliases {
		t.Run(alias, func(t *testing.T) {
			for _, suffix := range []string{"", ".Z", ".BCST.Z"} {
				for _, operands := range []string{"", "AX", "M0,X1", "X0,K1,X1", "X0,X1,K1,X2"} {
					source := x86DiagnosticFixture(t, strings.TrimSpace(alias+suffix+" "+operands))
					listing := x86DiagnosticListing(source, strings.TrimSpace(canonical+suffix+" "+operands))
					for _, arch := range []string{"amd64", "386"} {
						if !goAssemblerOracleX86SourceDiagnostic(source, arch, listing) {
							t.Errorf("complete %s alias lost at operand cardinality %q: %s", arch, operands, alias+suffix)
						}
						if operands != "" && goAssemblerOracleX86SourceDiagnostic(source, arch,
							x86DiagnosticListing(source, canonical+suffix)) {
							t.Fatal("operand-bearing original borrowed a zero-operand listing")
						}
						if operands == "" && goAssemblerOracleX86SourceDiagnostic(source, arch,
							x86DiagnosticListing(source, canonical+suffix+" AX")) {
							t.Fatal("zero-operand original borrowed an invented operand")
						}
					}
					if goasmoracle.SourceDiagnosticLine(source, listing, 2) {
						t.Fatal("zero/rest-operand alias escaped into the strict default")
					}
				}
			}
		})
	}
}

func TestGoAssemblerOracleX86ScalarZeroCompleteListingRoles(t *testing.T) {
	for _, opcode := range []string{"MOVSS", "MOVSD", "VMOVSS", "VMOVSD"} {
		t.Run(opcode, func(t *testing.T) {
			for _, test := range []struct {
				name, suffix, operands, listing string
				want                            bool
			}{
				{"two", "", "$0.0,X0", "X0,X0", true},
				{"three", "", "$0.0,K1,X0", "X0,K1,X0", true},
				{"four", "", "$0.0,X1,K1,X0", "X0,X1,K1,X0", true},
				{"suffix", ".Z", "$0.0,X1,K7,X15", "X15,X1,K7,X15", true},
				{"unary-parentheses", "", "$+(-( -0.0)),K1,X0", "X0,K1,X0", true},
				{"negative-zero", "", "$-0.0,K1,X0", "X0,K1,X0", false},
				{"nonzero", "", "$1.0,K1,X0", "X0,K1,X0", false},
				{"float32-underflow", "", "$1e-50,K1,X0", "X0,K1,X0", false},
				{"integer-zero", "", "$0,K1,X0", "X0,K1,X0", false},
				{"invented-float-token", "", "$0 . 0,K1,X0", "X0,K1,X0", false},
				{"binary-expression", "", "$0.0+0.0,K1,X0", "X0,K1,X0", false},
				{"high-destination", "", "$0.0,K1,X16", "X16,K1,X16", false},
				{"noncanonical-register", "", "$0.0,K1,X00", "X00,K1,X00", false},
				{"memory-destination", "", "$0.0,K1,(AX)", "(AX),K1,(AX)", false},
				{"changed-mask", "", "$0.0,K1,X0", "X0,K2,X0", false},
				{"changed-merge", "", "$0.0,X1,K1,X0", "X0,X2,K1,X0", false},
				{"missing-from", "", "$0.0,K1,X0", "K1,X0", false},
				{"missing-restarg", "", "$0.0,K1,X0", "X0,X0", false},
				{"extra-restarg", "", "$0.0,K1,X0", "X0,K1,K2,X0", false},
				{"wrong-from", "", "$0.0,K1,X0", "X1,K1,X0", false},
				{"unknown-suffix", ".UNKNOWN", "$0.0,K1,X0", "X0,K1,X0", false},
				{"misordered-suffix", ".Z.SAE", "$0.0,K1,X0", "X0,K1,X0", false},
			} {
				t.Run(test.name, func(t *testing.T) {
					source := x86DiagnosticFixture(t, opcode+test.suffix+" "+test.operands)
					output := x86DiagnosticListing(source, "XORPS"+test.suffix+" "+test.listing)
					for _, arch := range []string{"amd64", "386"} {
						if got := goAssemblerOracleX86SourceDiagnostic(source, arch, output); got != test.want {
							t.Fatalf("%s scalar source/listing join=%t, want %t", arch, got, test.want)
						}
					}
					if goasmoracle.SourceDiagnosticLine(source, output, 2) ||
						goAssemblerOracleX86SourceDiagnostic(source, "arm64", output) {
						t.Fatal("positive-zero rewrite escaped its explicit x86 adapter")
					}
				})
			}
		})
	}
}

func TestGoAssemblerOracleRewrittenListingPreservesSourceBoundary(t *testing.T) {
	source := x86DiagnosticFixture(t, "PADDD M0,X1")
	output := x86DiagnosticListing(source, "PADDL M0,X1")
	for _, control := range []string{
		strings.Replace(output, "("+source+":2)", "(foreign"+source+":2)", 1),
		strings.Replace(output, ":2)", ":3)", 1),
		strings.Replace(output, "00000", "0", 1),
		strings.Replace(output, "00000", "000000", 1),
		strings.Replace(output, "asm: bad: invalid instruction: ", "foreign ", 1),
		"asm: assembly failed\n",
	} {
		if goAssemblerOracleX86SourceDiagnostic(source, "amd64", control) {
			t.Fatalf("rewritten listing bypassed source/PC/backend boundary: %q", control)
		}
	}
	called := false
	if goasmoracle.SourceDiagnosticLineWithListing(source, output, 3, func(_, _ []string) bool { called = true; return true }) || called {
		t.Fatal("matcher ran before the exact focus check")
	}
	for _, statement := range []string{"", "// PADDD M0,X1", "label:", "label: PADDD M0,X1", "PADDD M0,X1 /*"} {
		badSource := x86DiagnosticFixture(t, statement)
		called = false
		if goasmoracle.SourceDiagnosticLineWithListing(badSource, x86DiagnosticListing(badSource, "PADDL M0,X1"), 2,
			func(_, _ []string) bool { called = true; return true }) || called {
			t.Fatalf("matcher received an unbound original statement: %q", statement)
		}
	}
}
