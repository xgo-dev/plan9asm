package plan9asm

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// Go accepts CRLF and LF identically. This copy is for source-policy parsing
// and mutation controls only, never compiler input or source authentication.
func normalizeNativeOwnerPolicySource(source []byte) []byte {
	return bytes.ReplaceAll(source, []byte("\r\n"), []byte("\n"))
}

func TestNativeOwnerPolicyNormalizationIsLimitedToCRLF(t *testing.T) {
	source := []byte("a\r\nb\rc\n")
	before := append([]byte(nil), source...)
	if got := string(normalizeNativeOwnerPolicySource(source)); got != "a\nb\rc\n" {
		t.Fatal("policy normalization changed more than CRLF", got)
	}
	if !bytes.Equal(source, before) {
		t.Fatal("source policy adaptation mutated original bytes")
	}
}

func TestNativeOwnerPoliciesKeepCRLFSourceAndMutations(t *testing.T) {
	owners := []struct {
		name   string
		path   string
		policy func([]byte) error
	}{
		{"bit-scan", "amd64_scalar_bitscan_execution_linux_amd64_test.go", x86BitScanNativeOwnerPolicy},
		{"bool", x86ABI0BoolNativeOwnerPath, x86ABI0BoolNativeOwnerPolicy},
	}
	for _, owner := range owners {
		t.Run(owner.name, func(t *testing.T) {
			source, err := os.ReadFile(owner.path)
			if err != nil {
				t.Fatal(err)
			}
			lf := strings.ReplaceAll(string(source), "\r\n", "\n")
			for _, ending := range []struct{ name, newline string }{{"LF", "\n"}, {"CRLF", "\r\n"}} {
				t.Run(ending.name, func(t *testing.T) {
					encode := func(text string) []byte {
						return []byte(strings.ReplaceAll(text, "\n", ending.newline))
					}
					if err := owner.policy(encode(lf)); err != nil {
						t.Fatal("Go-equivalent source line endings changed native ownership", err)
					}
					for _, mutation := range []string{
						strings.Replace(lf, "linux && amd64", "darwin && amd64", 1),
						strings.Replace(lf, "x87IA32RequireNativeHost(t)", "t.Skip(\"missing tools\")", 1),
						strings.Replace(lf, "x87IA32RequireNativeHost(t)", "return", 1),
					} {
						if err := owner.policy(encode(mutation)); err == nil {
							t.Fatal("line-ending adaptation admitted changed host/skip/early-return policy")
						}
					}
				})
			}
		})
	}
}
