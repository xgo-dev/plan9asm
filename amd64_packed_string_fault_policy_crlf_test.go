package plan9asm

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestX86PackedStringFaultNativePolicyKeepsCRLFAndMutations(t *testing.T) {
	source, err := os.ReadFile("amd64_packed_string_fault_linux_amd64_test.go")
	if err != nil {
		t.Fatal(err)
	}
	lf := string(normalizeNativeOwnerPolicySource(source))
	for _, ending := range []struct{ name, newline string }{{"LF", "\n"}, {"CRLF", "\r\n"}} {
		t.Run(ending.name, func(t *testing.T) {
			encode := func(text string) []byte {
				return []byte(strings.ReplaceAll(text, "\n", ending.newline))
			}
			original := encode(lf)
			before := append([]byte(nil), original...)
			t.Run("original", func(t *testing.T) {
				if err := x86PackedStringFaultNativePolicy(original); err != nil {
					t.Fatal("Go-equivalent line endings changed native fault ownership", err)
				}
				if !bytes.Equal(original, before) {
					t.Fatal("policy parsing rewrote original native source")
				}
			})
			mutations := x86PackedStringFaultNativeMutations(lf)
			if len(mutations) != 9 {
				t.Fatal("complete native policy mutation denominator changed")
			}
			for name, mutation := range mutations {
				t.Run(name, func(t *testing.T) {
					changed := encode(mutation)
					if mutation == lf || bytes.Equal(changed, original) || x86PackedStringFaultNativePolicy(changed) == nil {
						t.Fatal("line-ending adaptation hid a native policy mutation")
					}
				})
			}
		})
	}
}
