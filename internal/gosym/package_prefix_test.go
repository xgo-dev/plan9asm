package gosym

import (
	"fmt"
	"testing"
)

func TestPackagePrefixByteGrammar(t *testing.T) {
	for _, test := range []struct{ raw, native string }{
		{"", ""},
		{"example.invalid/plain", "example.invalid/plain"},
		{"gopkg.in/example.v3", "gopkg.in/example%2ev3"},
		{"example.invalid/dotted.path/plain", "example.invalid/dotted.path/plain"},
		{"a/b.c.d", "a/b%2ec%2ed"},
		{"a/%2e", "a/%252e"},
		{"a/\"quoted\"", "a/%22quoted%22"},
		{"a/空间", "a/%e7%a9%ba%e9%97%b4"},
		{"a/\x00\x1f \x7f", "a/%00%1f%20%7f"},
	} {
		t.Run(fmt.Sprintf("%q", test.raw), func(t *testing.T) {
			if actual := PackagePrefix(test.raw); actual != test.native {
				t.Fatalf("native byte spelling = %q, want %q", actual, test.native)
			}
		})
	}
	for value := 0; value <= 255; value++ {
		for _, final := range []bool{false, true} {
			t.Run(fmt.Sprintf("byte-%02x/final=%t", value, final), func(t *testing.T) {
				encoded := string([]byte{byte(value)})
				// Explicit ASCII classes from objabi's grammar, not URL rules.
				if value <= 32 || value >= 127 || value == 34 || value == 37 || final && value == 46 {
					encoded = fmt.Sprintf("%%%02x", value)
				}
				raw, expected := "domain/"+string([]byte{byte(value)}), "domain/"+encoded
				if !final {
					raw, expected = string([]byte{byte(value)})+"/pkg", encoded+"/pkg"
				}
				if actual := PackagePrefix(raw); actual != expected {
					t.Fatalf("native byte spelling = %q, want %q", actual, expected)
				}
			})
		}
	}
}
