package gotoolprofile

import "testing"

func TestCPPIncludeLiteralPresenceDoesNotDecideInputStackEOF(t *testing.T) {
	// Literal authentication is not directive syntax acceptance. An included
	// tokenizer may resume its parent's newline; the active Go/CPP input stack
	// must still reject the same directive at translation-unit EOF.
	for _, source := range []string{
		"#include \"../../src/value.h\"",
		"#include \"../../src/value.h\" // final included comment",
	} {
		if !cppLiteralInclude([]byte(source), "../../src/value.h") {
			t.Fatalf("original literal at included EOF was discarded: %q", source)
		}
	}
	for _, source := range []string{
		"#include \"../../src/value.h\" junk",
		"#include \"../../src/other.h\"",
		"// #include \"../../src/value.h\"",
		"#include \"../../src/value.h",
	} {
		if cppLiteralInclude([]byte(source), "../../src/value.h") {
			t.Fatalf("missing or invalid literal was authenticated: %q", source)
		}
	}
}
