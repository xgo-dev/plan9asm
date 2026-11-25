package preprocess

import (
	"strings"
	"testing"
)

func TestPreprocessCoverageEdges(t *testing.T) {
	src := `
#define VALUE 7
#define PAIR(a, b) MOVQ a, b \
ADDQ a, b
#define KEEP AX
/* block
comment */
#ifdef VALUE
PAIR (KEEP, BX)
#else
MOVQ $0, DX
#endif
#if !defined(MISSING)
MOVQ $(VALUE + 1), CX
#elif defined(VALUE)
MOVQ $9, SI
#endif
#ifndef MISSING
MOVQ VALUE, DI
#endif
TEXT foo(SB),NOSPLIT,$0-0 // trailing comment
	PAIR(AX, DX); MOVQ KEEP, R8
	RET
`
	pp, err := Preprocess(src)
	if err != nil {
		t.Fatalf("preprocess() error = %v", err)
	}
	for _, want := range []string{
		"MOVQ AX, BX",
		"ADDQ AX, BX",
		"MOVQ $(7 + 1), CX",
		"MOVQ 7, DI",
		"MOVQ AX, DX",
		"MOVQ AX, R8",
		"TEXT foo(SB),NOSPLIT,$0-0",
	} {
		if !strings.Contains(pp, want) {
			t.Fatalf("missing %q in preprocessed output:\n%s", want, pp)
		}
	}
	for _, bad := range []string{"MOVQ $0, DX", "/*", "//"} {
		if strings.Contains(pp, bad) {
			t.Fatalf("unexpected %q in preprocessed output:\n%s", bad, pp)
		}
	}

	if _, err := Preprocess("#else\n"); err == nil {
		t.Fatalf("stray #else unexpectedly succeeded")
	}
	if _, err := Preprocess("#if VALUE\nMOVQ AX, BX\n"); err == nil {
		t.Fatalf("unterminated #if unexpectedly succeeded")
	}
	if _, err := Preprocess("#if VALUE\n#else\n#else\n#endif\n"); err == nil {
		t.Fatalf("duplicate #else unexpectedly succeeded")
	}

	if name, params, body, err := ParseMacroDefine("F(a, b) MOVQ a, b"); err != nil || name != "F" || len(params) != 2 || body != "MOVQ a, b" {
		t.Fatalf("ParseMacroDefine() = (%q, %v, %q, %v)", name, params, body, err)
	}
	if _, _, _, err := ParseMacroDefine("1BAD x"); err == nil {
		t.Fatalf("ParseMacroDefine(invalid) unexpectedly succeeded")
	}
	if args, ok := ParseMacroCall("PAIR(AX, BX)", "PAIR", 2); !ok || len(args) != 2 || args[0] != "AX" || args[1] != "BX" {
		t.Fatalf("ParseMacroCall() = (%v, %v)", args, ok)
	}
	if _, ok := ParseMacroCall("PAIR(AX)", "PAIR", 2); ok {
		t.Fatalf("ParseMacroCall with wrong arity unexpectedly succeeded")
	}
	if got, changed := ExpandInlineMacroCalls("PAIR(AX, BX); RET", "PAIR", Macro{
		body:   "MOVQ a, b",
		params: []string{"a", "b"},
	}); !changed || !strings.Contains(got, "MOVQ AX, BX") {
		t.Fatalf("ExpandInlineMacroCalls() = (%q, %v)", got, changed)
	}
	if got, changed := ExpandIdentMacros("MOVQ VALUE, AX", map[string]Macro{"VALUE": {body: "9"}}); !changed || got != "MOVQ 9, AX" {
		t.Fatalf("ExpandIdentMacros() = (%q, %v)", got, changed)
	}
	if got := ReplaceMacroParams("ADDQ a, b", []string{"a", "b"}, []string{"CX", "DX"}); got != "ADDQ CX, DX" {
		t.Fatalf("ReplaceMacroParams() = %q", got)
	}
	if out := ExpandPPLine("WRAP(AX, BX)", map[string]Macro{
		"WRAP": {body: "PAIR(a, b)", params: []string{"a", "b"}},
		"PAIR": {body: "MOVQ a, b", params: []string{"a", "b"}},
	}, []string{"WRAP", "PAIR"}, 0); len(out) != 1 || out[0] != "MOVQ AX, BX" {
		t.Fatalf("ExpandPPLine() = %#v", out)
	}
}
