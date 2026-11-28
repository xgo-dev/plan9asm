package preprocess

import (
	"strings"
	"testing"
)

func TestPreprocessExpandsFunctionLikeMacrosWithSpaceBeforeParen(t *testing.T) {
	src := `
#define ST(dst) MOVQ AX, dst
#define ROUNDS(a,b,c,d) ADDQ a, b; ADDQ c, d
TEXT foo(SB),NOSPLIT,$0-0
	ST (x+0(FP))
	ROUNDS (AX, BX, CX, DX)
	RET
`
	pp, err := Preprocess(src)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(pp, "ST (") {
		t.Fatalf("macro call with space was not expanded: %q", pp)
	}
	if strings.Contains(pp, "ROUNDS (") {
		t.Fatalf("inline macro call with space was not expanded: %q", pp)
	}
	if !strings.Contains(pp, "MOVQ AX, x+0(FP)") {
		t.Fatalf("expected ST expansion, got: %q", pp)
	}
	if !strings.Contains(pp, "ADDQ AX, BX") || !strings.Contains(pp, "ADDQ CX, DX") {
		t.Fatalf("expected ROUNDS expansion, got: %q", pp)
	}
}
