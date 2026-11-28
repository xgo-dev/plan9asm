package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARMLdrexStrex(t *testing.T) {
	file, err := Parse(ArchARM, `TEXT ·cas(SB),NOSPLIT,$0-0
	LDREX (R1), R0
	STREX R3, (R1), R0
	RET
`)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "armv7-unknown-linux-gnueabihf",
		Goarch:       "arm",
		ResolveSym:   func(sym string) string { return "example." + strings.TrimPrefix(sym, "·") },
		Sigs: map[string]FuncSig{
			"example.cas": {Name: "example.cas", Ret: Void},
		},
	})
	if err != nil {
		t.Fatalf("Translate() error = %v", err)
	}
	for _, want := range []string{".inst 0xe1910f9f", ".inst 0xe1810f93"} {
		if !strings.Contains(ll, want) {
			t.Fatalf("missing %q in output:\n%s", want, ll)
		}
	}
}
