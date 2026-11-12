package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

func TestARM64ABI0TailResultMissingDeclarationIsContext(t *testing.T) {
	declaration, source := arm64ABI0TailResultFixture(false, "B")
	for _, test := range []struct {
		name, source, symbol string
	}{
		{
			name:   "foreign-entry",
			source: source + "TEXT Alternate(SB),516,$0-16\nB resultbody<>(SB)\n",
			symbol: "Alternate",
		},
		{
			name:   "missing-local-entry",
			source: strings.Replace(source, "·Slots", "·Missing", 1),
			symbol: "Missing",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			// These complete sources really assemble; no unsafe body is run.
			requireARM64GoABIInternalObject(t, test.source)
			for _, api := range []string{"text", "module", "GoModule"} {
				t.Run(api, func(t *testing.T) {
					ir, err := arm64ABI0TailResultTranslate(t, test.source, declaration,
						"aarch64-unknown-linux-gnu", api, nil)
					if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
						t.Fatalf("unbound actual tail declaration lost Context or produced IR: ir=%q err=%v", ir, err)
					}
					if api == "GoModule" && (!strings.Contains(err.Error(), test.symbol) ||
						!strings.Contains(err.Error(), "missing Go declaration for asm symbol")) {
						t.Fatalf("pre-binding failure lost its original missing-declaration identity/reason: %v", err)
					}
				})
			}
		})
	}

	t.Run("ordinary-noncandidate", func(t *testing.T) {
		ordinary := "TEXT ·Other(SB),516,$0-0\nRET\n"
		requireARM64GoABIInternalObject(t, ordinary)
		ir, err := arm64ABI0TailResultTranslate(t, ordinary, declaration,
			"aarch64-unknown-linux-gnu", "GoModule", nil)
		if err == nil || errors.Is(err, ErrProbeNeedsContext) || ir != "" ||
			!strings.Contains(err.Error(), "missing Go declaration for asm symbol \"·Other\"") {
			t.Fatalf("ordinary declaration failure changed routing: ir=%q err=%v", ir, err)
		}
	})
}
