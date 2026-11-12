//go:build !go1.27

package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

func TestGoAMD64FixedLocalPointerChoicesNeedAuditedDATAProducer(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	rows := append(fixedLocalPointerChoiceAllPositiveCases(), fixedLocalNativeAddressCases()...)
	if len(rows) != 42 {
		t.Fatal("complete mixed-DATA source inventory changed", len(rows))
	}
	assembly, declarations := fixedLocalPointerChoiceProgram(t, fixedLocalChoiceData, rows)
	// Original Go accepts the complete source. Only the independently audited
	// object producer is unavailable; this is not an instruction rejection.
	requireX86GoAssemblerResult(t, "amd64", assembly, true)
	for _, target := range []struct{ name, triple string }{
		{"linux/amd64", "x86_64-unknown-linux-gnu"},
		{"darwin/amd64", "x86_64-apple-darwin"},
		{"windows/amd64", "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			pkg, request, _, _ := fixedLocalTransportFixture(t, assembly, declarations, target.name, target.triple)
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			source, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
			if source != nil {
				if closeErr := source.Close(); closeErr != nil {
					t.Error(closeErr)
				}
			}
			if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "mixed DATA needs its independent actual Go object producer") {
				t.Fatal("unaudited mixed-DATA producer did not retain its exact boundary", err)
			}
		})
	}
}
