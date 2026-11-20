//go:build !go1.27

package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

func TestGoAMD64FixedLocalImplicitMultiplyPrivateLeafNeedsAuditedProducer(t *testing.T) {
	assembly, declarations, _, _ := fixedLocalImplicitMultiplyProgram("x86_64-unknown-linux-gnu", true)
	requireX86GoAssemblerResult(t, "amd64", assembly, true)
	pkg, request, _, _ := fixedLocalTransportFixture(t, assembly, declarations, "linux/amd64", "x86_64-unknown-linux-gnu")
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	source, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
	if source != nil {
		defer source.Close()
	}
	if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "mixed DATA needs its independent actual Go object producer") {
		t.Fatal("private CALL borrowed an unaudited original object association", err)
	}
}
