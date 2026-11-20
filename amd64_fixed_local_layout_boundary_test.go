package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestGoAMD64FixedLocalOrdinaryRetainedBoundary(t *testing.T) {
	var body strings.Builder
	for index := 0; index < 15; index++ {
		fmt.Fprintf(&body, "JMP next%d\nnext%d:\n", index, index)
	}
	fn, sig := fixedLocalReplayFixture(t, body.String())
	fn.FrameSize = 64 << 10
	if _, err := proveX86FixedLocal(fn, sig); err != nil {
		t.Fatal("sixteen ordinary states must retain the original one-MiB allowance", err)
	}
}
