package plan9asm

import "testing"

func TestARM64ABI0ByteRegionOriginalHostObservation(t *testing.T) {
	arm64ABI0ByteRegionOriginalRun(t, "darwin", nil)
}
