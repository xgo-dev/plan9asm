package plan9asm

import (
	"os"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

// A directory junction may change the physical driver spelling. The final
// driver itself must still be a regular file, never an indirect file entry.
func goAMD64FrameSourceDriverPath(name string) (string, error) {
	before, err := sourcepath.Lstat(name)
	if err != nil || !before.Mode().IsRegular() {
		return "", goAMD64FrameContext("actual driver is not a regular file")
	}
	physical, err := sourcepath.Resolve(name)
	if err != nil {
		return "", goAMD64FrameContext("actual driver physical identity is unavailable: %v", err)
	}
	after, err := sourcepath.Lstat(physical)
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return "", goAMD64FrameContext("actual driver identity changed while resolving")
	}
	return physical, nil
}
