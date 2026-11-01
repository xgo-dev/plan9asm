package plan9asm

import (
	"os"
	"testing"
)

// This prefix is selected by the exhaustive required Linux cross-runtime job.
// Both originals execute directly: IA32 compilation is not execution evidence.
func TestCrossLinuxRuntimeMatrixX86StackFlagsIDNativeGo(t *testing.T) {
	x87IA32RequireNativeHost(t)
	t.Run("OriginalAMD64", TestX86StackFlagsIDNativeGo)
	t.Run("Original386", func(t *testing.T) {
		original := x86StackIDOriginalExecutable(t, "linux", "386")
		sealed, err := x87IA32StaticExecutable(original)
		if err != nil {
			t.Fatal(err)
		}
		output := x87IA32RunDirect(t, sealed, nil, os.Environ())
		if string(output) != "original Go stack ID observations 4\n" {
			t.Fatalf("strict native original Go IA32 four-word oracle: %q", output)
		}
	})
	x87IA32RequireNativeHost(t)
}
