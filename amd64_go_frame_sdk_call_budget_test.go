package plan9asm

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestGoAMD64FrameForeignABI0SDKArchiveBudgetBeforeRead(t *testing.T) {
	// These are deliberately invalid object bytes, not SDK source evidence.
	// Observe whether the second file was read before format validation: the
	// aggregate bound must stop an oversized graph before retaining that input.
	for _, excess := range []bool{false, true} {
		name := "exact-budget"
		if excess {
			name = "over-budget"
		}
		t.Run(name, func(t *testing.T) {
			directory, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			builtin := filepath.Join(directory, "src/cmd/internal/goobj/builtinlist.go")
			if err := os.MkdirAll(filepath.Dir(builtin), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(builtin, []byte("fixture"), 0600); err != nil {
				t.Fatal(err)
			}
			first, second := filepath.Join(directory, "first.a"), filepath.Join(directory, "second.a")
			file, err := os.Create(first)
			if err != nil {
				t.Fatal(err)
			}
			truncateErr := file.Truncate((64 << 20) - 1)
			closeErr := file.Close()
			if truncateErr != nil || closeErr != nil {
				t.Fatal(truncateErr, closeErr)
			}
			last := []byte{0}
			if excess {
				last = append(last, 0)
			}
			if err := os.WriteFile(second, last, 0600); err != nil {
				t.Fatal(err)
			}
			selected := goAMD64FrameSelection{ImportPath: "fixture/first", Standard: true, Export: first, Imports: []string{"fixture/second"}}
			source := &GoAMD64FrameSource{env: map[string]string{"GOROOT": directory}, inputs: make(map[string][32]byte),
				request: GoAMD64FrameCaptureRequest{Target: "linux/amd64"},
				imports: map[string]goAMD64FrameSelection{selected.ImportPath: selected,
					"fixture/second": {ImportPath: "fixture/second", Standard: true, Export: second}}}
			if _, err := source.ordinarySDKCallTexts(selected, map[string]bool{"Value": true}); err == nil {
				t.Fatal("invalid archive fixture acquired an SDK call observation")
			} else if excess && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("oversized input was not stopped by the source read bound", err)
			}
			if _, captured := source.inputs[first]; !captured {
				t.Fatal("the first fitting file was not observed")
			}
			if _, captured := source.inputs[second]; captured == excess {
				t.Fatal("the aggregate budget did not bound the next file before observation", captured, excess)
			}
		})
	}
}
